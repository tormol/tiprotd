use std::error::Error;
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, Shutdown};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::SocketAddr as UnixSocketAddr;

use chrono::Local;
use mio::{Evented, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use mio_uds::{UnixListener, UnixStream, UnixDatagram};

use crate::client_limiter::ClientStats;
use crate::ServiceSocket;
use crate::Server;

#[cfg(unix)]
pub trait Descriptor: AsRawFd + Evented {}
#[cfg(unix)]
impl<T: AsRawFd+Evented> Descriptor for T {}
#[cfg(not(unix))]
pub use Evented as Descriptor;
// pub enum Socket<'a> {
//     TcpStream(&'a TcpStream),
//     TcpListener(&'a TcpListener),
//     UdpSocket(&'a UdpSocket),
//     #[cfg(unix)]// all other
//     Any(&'a dyn Descriptor),
// }

/// Converts ::ffff:0.0.0.0/96 and ::0.0.0.0/96 ( except ::1 and ::) to IPv4 socket addresses.
///
/// When listening on :: IPv4 clienst are represented as IPv4-mapped addresses
/// (::ffff:0.0.0.0). These are less readable when printed, and might not be
/// detected as eg. multicast or loopback.
///
/// Using std's Ipv6Addr.to_ipv4() directly would convert some actual IPv6
/// addresses such as ::1 and :: because it also converts ::0.0.0.0/96
/// (IPv4-compatible addresses).
pub fn native_addr(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4() {
            if v4 > Ipv4Addr::new(0, 0, 0, 255) && v6.scope_id() == 0 && v6.flowinfo() == 0 {
                return SocketAddr::from((v4, v6.port()));
            }
        }
    }
    addr
}

/// get the current time and return something that can be used in a format!()
pub fn now() -> impl Display {
    Local::now().format("%Y-%m-%d %H:%M:%S")
}

/// Should the entry this event was for be dropped after return?
/// (because I kept forgetting which boolean meant what)
#[derive(Clone,Copy, PartialEq,Eq)]
pub enum EntryStatus { Drained, Unfinished, Remove }
pub use EntryStatus::*;

fn shutdown_direction(direction: Shutdown) -> &'static str {
    match direction {
        Shutdown::Both => "",
        Shutdown::Write => "the sending part of ",
        Shutdown::Read => "the receiving part of "
    }
}

/// How many bytes an open connection should count as.
/// This should include buffers and structs used by the OS as well as structs
/// and fixed tiny buffers used by this program.
/// TODO calculate based on fd limit to prevent EMFILE DoS attack
const TCP_CONNECTION_COST: usize = 2000; // guess

// want to try to handle short-lived connections without registering them,
// but after passing the socket to the callback we don't have access to it
// calling ready() on the returned value before it has a token also seems
// like a bad idea.
// Could unsafely copy the TcpStream into a ManuallyDrop, but that will
// create bugs if callback drops it.
// try two callbacks
pub fn tcp_accept_loop<
        P,
        T: FnMut(&mut TcpStreamWrapper) -> Option<P>,
        W: FnMut(TcpStreamWrapper, P, Token) -> ServiceSocket
>(
        listener: &TcpListener,  server: &mut Server,
        service_name: &'static &'static str,  poll_streams_for: Ready,
        mut trier: T,  mut wrapper: W
) -> EntryStatus {
    loop {
        match listener.accept() {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Drained,
            Err(ref e) if e.kind() == ErrorKind::ConnectionAborted => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => continue,
            Err(e) => {
                eprintln!("Error accepting {} TCP connection: {}", service_name, e);
                // non-remote error, close the socket
                // if EMFILE or ENFILE this might expose a DoS attack
                // but clientlimiter should prevent it
                return Remove;
            }
            Ok((stream, addr)) => {
                let res = match server.limits.request_resources_ref(addr, TCP_CONNECTION_COST) {
                    Some(res) => res,
                    None => {
                        // Once the connection is ready to accept(), the
                        // work to establish the connection has already
                        // been performed by the kernel.
                        // The best we can do is to immediately close it,
                        // to not let the client consume more resources.
                        continue;
                    }
                };
                let mut stream = TcpStreamWrapper {
                    stream,
                    limit_counters: res,
                    native_addr: native_addr(addr),
                    service_name,
                };
                eprintln!("{} {} tcp://{} connection established",
                        now(), service_name, stream.native_addr
                );
                if let Some(state) = trier(&mut stream) {
                    let entry = server.sockets.vacant_entry();
                    let result = server.poll.register(&*stream,
                        Token(entry.key()),
                        poll_streams_for,
                        PollOpt::edge(),
                    );
                    if let Err(e) = result {
                        eprintln!("Cannot register TCP connection: {}", e);
                    } else {
                        let token = Token(entry.key()); // make borrowck happy
                        entry.insert(wrapper(stream, state, token));
                        // TODO trigger Ready::readable() | Ready::writable()
                    }
                }
            }
        }
    }
}


pub struct TcpStreamWrapper {
    stream: TcpStream,
    pub limit_counters: Rc<ClientStats>, // maybe switch to weak
    pub native_addr: SocketAddr,
    pub service_name: &'static &'static str, // nested ref to avoid fat pointer
}
impl Deref for TcpStreamWrapper {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        &self.stream
    }
}
impl DerefMut for TcpStreamWrapper {
    fn deref_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}
impl Drop for TcpStreamWrapper {
    fn drop(&mut self) {
        self.limit_counters.release_resources(TCP_CONNECTION_COST);
        // socket deregisters itself from mio
        eprintln!("{} {} tcp://{} connection closed",
            now(), self.service_name, self.native_addr
        );
    }
}
impl TcpStreamWrapper {
    pub fn shutdown(&self,  direction: Shutdown) -> EntryStatus {
        if let Err(e) = self.stream.shutdown(direction) {
            eprintln!("tcp://{} error shutting down {}{} socket: {}",
                self.native_addr, shutdown_direction(direction), self.service_name, e
            );
            Remove
        } else {
            Drained
        }
    }
    pub fn end(&self,  cause: Result<usize,io::Error>,  operation: &str) {
        if let Err(e) = cause {
            eprintln!("tcp://{} error {}: {}, closing", self.native_addr, operation, e.description());
        } else {
            self.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(unix)]
pub struct DeleteOnDrop(Box<str>);
#[cfg(unix)]
impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(self.0.as_ref()) {
            eprintln!("Couldn't delete {}: {}", self.0, err);
        }
    }
}

#[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
pub struct PosixMqWrapper(pub posixmq::PosixMq, pub &'static str);
#[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
impl Deref for PosixMqWrapper {
    type Target = posixmq::PosixMq;
    fn deref(&self) -> &posixmq::PosixMq {
        &self.0
    }
}
#[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
impl Drop for PosixMqWrapper {
    fn drop(&mut self) {
        if let Err(e) = posixmq::unlink(self.1) {
            eprintln!("Error removing posix message queue /{}: {}", self.1, e);
        }
    }
}


#[cfg(unix)]
pub fn unix_stream_accept_loop<
        P,
        T: FnMut(&mut UnixStreamWrapper) -> Option<P>,
        W: FnMut(UnixStreamWrapper, P, Token) -> ServiceSocket
>(
        listener: &UnixListener,  server: &mut Server,
        service_name: &'static &'static str,  poll_stream_for: Ready,
        mut trier: T,  mut wrapper: W
) -> EntryStatus {
    loop {
        match listener.accept() {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Drained,
            Ok(None) => return Drained,
            Err(ref e) if e.kind() == ErrorKind::ConnectionAborted => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => continue,
            Err(e) => {
                eprintln!("Error accepting {} unix stream connection: {}", service_name, e);
                // non-remote error, close the socket
                // this allows EMFILE or ENFILE DoS attack, but unix sockets aren't important
                return Remove;
            }
            Ok(Some((stream, addr))) => {
                let mut stream = UnixStreamWrapper{stream, addr, service_name};
                eprintln!("{} {} uds://{:?} connection established",
                    now(), service_name, stream.addr
                );
                if let Some(state) = trier(&mut stream) {
                    let entry = server.sockets.vacant_entry();
                    let result = server.poll.register(&*stream,
                        Token(entry.key()),
                        poll_stream_for,
                        PollOpt::edge(),
                    );
                    if let Err(e) = result {
                        eprintln!("Cannot register unix stream connection: {}", e);
                    } else {
                        let token = Token(entry.key()); // make borrowck happy
                        entry.insert(wrapper(stream, state, token));
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
pub struct UnixStreamWrapper {
    stream: UnixStream,
    pub addr: UnixSocketAddr,
    pub service_name: &'static &'static str,
}
#[cfg(unix)]
impl Drop for UnixStreamWrapper {
    fn drop(&mut self) {
        eprintln!("{} {} uds://{:?} connection closed",
            now(), self.service_name, self.addr
        );
        // socket deregisters itself from mio
    }
}
#[cfg(unix)]
impl UnixStreamWrapper {
    pub fn shutdown(&self,  direction: Shutdown) -> bool {
        if let Err(e) = self.stream.shutdown(direction) {
            eprintln!("uds://{:?} error shutting down {}{} socket: {}",
                self.addr, shutdown_direction(direction), self.service_name, e
            );
            true
        } else {
            false
        }
    }
    pub fn end(&self,  cause: Result<usize,io::Error>,  operation: &str) {
        if let Err(e) = cause {
            eprintln!("uds://{:?} error {}: {}, closing", self.addr, operation, e.description());
        } else {
            self.shutdown(Shutdown::Both);
        }
    }
}
#[cfg(unix)]
impl Deref for UnixStreamWrapper {
    type Target = UnixStream;
    fn deref(&self) -> &UnixStream {
        &self.stream
    }
}
#[cfg(unix)]
impl DerefMut for UnixStreamWrapper {
    fn deref_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }
}


pub fn udp_receive<F: FnMut(usize, SocketAddr, &mut Server)>
(socket: &UdpSocket,  server: &mut Server,  service_name: &str,  mut f: F)
-> EntryStatus {
    loop {
        match socket.recv_from(&mut server.buffer) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Drained,
            Ok((len, from)) => f(len, from, server),
            // ignore errors caused by previous sends
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => {},
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => {},
            Err(ref e) if e.kind() == ErrorKind::ConnectionAborted => {},
            Err(e) => {
                eprintln!("{} {} UDP receive error: {}", now(), service_name, e);
                return Remove;
            }
        }
    }
}


/// returns false if a WouldBlock error was returned, and logs errors
pub fn udp_send(from: &UdpSocket,  msg: &[u8],  to: &SocketAddr,  service_name: &str) -> bool {
    match from.send_to(msg, to) {
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return false,
        Err(e) => {
            eprintln!("error sending udp packet ({}, udp://{}): {}",
                service_name, native_addr(*to), e
            );
        }
        Ok(len) if len != msg.len() => {
            eprintln!("udp://{} could only send {}/{} bytes of {} response",
                native_addr(*to), len, msg.len(), service_name
            );
        },
        Ok(_) => {}
    }
    true
}


/// returns false if a WouldBlock error was returned, and logs errors
#[cfg(unix)]
pub fn unix_datagram_send(from: &UnixDatagram,  msg: &[u8],  to: &UnixSocketAddr,
        service_name: &str
) -> bool {
    if let Some(path) = to.as_pathname() {
        if !path.starts_with("/") {
            eprintln!("Won't send to relative socket address {:?}", path);
            return true;
        }
        match from.send_to(msg, path) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return false,
            Err(e) => {
                eprintln!("error sending unix datagram packet ({}, uddg://{:?}): {}",
                    service_name, to, e
                );
            }
            Ok(len) if len != msg.len() => {
                eprintln!("Could only send {}/{} bytes of {} unix datagram response to {:?}",
                    len, msg.len(), service_name, to
                );
            },
            Ok(_) => {}
        }
        true
    } else {
        eprintln!("std doesn't allow sending unix datagram to {:?}, sorry", to);
        true
    }
}
