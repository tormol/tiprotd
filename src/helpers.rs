use std::any::Any;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, Shutdown};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::SocketAddr as UnixSocketAddr;
#[cfg(unix)]
use std::os::raw::{c_int, c_char};

use chrono::Local;
use mio::{Evented, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use mio_uds::{UnixListener, UnixStream, UnixDatagram};
#[cfg(unix)]
use nix::sys::socket::{getsockopt, setsockopt, sockopt::*};
#[cfg(unix)]
use nix::sys::socket::{InetAddr, SockAddr};
#[cfg(unix)]
use nix::libc;

use crate::client_limiter::ClientStats;
use crate::ServiceSocket;
use crate::Server;


#[derive(Clone,Copy, PartialEq,Eq,Hash, Debug)]
#[repr(u8)]
#[allow(unused)] // don't want to cfg out unsupported protocols
pub enum Protocol {
    Unknown=0,
    Tcp=1, Udp=2, Sctp=3, Udplite=4, Dccp=5,
    Uds=6, Uddg=7, Udsq=8,
    PosixMq=9, Pipe=10,
}
impl Protocol {
    pub fn url_identifier(self) -> &'static str {
        [
            "???",
            "tcp", "udp", "sctp", "udplite", "dccp",
            "uds", "uddg", "udsq",
            "posixmq", "pipe",
        ][self as u8 as usize]
    }
    pub fn prefix(self) -> &'static str {
        [
            "",
            "tcp://", "udp://", "sctp://", "udplite://", "dccp://",
            "unix stream socket ", "unix datagram socket ", "unix seqpacket socket ",
            "posix message queue ", "pipe ",
        ][self as u8 as usize]
    }
    pub fn description(self) -> &'static str {
        [
            "unknown",
            "TCP", "UDP", "SCTP", "UDPlite", "DCCP",
            "unix stream", "unix datagram", "unix seqpacket",
            "posix message queue", "pipe",
        ][self as u8 as usize]
    }
}
impl Display for Protocol {
    fn fmt(&self,  fmtr: &mut Formatter) -> fmt::Result {
        fmtr.write_str(self.url_identifier())
    }
}

#[cfg(unix)]
pub trait Descriptor: AsRawFd + Evented + Any+'static {
    fn as_any(&self) -> &(dyn Any+'static);
}
#[cfg(unix)]
impl<T: AsRawFd+Evented+Any+Sized> Descriptor for T {
    fn as_any(&self) -> &(dyn Any+'static) {
        self
    }
}
#[cfg(not(unix))]
pub trait Descriptor: Evented + Any {}
#[cfg(not(unix))]
impl<T: Evented+Any> Descriptor for T {}

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


/// Convert a nix result to a std::io result.
///
/// It maps nix::Error::Sys to std::io::Error::last_os_error() (because nix's
/// Errno is lossy) and panics on any nix invented error.
#[cfg(unix)]
fn nixe<T>(nix_result: Result<T, nix::Error>) -> Result<T, io::Error> {
    match nix_result {
        Ok(success) => Ok(success),
        Err(nix::Error::Sys(_)) => Err(io::Error::last_os_error()),
        Err(nix_invented) => panic!("nix caused error: {}", nix_invented)
    }
}

#[cfg(unix)]
fn create_incoming_socket(protocol: Protocol,
        typ: c_int,  variant: c_int,
        bind_addr: &libc::sockaddr,  addrlen: libc::socklen_t,
        set_buffers: Option<usize>,  log_buffers: bool,
        listen_backlog: Option<u16>,
) -> Result<RawFd, io::Error> {
    // FIXME these flags are not available on macOS
    let options = libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    let socket = unsafe { libc::socket(
            bind_addr.sa_family as c_int,
            typ | options,
            variant
    ) };
    if socket == -1 {
        return Err(io::Error::last_os_error());
    }
    if let Err(e) = nixe(setsockopt(socket, ReuseAddr, &true)) {
        eprintln!("Connot set SO_REUSEADDR for {} socket: {}", protocol.description(), e);
    }
    if log_buffers {
        if let Ok(default_size) = getsockopt(socket, RcvBuf) {
            println!("{} default receive buffer size is {}", protocol.description(), default_size);
        }
        if let Ok(default_size) = getsockopt(socket, SndBuf) {
            println!("{} default send buffer size is {}", protocol.description(), default_size);
        }
    }
    if let Some(set_to) = set_buffers {
        if let Err(e) = setsockopt(socket, RcvBuf, &set_to) {
            eprintln!("Cannot set {} socket receive buffer size to {}: {}",
                protocol.description(), set_to, e
            );
        } else if log_buffers {
            if let Ok(set_size) = getsockopt(socket, RcvBuf) {
                println!("Set {} socket receive buffer size to {}",
                    protocol.description(), set_size
                );
            }
        }
        if let Err(e) = setsockopt(socket, SndBuf, &set_to) {
            eprintln!("Cannot set {} socket send buffer size to {}: {}",
                protocol.description(), set_to, e
            );
        } else if log_buffers {
            if let Ok(set_size) = getsockopt(socket, SndBuf) {
                println!("Set {} socket send buffer size to {}",
                    protocol.description(), set_size
                );
            }
        }
    }
    if unsafe { libc::bind(socket, bind_addr, addrlen) } != 0 {
        let bind_err = io::Error::last_os_error();
        if unsafe { libc::close(socket) } != 0 {
            eprintln!("Cannot close failed {} socket: {}",
                protocol.description(), io::Error::last_os_error()
            );
        }
        return Err(bind_err);
    }
    if let Some(backlog) = listen_backlog {
        if unsafe { libc::listen(socket, backlog as c_int) } != 0 {
            let listen_err = io::Error::last_os_error();
            if unsafe { libc::close(socket) } != 0 {
                eprintln!("Cannot close failed {} socket: {}",
                    protocol.description(), io::Error::last_os_error()
                );
            }
            return Err(listen_err);
        }
    }
    Ok(socket)
}


/// Create a mio TcpListener for the specified port and register it.
///
/// Might in the future be changed to create multiple listeners,
/// such as one for IPv4 and one for IPv6.
///
/// OS are made to as small as possible on *nix.
pub fn listen_tcp(server: &mut Server,  service_name: &'static str,  port: u16,
        encapsulate: &mut dyn FnMut(TcpListener, Token)->ServiceSocket
) {
    #[cfg(not(unix))]
    let res = server.try_bind_ip("tcp", service_name, port, Ready::readable(),
        |addr| TcpListener::bind(&addr)
    );
    #[cfg(unix)]
    let res = server.try_bind_ip("tcp", service_name, port, Ready::readable(),
        |addr| {
            let nix_addr = SockAddr::Inet(InetAddr::from_std(&addr));
            let (sockaddr, socklen) = unsafe { nix_addr.as_ffi_pair() };
            let listener = create_incoming_socket(Protocol::Tcp,
                libc::SOCK_STREAM, 0, sockaddr, socklen,
                Some(0), false, Some(10)/*FIXME find what std uses*/
            )?;
            unsafe { Ok(TcpListener::from_raw_fd(listener)) }
        }
    );
    if let Some((listener, entry)) = res {
        let token = Token(entry.key()); // make borrowck happy
        entry.insert(encapsulate(listener, token));
    } else {
        std::process::exit(1);
    }

    #[cfg(all(unix, not(any(target_os="macos", target_os="dragonfly", target_os="openbsd"))))]
    listen_sctp(server, service_name, port, encapsulate);
    #[cfg(any(target_os="linux", target_os="freebsd"/*probably not*/))]
    listen_dccp(server, service_name, port, encapsulate);
}


fn shutdown_direction(direction: Shutdown) -> &'static str {
    match direction {
        Shutdown::Both => "",
        Shutdown::Write => "the sending part of ",
        Shutdown::Read => "the receiving part of "
    }
}

/// How many bytes an open connection should count as.
/// This should include structs used by the OS as well as structs
/// and fixed tiny buffers used by this program.
/// TODO calculate based on fd limit to prevent EMFILE DoS attack
const TCP_CONNECTION_COST: usize = 200; // guess
const ASSUMED_TCP_RECEIVE_BUFFER_SIZE: usize = 60_000;
const ASSUMED_TCP_SEND_BUFFER_SIZE: usize = 16_000;
/// The sum of receive and send buffer sizes reported for the first connection
static TCP_BUFFERS_SIZE: AtomicUsize = AtomicUsize::new(0);

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
                let mut buffers_size = TCP_BUFFERS_SIZE.load(Ordering::Relaxed);
                if buffers_size == 0 {
                    #[cfg(unix)] {
                        buffers_size += match getsockopt(stream.as_raw_fd(), RcvBuf) {
                            Ok(receive_size) => {
                                println!("tcp receive buffer size is {}", receive_size);
                                receive_size
                            }
                            Err(e) => {
                                eprintln!("Cannot get tcp receive buffer size: {}", e);
                                ASSUMED_TCP_RECEIVE_BUFFER_SIZE
                            }
                        };
                        buffers_size += match getsockopt(stream.as_raw_fd(), SndBuf) {
                            Ok(send_size) => {
                                println!("tcp send buffer size is {}", send_size);
                                send_size
                            }
                            Err(e) => {
                                eprintln!("Cannot get tcp send buffer size: {}", e);
                                ASSUMED_TCP_SEND_BUFFER_SIZE
                            }
                        };
                    }
                    #[cfg(not(unix))] {
                        buffers_size += ASSUMED_TCP_RECEIVE_BUFFER_SIZE;
                        buffers_size += ASSUMED_TCP_SEND_BUFFER_SIZE;
                    }
                    TCP_BUFFERS_SIZE.store(buffers_size, Ordering::SeqCst);
                }
                let tcp_connection_cost = TCP_CONNECTION_COST + buffers_size;
                let res = match server.limits.request_resources_ref(addr, tcp_connection_cost) {
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


#[cfg(all(unix, not(any(target_os="macos", target_os="dragonfly", target_os="openbsd"))))]
pub fn listen_sctp(server: &mut Server,  service_name: &'static str,  port: u16,
        encapsulate: &mut dyn FnMut(TcpListener, Token)->ServiceSocket
) {
    let res = server.try_bind_ip("sctp", service_name, port, Ready::readable(),
        |addr| {
            let nix_addr = SockAddr::Inet(InetAddr::from_std(&addr));
            let (sockaddr, socklen) = unsafe { nix_addr.as_ffi_pair() };
            let listener = create_incoming_socket(Protocol::Sctp,
                    libc::SOCK_STREAM, libc::IPPROTO_SCTP,
                    sockaddr, socklen,
                    Some(0), false, Some(10/*FIXME*/),
            )?;
            unsafe { Ok(TcpListener::from_raw_fd(listener)) }
        }
    );
    if let Some((listener, entry)) = res {
        let token = Token(entry.key()); // make borrowck happy
        entry.insert(encapsulate(listener, token));
    } else {
        std::process::exit(1);
    }
}

#[cfg(any(target_os="linux", target_os="freebsd"/*probably not*/))]
pub fn listen_dccp(server: &mut Server,  service_name: &'static str,  port: u16,
        encapsulate: &mut dyn FnMut(TcpListener, Token)->ServiceSocket
) {
    let res = server.try_bind_ip("dccp", service_name, port, Ready::readable(),
        |addr| {
            let nix_addr = SockAddr::Inet(InetAddr::from_std(&addr));
            let (sockaddr, socklen) = unsafe { nix_addr.as_ffi_pair() };
            let listener = create_incoming_socket(Protocol::Dccp,
                    libc::SOCK_DCCP, 0, sockaddr, socklen,
                    Some(0), false, Some(10/*FIXME*/),
            )?;
            unsafe { Ok(TcpListener::from_raw_fd(listener)) }
        }
    );
    if let Some((listener, entry)) = res {
        let token = Token(entry.key()); // make borrowck happy
        entry.insert(encapsulate(listener, token));
    } else {
        std::process::exit(1);
    }
}


/// Create a mio UdpSocket bound to the specified port and register it.
pub fn listen_udp(server: &mut Server,  service_name: &'static str,
        port: u16,  poll_for: Ready,
        encapsulate: &mut dyn FnMut(UdpSocket, Token)->ServiceSocket
) {
    let (socket, entry) = server.try_bind_ip("udp", service_name, port, poll_for,
        |addr| UdpSocket::bind(&addr)
    ).unwrap_or_else(|| std::process::exit(1) );
    let token = Token(entry.key()); // make borrowck happy
    entry.insert(encapsulate(socket, token));
    #[cfg(any(target_os="linux", target_os="freebsd"))]
    listen_udplite(server, service_name, port, poll_for, encapsulate);
}


/// Create a mio UdpSocket actually representing an UDP-lite socket
/// bound to the specified port and register it.
#[cfg(any(target_os="linux", target_os="freebsd"))]
pub fn listen_udplite(server: &mut Server,  service_name: &'static str,
        port: u16,  poll_for: Ready,
        encapsulate: &mut dyn FnMut(UdpSocket, Token)->ServiceSocket
) {
    let (socket, entry) = server.try_bind_ip("udplite", service_name, port, poll_for,
        |addr| {
            use std::os::raw::c_void;
            let nix_addr = SockAddr::Inet(InetAddr::from_std(&addr));
            let (sockaddr, socklen) = unsafe { nix_addr.as_ffi_pair() };
            let socket = create_incoming_socket(Protocol::Udplite,
                    libc::SOCK_DGRAM, libc::IPPROTO_UDPLITE,
                    sockaddr, socklen,
                    Some(0), false, None,
            )?;
            #[cfg(target_os="linux")]
            const UDPLITE_SEND_CSCOV: c_int = 10;
            #[cfg(target_os="linux")]
            const UDPLITE_RECV_CSCOV: c_int = 11;
            let ret = unsafe { libc::setsockopt(socket,
                    libc::IPPROTO_UDPLITE,
                    UDPLITE_SEND_CSCOV,
                    &8 as *const c_int as *const c_void,
                    std::mem::size_of::<c_int>() as libc::socklen_t
            ) };
            if ret != 0 {
                eprintln!("Connot set UDPLITE_SEND_CSCOV for udplite://{}: {}, continuing anyway.",
                    addr, io::Error::last_os_error()
                );
            }
            unsafe { Ok(UdpSocket::from_raw_fd(socket)) }
        }
    ).unwrap_or_else(|| std::process::exit(1) );
    let token = Token(entry.key());
    entry.insert(encapsulate(socket, token));
}


/// also for listeners, deletes on drop if named
#[cfg(unix)]
pub struct UnixSocketWrapper<S: Descriptor>(pub S, pub Box<str>);
#[cfg(unix)]
impl<S: Descriptor> UnixSocketWrapper<S> {
    fn create(on: String,  server: &mut Server,  binder: fn(&str)->Result<S,io::Error>)
    -> Option<Self> {
        match binder(&on) {
            Ok(socket) => Some(UnixSocketWrapper(socket, on.into_boxed_str())),
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied
            && server.path_base.starts_with("/") => {
                eprintln!("Doesn't have permission to create unix socket in {}, trying current directory instead",
                    server.path_base
                );
                server.path_base = "";
                Self::create(on, server, binder)
            }
            Err(ref e) if e.kind() == ErrorKind::AddrInUse => {
                // try to connect to see if it's stale, then remove it and try again if it is
                match UnixStream::connect(&on) {
                    Err(ref e) if e.kind() == ErrorKind::ConnectionRefused
                    || e.kind() == ErrorKind::NotFound => {
                        // stale or not a socket
                        // TODO test if path is a socket first
                        match std::fs::remove_file(&on) {
                            Err(ref e) if e.kind() != ErrorKind::NotFound => {
                                eprintln!("Cannot remove stale socket {:?}: {}", on, e);
                                None
                            }
                            _ => {
                                eprintln!("Removed stale socket {:?}", on);
                                // try again
                                Self::create(on, server, binder)
                            }
                        }
                    },
                    _ => {
                        eprintln!("socket {:?} already exists, another instance might already be running", on);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Cannot listen on {}: {}", on, e.description());
                None
            }
        }
    }
}
#[cfg(unix)]
impl UnixSocketWrapper<UnixListener> {
    pub fn create_stream_listener(service_name: &str,  server: &mut Server,
            encapsulate: fn(Self)->ServiceSocket
    ) {
        let on = format!("{}.socket", service_name);
        if let Some(socket) = Self::create(on, server, |path| UnixListener::bind(path) ) {
            let entry = server.sockets.vacant_entry();
            server.poll.register(&*socket, Token(entry.key()), Ready::readable(), PollOpt::edge())
                .expect("Cannot register unix stream listener");
            entry.insert(encapsulate(socket));
        }
        Self::create_seqpacket_listener(service_name, server, encapsulate);
    }

    pub fn create_seqpacket_listener(service_name: &str,  server: &mut Server,
            encapsulate: fn(Self)->ServiceSocket
    ) {
        let on = format!("{}_seqpacket.socket", service_name);
        let res = Self::create(on, server, |path| {
            let mut sockbuf = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
            sockbuf.sun_family = libc::AF_UNIX as libc::sa_family_t;
            if path.len() > std::mem::size_of_val(&sockbuf.sun_path) {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            for (byte, dst) in path.bytes().zip(&mut sockbuf.sun_path[..]) {
                *dst = byte as c_char;
            }
            let sockaddr = unsafe { &*(&sockbuf as *const _ as *const libc::sockaddr) };
            let offset = &sockbuf.sun_path as *const _ as usize - &sockbuf as *const _ as usize;
            let socklen = offset as libc::socklen_t + path.len() as libc::socklen_t;
            let listener = create_incoming_socket(Protocol::Udsq,
                    libc::SOCK_SEQPACKET, 0,
                    &sockaddr, socklen,
                    None, false, Some(10/*FIXME*/),
            )?;
            Ok(unsafe { UnixListener::from_raw_fd(listener) })
        });
        if let Some(socket) = res {
            let entry = server.sockets.vacant_entry();
            server.poll.register(&*socket, Token(entry.key()), Ready::readable(), PollOpt::edge())
                .expect("Cannot register unix seqpacket listener");
            entry.insert(encapsulate(socket));
        }
    }
}
#[cfg(unix)]
impl UnixSocketWrapper<UnixDatagram> {
    pub fn create_datagram_socket(service_name: &str,  poll_for: Ready,
            server: &mut Server,  encapsulate: fn(Self)->ServiceSocket
    ) {
        let on = format!("{}_dgram.socket", service_name);
        if let Some(socket) = Self::create(on, server, |path| UnixDatagram::bind(path) ) {
            let entry = server.sockets.vacant_entry();
            server.poll.register(&*socket, Token(entry.key()), poll_for, PollOpt::edge())
                        .expect("Cannot register unix datagram socket");
            entry.insert(encapsulate(socket));
        }
    }
}
#[cfg(unix)]
impl<S: Descriptor> Deref for UnixSocketWrapper<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.0
    }
}
#[cfg(unix)]
impl<S: Descriptor> Drop for UnixSocketWrapper<S> {
    fn drop(&mut self) {
        if !self.1.starts_with('\0') {
            if let Err(err) = std::fs::remove_file(self.1.as_ref()) {
                eprintln!("Couldn't delete {}: {}", self.1, err);
            }
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


/// Create a posix message queue, open it as nonblocking and register it with mio.
///
/// capacity and max message size should be set via the options parameter.
#[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
pub fn listen_posixmq(server: &mut Server,  service_name: &'static str,  poll_for: Ready,
        options: &mut posixmq::OpenOptions,
        encapsulate: &mut dyn FnMut(PosixMqWrapper, Token)->ServiceSocket
) {
    match options.create().nonblocking().open(service_name) {
        Ok(mq) => {
            let entry = server.sockets.vacant_entry();
            let token = Token(entry.key());
            let res = server.poll.register(&mq, token, poll_for, mio::PollOpt::edge());
            if let Err(e) = res {
                eprintln!("Cannot register posix message queue /{} with mio: {}, skipping",
                    service_name, e
                );
            } else {
                entry.insert(encapsulate(PosixMqWrapper(mq, service_name), token));
            }
        }
        Err(e) => {
            eprintln!("Cannot open posix message queue /{}: {}", service_name, e);
        }
    }
}
