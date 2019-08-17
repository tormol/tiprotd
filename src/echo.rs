use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::rc::Rc;
#[cfg(unix)]
use std::os::unix::net::SocketAddr as UnixSocketAddr;

use mio::{IoVec, Ready, Token};
use mio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use mio_uds::{UnixDatagram, UnixListener};

use crate::Server;
use crate::ServiceSocket;
use crate::helpers::*;

const ECHO_PORT: u16 = 7; // read and write

pub enum EchoSocket {
    TcpListener(TcpListener),
    TcpConn(TcpStreamWrapper, VecDeque<u8>, bool),
    Udp(UdpSocket, VecDeque<(SocketAddr,Rc<[u8]>)>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper, VecDeque<u8>, bool),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, VecDeque<(UnixSocketAddr,Rc<[u8]>)>),
}

fn tcp_echo(conn: &mut TcpStreamWrapper,  unsent: &mut VecDeque<u8>,  recv_shutdown: &mut bool,
        buffer: &mut[u8],  readiness: Ready
) -> EntryStatus {
    if !*recv_shutdown && readiness.is_readable() {
        loop {
            match conn.read(buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) if len > 0 => {
                    // if unsent.is_empty() {
                    //     // try to send without copying
                    //     match conn.write_bufs(&[buffer[..len].into(), buffer[..len].into()]) {
                    //         Ok(wrote) => {

                    //         }
                    //     }
                    // }
                    if conn.limit_counters.request_resources(2*len) {
                        unsent.extend(&buffer[..len]);
                        unsent.extend(&buffer[..len]);
                    } else {
                        return Remove;
                    }
                }
                Ok(0) => {
                    *recv_shutdown = true;
                    break;
                }
                end => {
                    conn.limit_counters.release_resources(unsent.len());
                    conn.end(end, "reading bytes to echo");
                    return Remove;
                }
            }
        }
    }
    // if the socket is write ready but we don't have anything to write,
    // we cannot drain the readiness, so always try to write when we get some
    // if there is data to write, we need to try writing it even if no more
    // data is received
    while !unsent.is_empty() {
        // use vectored io to send both slices of the deque at once
        // IoVec can't be empty though, so need to special case
        let (first, second) = unsent.as_slices();
        let result = match IoVec::from_bytes(second) {
            Some(second) => conn.write_bufs(&[first.into(), second]),
            None => conn.write(first),
        };
        match result {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(len @ 1..=std::usize::MAX) => {
                conn.limit_counters.release_resources(len);
                unsent.drain(..len).for_each(|_| {} );
            }
            end => {
                conn.limit_counters.release_resources(unsent.len());
                conn.end(end, "echoing");
                return Remove;
            }
        }
    }
    if *recv_shutdown && unsent.is_empty() {
        conn.shutdown(Shutdown::Both);
        Remove
    } else {
        Drained
    }
}

#[cfg(unix)]
fn unix_stream_echo(conn: &mut UnixStreamWrapper,  unsent: &mut VecDeque<u8>,
        recv_shutdown: &mut bool,  buffer: &mut[u8],  readiness: Ready
) -> EntryStatus {
    if !*recv_shutdown && readiness.is_readable() {
        loop {
            match conn.read(buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) if len > 0 => {
                    unsent.extend(&buffer[..len]);
                    unsent.extend(&buffer[..len]);
                }
                Ok(0) => {
                    *recv_shutdown = true;
                    break;
                }
                end => {
                    conn.end(end, "reading bytes to echo");
                    return Remove;
                }
            }
        }
    }
    while !unsent.is_empty() {
        // use vectored io to send both slices of the deque at once
        // IoVec can't be empty though, so need to special case
        let (first, second) = unsent.as_slices();
        let result = match IoVec::from_bytes(second) {
            Some(second) => conn.write_bufs(&[first.into(), second]),
            None => conn.write(first),
        };
        match result {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(len @ 1..=std::usize::MAX) => {
                unsent.drain(..len).for_each(|_| {} );
            }
            end => {
                conn.end(end, "echoing");
                return Remove;
            }
        }
    }
    if *recv_shutdown && unsent.is_empty() {
        conn.shutdown(Shutdown::Both);
        Remove
    } else {
        Drained
    }
}

use self::EchoSocket::*;

impl EchoSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "echo", ECHO_PORT,
            &mut|listener, Token(_)| ServiceSocket::Echo(TcpListener(listener))
        );
        listen_udp(server, "echo", ECHO_PORT, Ready::readable() | Ready::writable(),
            &mut|socket, Token(_)| ServiceSocket::Echo(Udp(socket, VecDeque::new()))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("echo", server,
            &mut|listener, Token(_)| ServiceSocket::Echo(UnixStreamListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("echo", Ready::all(), server,
            &mut|socket, Token(_)| ServiceSocket::Echo(UnixDatagram(socket, VecDeque::new()))
        );
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut TcpListener(ref listener) => {
                tcp_accept_loop(listener, server, &"echo", Ready::all(),
                    |_| Some(()),
                    |stream, (), Token(_)| {
                        ServiceSocket::Echo(TcpConn(stream, VecDeque::new(), false))
                    },
                )
            }
            &mut TcpConn(ref mut stream, ref mut unsent, ref mut read_shutdown) => {
                tcp_echo(stream, unsent, read_shutdown, &mut server.buffer, readiness)
            }
            // don't count stored UDP data toward resource limits, as sending
            // is only limited by the OS's socket buffer, and not by the
            // client or network. A client should not be able to cause an
            // issue here before hitting its UDP send limit.
            &mut Udp(ref socket, ref mut unsent) => {
                if readiness.is_readable() {
                    let result = udp_receive(socket, server, "echo", |len, from, server| {
                        if server.limits.allow_unacknowledged_send(from, 2*len) {
                            eprintln!("{} udp://{} sends {} bytes to echo",
                                now(), native_addr(from), len
                            );
                            // TODO send directly if unsent.is_empty()
                            let msg = Rc::<[u8]>::from(&server.buffer[..len]);
                            unsent.push_back((from, msg.clone()));
                            unsent.push_back((from, msg));
                        }
                    });
                    if result == Remove {
                        return Remove;
                    }
                }
                while let Some((addr,msg)) = unsent.front() {
                    if udp_send(socket, msg, addr, "echo") {
                        let _ = unsent.pop_front();
                    } else {
                        break;
                    }
                }
                if unsent.capacity() > 10  &&  unsent.capacity()/8 > unsent.len() {
                    unsent.shrink_to_fit();
                }
                Drained
            }
            #[cfg(unix)]
            &mut UnixDatagram(ref socket, ref mut unsent) => {
                if readiness.is_readable() {
                    loop {
                        match socket.recv_from(&mut server.buffer) {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            // send errors might be returned on the next read
                            Err(e) => eprintln!("unix datagram echo error (on receive): {}", e),
                            Ok((len, from)) => {
                                eprintln!("{} uddg://{:?} sends {} bytes to echo",
                                    now(), from, len
                                );
                                // TODO send directly if unsent.is_empty()
                                let msg = Rc::<[u8]>::from(&server.buffer[..len]);
                                unsent.push_back((from.clone(), msg.clone()));
                                unsent.push_back((from, msg));
                            }
                        }
                    }
                }
                while let Some((addr,msg)) = unsent.front() {
                    if unix_datagram_send(socket, msg, &addr, "echo") {
                        let _ = unsent.pop_front();
                    } else {
                        break;
                    }
                }
                if unsent.capacity() > 10  &&  unsent.capacity()/8 > unsent.len() {
                    unsent.shrink_to_fit();
                }
                Drained
            }
            #[cfg(unix)]
            &mut UnixStreamListener(ref listener) => {
                unix_stream_accept_loop(listener, server, &"echo", Ready::all(),
                    |_| Some(()),
                    |stream, (), Token(_)| {
                        ServiceSocket::Echo(UnixStreamConn(stream, VecDeque::new(), false))
                    }
                )
            }
            #[cfg(unix)]
            &mut UnixStreamConn(ref mut conn, ref mut unsent, ref mut read_shutdown) => {
                unix_stream_echo(conn, unsent, read_shutdown, &mut server.buffer, readiness)
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &TcpListener(ref listener) => Some(listener),
            &Udp(ref socket, _) => Some(socket),
            &TcpConn(ref conn, _, _) => Some(&**conn),
            #[cfg(unix)]
            &UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(unix)]
            &UnixStreamConn(ref conn, _, _) => Some(&**conn),
        }
    }
}
