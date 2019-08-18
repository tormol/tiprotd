use std::fmt::Debug;
use std::net::Shutdown;
use std::io::{ErrorKind, Read, Write, stdout};

use mio::{Ready, Token};
use mio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use mio_uds::{UnixDatagram, UnixListener};

use crate::Server;
use crate::ServiceSocket;
use crate::helpers::*;

const DISCARD_PORT: u16 = 9;

#[derive(Debug)]
pub enum DiscardSocket {
    // On *nix I could merge many of these, using read() directly,
    // but need to release resources
    TcpListener(TcpListener),
    TcpConn(TcpStreamWrapper),
    Udp(UdpSocket),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>),
    //#[cfg(unix)]
    //Pipe(Pipe)
    #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
    PosixMq(PosixMqWrapper),
}

use self::DiscardSocket::*;

fn anti_discard(from: &dyn Debug,  protocol: &str,  bytes: &[u8]) {
    let now = now();
    eprintln!("{} {}://{:?} discards {} bytes", now, protocol, from, bytes.len());
    // TODO rate limit logging to prevent filling up disk
    print!("{} {}://{:?} discards {} bytes: ", now, protocol, from, bytes.len());
    // TODO escape to printable characters
    stdout().write(bytes).expect("Writing to stdout failed");
    if bytes.last().cloned() != Some(b'\n') {
        println!();
    }
}

impl DiscardSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "discard", DISCARD_PORT,
            &mut|listener, Token(_)| ServiceSocket::Discard(TcpListener(listener))
        );
        listen_udp(server, "discard", DISCARD_PORT, Ready::readable(),
            &mut|socket, Token(_)| ServiceSocket::Discard(Udp(socket))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("discard", server,
            &mut|listener, Token(_)| ServiceSocket::Discard(UnixStreamListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("discard", Ready::readable(), server,
            &mut|socket, Token(_)| ServiceSocket::Discard(UnixDatagram(socket))
        );
        #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
        listen_posixmq(server, "discard", Ready::readable(),
            posixmq::OpenOptions::readonly()
                .mode(0o622)
                .max_msg_len(server.buffer.len())
                .capacity(2),
            &mut|mq, Token(_)| ServiceSocket::Discard(PosixMq(mq))
        );
    }

    pub fn ready(&mut self,  _: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut TcpListener(ref listener) => {
                tcp_accept_loop(listener, server,  &"discard", Ready::readable(),
                    |stream| {stream.shutdown(Shutdown::Write); Some(())}, // likely long-lived
                    |stream, (), Token(_)| ServiceSocket::Discard(TcpConn(stream)),
                )
            }
            &mut TcpConn(ref mut stream) => {
                loop {
                    match stream.read(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Ok(len) if len > 0 => {
                            anti_discard(&stream.native_addr, "tcp", &server.buffer[..len]);
                        }
                        end => {
                            stream.end(end, "reading bytes to discard");
                            break Remove;
                        }
                    }
                }
            }
            &mut Udp(ref socket) => {
                loop {
                    match socket.recv_from(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("{} discard UDP error: {}", now(), e);
                            break Remove; // some errors should probably be ignored, but see what happens
                        }
                        Ok((len, from)) => {
                            anti_discard(&native_addr(from), "udp", &server.buffer[..len]);
                        }
                    }
                }
            }
            #[cfg(unix)]
            &mut UnixStreamListener(ref mut listener) => {
                unix_stream_accept_loop(listener, server, &"discard", Ready::readable(),
                    |stream| {stream.shutdown(Shutdown::Write); Some(())}, // likely long-lived
                    |stream, (), Token(_)| ServiceSocket::Discard(UnixStreamConn(stream))
                )
            }
            #[cfg(unix)]
            &mut UnixStreamConn(ref mut stream) => {
                loop {
                    match stream.read(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Ok(len) if len > 0 => anti_discard(&stream.addr, "uds", &server.buffer[..len]),
                        end => {
                            stream.end(end, "reading bytes to discard");
                            break Remove;
                        }
                    }
                }
            }
            #[cfg(unix)]
            &mut UnixDatagram(ref socket) => {
                loop {
                    match socket.recv_from(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error receiving unix datagram packet to discard: {}", e);
                            break Remove;
                        }
                        Ok((len, from)) => {
                            anti_discard(&from, "uddg", &server.buffer[..len]);
                        }
                    }
                }
            }
            #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
            &mut PosixMq(ref mq) => {
                loop {
                    match mq.receive(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error receiving from posix message queue /discard: {}, removing it.", e);
                            break Remove;
                        },
                        Ok((_priority, len)) => anti_discard(&"/discard", "mq", &server.buffer[..len]),
                    }
                }
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &TcpListener(ref listener) => Some(listener),
            &Udp(ref socket) => Some(socket),
            &TcpConn(ref conn) => Some(&**conn),
            #[cfg(unix)]
            &UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &UnixDatagram(ref socket) => Some(&**socket),
            #[cfg(unix)]
            &UnixStreamConn(ref conn) => Some(&**conn),
            #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
            &PosixMq(ref mq) => Some(&**mq),
        }
    }
}
