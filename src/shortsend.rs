use std::collections::HashSet;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::time::SystemTime;
#[cfg(unix)]
use std::os::unix::net::SocketAddr as UnixSocketAddr;

use mio::{Ready, Token};
use mio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use mio_uds::{UnixDatagram, UnixListener};

use crate::Server;
use crate::ServiceSocket;
use crate::helpers::*;

fn tcp_shortsend_accept_loop
(listener: &TcpListener,  server: &mut Server,  service_name: &'static &'static str,  msg: &[u8])
-> EntryStatus {
    let mut remove_listener = false;
    let accept_result = tcp_accept_loop(listener, server, service_name, Ready::writable(),
        |stream| {
            match stream.write(msg) {
                Ok(wrote) if wrote == msg.len() => stream.end(Ok(0), "/*print unreachable*/"),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    eprintln!("TCP send buffer appears to have zero capacity! stopping TCP {}",
                        stream.service_name
                    );
                    remove_listener = true;
                }
                Ok(wrote) if wrote > 0 => {
                    eprintln!("TCP send buffer is too small to send the {} bytes of {} in one go o_0, stopping TCP {}",
                        msg.len(), stream.service_name, service_name
                    );
                    remove_listener = true;
                }
                closing => {
                    eprintln!("tcp://{} managed to close the connection before we could send the {} bytes of {}",
                        stream.native_addr, msg.len(), service_name
                    );
                    stream.end(closing, &format!("sending {}", service_name));
                }
            }
            None
        },
        |_, (), _| unreachable!("{} TCP streams cannot be stored", service_name)
    );
    if remove_listener {
        Remove
    } else {
        accept_result
    }
}

#[cfg(unix)]
fn unix_stream_shortsend_accept_loop
(listener: &UnixListener,  server: &mut Server,  service_name: &'static &'static str,  msg: &[u8])
-> EntryStatus {
    let mut remove_listener = false;
    let accept_result = unix_stream_accept_loop(listener, server, service_name, Ready::writable(),
        |stream| {
            match stream.write(msg) {
                Ok(wrote) if wrote == msg.len() => stream.end(Ok(0), "/*print unreachable*/"),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    eprintln!(
                        "unix stream send buffer appears to have zero capacity! stopping TCP {}",
                        stream.service_name
                    );
                    remove_listener = true;
                }
                Ok(wrote) if wrote > 0 => {
                    eprintln!("unix stream send buffer is too small to send the {} bytes of {} in one go o_0, stopping TCP {}",
                        msg.len(), stream.service_name, service_name
                    );
                    remove_listener = true;
                }
                closing => {
                    eprintln!("uds://{:?} managed to close the connection before we could send the {} bytes of {}",
                        stream.addr, msg.len(), service_name
                    );
                    stream.end(closing, &format!("sending {}", service_name));
                }
            }
            None
        },
        |_, (), _| unreachable!("{} unix stream connections cannot be stored", service_name)
    );
    if remove_listener {
        Remove
    } else {
        accept_result
    }
}

fn udp_shortsend(
        socket: &UdpSocket,
        server: &mut Server,
        service_name: &str,
        readiness: Ready,
        outstanding: &mut HashSet<SocketAddr>,
        msg: &[u8]
) -> EntryStatus {
    if readiness.is_readable() {
        loop {
            match socket.recv_from(&mut server.buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                // send errors might be returned on the next read
                Err(e) => eprintln!("UDP {} error (on receive): {}", service_name, e),
                Ok((len, from)) => {
                    if server.limits.allow_unacknowledged_send(from, msg.len()) {
                        eprintln!("{} udp://{} sends {} bytes for {}",
                            now(), native_addr(from), len, service_name
                        );
                        // little copying involved, so don't bother sending directly
                        outstanding.insert(from);
                    }
                }
            }
        }
    }
    // TODO try sendmmsg where available
    while let Some(&addr) = outstanding.iter().next() {
        if udp_send(socket, msg, &addr, service_name) {
            let _ = outstanding.remove(&addr);
        } else {
            break;
        }
    }
    Drained
}

#[cfg(unix)]
fn unix_datagram_shortsend(
        socket: &UnixDatagram,
        service_name: &str,
        readiness: Ready,
        outstanding: &mut Vec<UnixSocketAddr>,
        msg: &[u8],
) -> EntryStatus {
    if readiness.is_readable() {
        loop {
            match socket.recv_from(&mut [0; 32]) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                // send errors might be returned on the next read
                Err(e) => eprintln!("unix datagram {} error (on receive): {}", service_name, e),
                Ok((len, from)) => {
                    eprintln!("{} uddg://{:?} sends {} bytes for {}",
                        now(), from, len, service_name
                    );
                    // little copying involved, so don't bother sending directly
                    outstanding.push(from);
                }
            }
        }
    }
    // TODO try sendmmsg
    while let Some(addr) = outstanding.last() {
        if unix_datagram_send(socket, msg, addr, service_name) {
            let _ = outstanding.pop();
        } else {
            break;
        }
    }
    Drained
}


const QOTD_PORT: u16 = 17;
const QOTD: &[u8] = b"No quote today, the DB has gone away\n";

pub enum QotdSocket {
    TcpListener(TcpListener),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Vec<UnixSocketAddr>), // doesn't implement Hash
    #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
    PosixMq(PosixMqWrapper),
}

impl QotdSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "qotd", QOTD_PORT,
            &mut|listener, Token(_)| ServiceSocket::Qotd(QotdSocket::TcpListener(listener))
        );
        listen_udp(server, "qotd", QOTD_PORT, Ready::readable() | Ready::writable(),
            &mut|socket, Token(_)| ServiceSocket::Qotd(QotdSocket::Udp(socket, HashSet::new()))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("qotd", server,
            |listener| ServiceSocket::Qotd(QotdSocket::UnixStreamListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("qotd", Ready::all(), server,
            |socket| ServiceSocket::Qotd(QotdSocket::UnixDatagram(socket, Vec::new()))
        );
        #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
        listen_posixmq(server, "qotd", Ready::writable(),
            posixmq::OpenOptions::writeonly().mode(0o644).max_msg_len(QOTD.len()).capacity(1),
            &mut|mq, Token(_)| ServiceSocket::Qotd(QotdSocket::PosixMq(mq))
        );
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut QotdSocket::TcpListener(ref listener) => {
                tcp_shortsend_accept_loop(listener, server, &"qotd", QOTD)
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixStreamListener(ref listener) => {
                unix_stream_shortsend_accept_loop(listener, server, &"qotd", QOTD)
            }
            &mut QotdSocket::Udp(ref socket, ref mut outstanding) => {
                udp_shortsend(socket, server, "qotd", readiness, outstanding, QOTD)
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixDatagram(ref socket, ref mut outstanding) => {
                unix_datagram_shortsend(socket, "qotd", readiness, outstanding, QOTD)
            }
            #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
            &mut QotdSocket::PosixMq(ref mq) => {
                loop {
                    match mq.send(0, QOTD) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error sending to posix message queue /qotd: {}, removing it.", e);
                            break Remove;
                        }
                        Ok(()) => {}
                    }
                }
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &QotdSocket::TcpListener(ref listener) => Some(listener),
            &QotdSocket::Udp(ref socket, _) => Some(socket),
            #[cfg(unix)]
            &QotdSocket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &QotdSocket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
            &QotdSocket::PosixMq(ref mq) => Some(&**mq),
        }
    }
}


const TIME32_PORT: u16 = 37;

pub enum Time32Socket {
    TcpListener(TcpListener),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Vec<UnixSocketAddr>),
}

fn new_time32() -> [u8;4] {
    let now = SystemTime::elapsed(&SystemTime::UNIX_EPOCH).unwrap_or_else(|ste| {
        // Pre-1970 time? The system might have fallen into my own trap.
        // In any case, this is just more fun to pass forward
        ste.duration()
    });
    let now = now.as_secs();
    // lsb: bit switches every ...
    // 0: 1s
    // 8: 256s ≈ 4min
    // 11: ~64min ≈ 1hour
    // 15: ~16hour ≈ 1day
    let random_2 = ((now >> 16) ^ (now >> 8)) & 0b011;
    // mess with the response, switch type every ~four minutes
    let sometime = match random_2 {
        0 => now & 0xff, // it's the 70's again
        1 => 0x7fffff00 | now, // can you handle it
        2 => now.wrapping_sub(60*60*24*(365*100+100/4)), // a blast from the past
        3 => now ^ 0xff, // going backwards
        _ => unreachable!()
    };
    [// as bytes in network order
        (sometime >> 24) as u8,
        (sometime >> 16) as u8,
        (sometime >>  8) as u8,
        sometime as u8
    ]
}

impl Time32Socket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "time32", TIME32_PORT,
            &mut|listener, Token(_)| ServiceSocket::Time32(Time32Socket::TcpListener(listener))
        );
        listen_udp(server, "time32", TIME32_PORT, Ready::readable() | Ready::writable(),
            &mut|socket, Token(_)| ServiceSocket::Time32(Time32Socket::Udp(socket, HashSet::new()))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("time32", server,
            |listener| ServiceSocket::Time32(Time32Socket::UnixStreamListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("time32", Ready::all(), server,
            |socket| ServiceSocket::Time32(Time32Socket::UnixDatagram(socket, Vec::new()))
        );
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        let sometime = new_time32();
        match self {
            &mut Time32Socket::TcpListener(ref listener) => {
                tcp_shortsend_accept_loop(listener, server, &"time32", &sometime)
            }
            #[cfg(unix)]
            &mut Time32Socket::UnixStreamListener(ref listener) => {
                unix_stream_shortsend_accept_loop(listener, server, &"time32", &sometime)
            }
            &mut Time32Socket::Udp(ref socket, ref mut outstanding) => {
                udp_shortsend(socket, server, "time32", readiness, outstanding, &sometime)
            }
            #[cfg(unix)]
            &mut Time32Socket::UnixDatagram(ref socket, ref mut outstanding) => {
                unix_datagram_shortsend(socket, "time32", readiness, outstanding, &sometime)
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &Time32Socket::TcpListener(ref listener) => Some(listener),
            &Time32Socket::Udp(ref socket, _) => Some(socket),
            #[cfg(unix)]
            &Time32Socket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &Time32Socket::UnixDatagram(ref socket, _) => Some(&**socket),
        }
    }
}
