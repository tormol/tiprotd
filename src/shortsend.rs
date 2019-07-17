use std::collections::HashSet;
use std::io::{ErrorKind, Write};
use std::net::{Shutdown, SocketAddr};
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

fn tcp_write_short(stream: &mut TcpStreamWrapper,  mut written: u32,  msg: &[u8])
-> (EntryStatus, u32) {
    loop {
        match stream.write(&msg[written as usize..]) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return (Drained, written),
            Ok(wrote) if written as usize + wrote == msg.len() => {
                stream.end(Ok(0), "/*unreachable*/");
                return (Remove, msg.len() as u32);
            }
            Ok(wrote @ 1..=std::usize::MAX) => {
                if wrote == 0 {
                    eprintln!("Could only write {} of {} bytes of {} response to tcp://{} o_O",
                        wrote, msg.len(), stream.service_name, stream.native_addr
                    );
                }
                written += wrote as u32;
            }
            closing => {
                eprintln!("tcp://{} managed to close the connection before we could send the {} bytes of {}",
                    stream.native_addr, msg.len(), stream.service_name
                );
                let operation = format!("sending {}", stream.service_name);
                stream.end(closing, &operation);
                return (Remove, written);
            }
        }
    }
}

#[cfg(unix)]
fn unix_stream_write_short(stream: &mut UnixStreamWrapper,  mut written: u32,  msg: &[u8])
-> (EntryStatus, u32) {
    loop {
        match stream.write(&msg[written as usize..]) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return (Drained, written),
            Ok(wrote) if written as usize + wrote == msg.len() => {
                stream.end(Ok(0), "/*unreachable*/");
                return (Remove, msg.len() as u32);
            }
            Ok(wrote @ 1..=std::usize::MAX) => {
                if wrote == 0 {
                    eprintln!("Could only write {} of {} bytes of {} response to uds://{:?} o_O",
                        wrote, msg.len(), stream.service_name, stream.addr
                    );
                }
                written += wrote as u32;
            }
            closing => {
                eprintln!("uds://{:?} managed to close the connection before we could send the {} bytes of {}",
                    stream.addr, msg.len(), stream.service_name
                );
                let operation = format!("sending {}", stream.service_name);
                stream.end(closing, &operation);
                return (Remove, written);
            }
        }
    }
}

fn udp_short(socket: &UdpSocket,  outstanding: &mut HashSet<SocketAddr>,
        readiness: Ready,  server: &mut Server,  msg: &[u8],  service_name: &str
) -> EntryStatus {
    if readiness.is_readable() {
        loop {
            match socket.recv_from(&mut server.buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                // send errors might be returned on the next read
                Err(e) => eprintln!("UDP {} error (on receive): {}", service_name, e),
                Ok((len, from)) => {
                    if server.limits.allow_unacknowledged_send(from, QOTD.len()) {
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
fn unix_datagram_short(socket: &UnixDatagram,  outstanding: &mut Vec<UnixSocketAddr>,
        readiness: Ready,  msg: &[u8],  service_name: &str
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
    TcpConn(TcpStreamWrapper, u32),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper, u32),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Vec<UnixSocketAddr>), // doesn't implement Hash
    #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
    PosixMq(PosixMqWrapper),
}

impl QotdSocket {
    pub fn setup(server: &mut Server) {
        server.listen_tcp(QOTD_PORT, "qotd",
            &mut|listener, Token(_)| ServiceSocket::Qotd(QotdSocket::TcpListener(listener))
        );
        server.listen_udp(QOTD_PORT, Ready::readable() | Ready::writable(), "qotd",
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
        server.setup_mq("qotd", Ready::writable(),
            posixmq::OpenOptions::writeonly().mode(0o644).max_msg_len(QOTD.len()).capacity(1),
            &mut|mq, Token(_)| ServiceSocket::Qotd(QotdSocket::PosixMq(mq))
        );
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut QotdSocket::TcpListener(ref listener) => {
                tcp_accept_loop(listener, server, &"qotd", Ready::writable(),
                    |stream| match tcp_write_short(stream, 0, QOTD) {
                        (Drained, wrote) => Some(wrote),
                        (Remove, _) => None,
                        (_, _) => unreachable!()
                    },
                    |stream, written, Token(_)| {
                        stream.shutdown(Shutdown::Read);
                        ServiceSocket::Qotd(QotdSocket::TcpConn(stream, written))
                    }
                )
            }
            &mut QotdSocket::TcpConn(ref mut stream, ref mut written) => {
                let (status, now_written) = tcp_write_short(stream, *written, QOTD);
                *written = now_written;
                status
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixStreamListener(ref listener) => {
                unix_stream_accept_loop(listener, server, &"qotd", Ready::writable(),
                    |stream| match unix_stream_write_short(stream, 0, QOTD) {
                        (Drained, wrote) => Some(wrote),
                        (Remove, _) => None,
                        (_, _) => unreachable!()
                    },
                    |stream, written, Token(_)| {
                        stream.shutdown(Shutdown::Read);
                        ServiceSocket::Qotd(QotdSocket::UnixStreamConn(stream, written))
                    }
                )
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixStreamConn(ref mut stream, ref mut written) => {
                let (status, now_written) = unix_stream_write_short(stream, *written, QOTD);
                *written = now_written;
                status
            }
            &mut QotdSocket::Udp(ref socket, ref mut outstanding) => {
                udp_short(socket, outstanding, readiness, server, QOTD, "qotd")
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixDatagram(ref socket, ref mut outstanding) => {
                unix_datagram_short(socket, outstanding, readiness, QOTD, "qotd")
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
            &QotdSocket::TcpConn(ref conn, _) => Some(&**conn),
            #[cfg(unix)]
            &QotdSocket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &QotdSocket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(unix)]
            &QotdSocket::UnixStreamConn(ref conn, _) => Some(&**conn),
            #[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
            &QotdSocket::PosixMq(ref mq) => Some(&**mq),
        }
    }
}


const TIME32_PORT: u16 = 37;

pub enum Time32Socket {
    TcpListener(TcpListener),
    TcpConn(TcpStreamWrapper),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper),
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
        server.listen_tcp(TIME32_PORT, "time32",
            &mut|listener, Token(_)| ServiceSocket::Time32(Time32Socket::TcpListener(listener))
        );
        server.listen_udp(TIME32_PORT, Ready::readable() | Ready::writable(), "time32",
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
                tcp_accept_loop(listener, server, &"time32", Ready::writable(),
                    |stream| match tcp_write_short(stream, 0, &sometime) {
                        (Drained, 0) => Some(()),
                        _ => None
                    },
                    |stream, (), Token(_)| ServiceSocket::Time32(Time32Socket::TcpConn(stream))
                )
            }
            &mut Time32Socket::TcpConn(ref mut stream) => {
                match tcp_write_short(stream, 0, &sometime) {
                    (Drained, 0) => Drained,
                    _ => Remove,
                }
            }
            #[cfg(unix)]
            &mut Time32Socket::UnixStreamListener(ref listener) => {
                unix_stream_accept_loop(listener, server, &"time32", Ready::writable(),
                    |stream| match unix_stream_write_short(stream, 0, &sometime) {
                        (Drained, 0) => Some(()),
                        _ => None
                    },
                    |stream, (), _| ServiceSocket::Time32(Time32Socket::UnixStreamConn(stream))
                )
            }
            #[cfg(unix)]
            &mut Time32Socket::UnixStreamConn(ref mut stream) => {
                match unix_stream_write_short(stream, 0, &sometime) {
                    (Drained, 0) => Drained,
                    _ => Remove,
                }
            }
            &mut Time32Socket::Udp(ref socket, ref mut outstanding) => {
                udp_short(socket, outstanding, readiness, server, &sometime, "time32")
            }
            #[cfg(unix)]
            &mut Time32Socket::UnixDatagram(ref socket, ref mut outstanding) => {
                unix_datagram_short(socket, outstanding, readiness, &sometime, "time32")
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &Time32Socket::TcpListener(ref listener) => Some(listener),
            &Time32Socket::Udp(ref socket, _) => Some(socket),
            &Time32Socket::TcpConn(ref conn) => Some(&**conn),
            #[cfg(unix)]
            &Time32Socket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &Time32Socket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(unix)]
            &Time32Socket::UnixStreamConn(ref conn) => Some(&**conn),
        }
    }
}
