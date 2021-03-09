use std::collections::HashSet;
use std::fs::File;
use std::io::{ErrorKind, Write, BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::SystemTime;

use mio::{Ready, Token};
use mio::net::{TcpListener, UdpSocket};
#[cfg(feature="udplite")]
use udplite::UdpLiteSocket;
#[cfg(unix)]
use uds::{UnixSocketAddr, UnixDatagramExt};
#[cfg(unix)]
use mio_uds::{UnixDatagram, UnixListener};
#[cfg(feature="seqpacket")]
use uds::nonblocking::UnixSeqpacketListener;
use rand::seq::SliceRandom;
use chrono::{TimeZone, Utc, offset::FixedOffset, DateTime, NaiveDateTime};

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
                    eprintln!(
                        "unix stream send buffer is too small to send the {} bytes of {} in one go o_0, stopping unix stream {}",
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

#[cfg(feature="seqpacket")]
fn unix_seqpacket_shortsend_accept_loop(
    listener: &UnixSeqpacketListener,  server: &mut Server,
    service_name: &'static &'static str,  msg: &[u8]
) -> EntryStatus {
    let mut remove_listener = false;
    let accept_result = unix_seqpacket_accept_loop(listener, server, service_name, Ready::writable(),
        |conn| {
            match conn.send(msg) {
                Ok(wrote) if wrote == msg.len() => conn.end(Ok(0), "/*print unreachable*/"),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    eprintln!(
                        "unix seqpacket send buffer appears to have zero capacity! stopping TCP {}",
                        conn.service_name
                    );
                    remove_listener = true;
                }
                Ok(wrote) if wrote > 0 => {
                    eprintln!(
                        "unix seqpacket send buffer is too small to send the {}-bytes packet of {}, stopping seqpacket {}",
                        msg.len(), conn.service_name, service_name
                    );
                    remove_listener = true;
                }
                closing => {
                    eprintln!("udsq://{:?} managed to close the connection before we could send the {} bytes of {}",
                        conn.addr, msg.len(), service_name
                    );
                    conn.end(closing, &format!("sending {}", service_name));
                }
            }
            None
        },
        |_, (), _| unreachable!("{} unix seqpacket connections cannot be stored", service_name)
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

fn udplite_shortsend(
    socket: &UdpLiteSocket,
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
                Err(e) => eprintln!("UDP-lite {} error (on receive): {}", service_name, e),
                Ok((len, from)) => {
                    if server.limits.allow_unacknowledged_send(from, msg.len()) {
                        eprintln!("{} udplite://{} sends {} bytes for {}",
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
        if udplite_send(socket, msg, &addr, service_name) {
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
            match socket.recv_from_unix_addr(&mut [0; 32]) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                // send errors might be returned on the next read
                Err(e) => eprintln!("unix datagram {} error (on receive): {}", service_name, e),
                Ok((len, from)) => {
                    eprintln!("{} uddg://{} sends {} bytes for {}",
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
const QOTD_FILE: &str = "quotes.txt";
const FALLBACK_QOTD: &[u8] = b"No quote today, the DB has gone away\n";

type QuoteDb = Rc<[Box<[u8]>]>;

#[derive(Debug)]
pub enum QotdSocket {
    TcpListener(TcpListener, QuoteDb, u32),
    Udp(UdpSocket, HashSet<SocketAddr>, QuoteDb, u32),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket, HashSet<SocketAddr>, QuoteDb, u32),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>, QuoteDb, u32),
    #[cfg(unix)]
    UnixDatagram(
        UnixSocketWrapper<UnixDatagram>,
        Box<(Vec<UnixSocketAddr>/*doesn't implement Hash*/, QuoteDb, u32)>
    ),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>, QuoteDb, u32),
    #[cfg(feature="posixmq")]
    PosixMq(PosixMqWrapper, QuoteDb, u32),
}

/// read file, split by lines matching /---+\s*/ and shuffle
fn read_qotes(path: &Path) -> QuoteDb {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                eprintln!("No QOTD file {:?}. Sending fallback quote instead", path);
            } else {
                eprintln!("Cannot read {:?}: {}. Sending fallback quote instead", path, e);
            }
            return Rc::from(vec![Box::from(FALLBACK_QOTD)]);
        }
    };
    let mut quotes = Vec::new();
    let mut buf = Vec::with_capacity(256);
    let mut reader = BufReader::new(file);
    loop {
        match reader.read_until(b'\n', &mut buf) {
            Err(ref e) if quotes.is_empty() => {
                eprintln!("Error reading {:?}: {}. Sending fallback quote instead.", path, e);
                return Rc::from(vec![Box::from(FALLBACK_QOTD)]);
            }
            Err(e) => {
                eprintln!("Error while reading {:?}: {}. Using {} quote(s) successfully read.",
                    path, e, quotes.len()
                );
                buf.clear(); // discard potentially half read quote
                break;
            }
            Ok(0) => break,
            Ok(n) => {
                let line_start = buf.len() - n;
                // remove trailing whitespace and normalize line endings
                // (or lack of a trailing one)
                let trailing_whitespace = buf[line_start..].iter()
                    .rev()
                    .take_while(|&&c| c.is_ascii_whitespace() )
                    .count();
                buf.truncate(buf.len()-trailing_whitespace);
                buf.push(b'\n');
                // check if buf ends with separator
                let not_whitespace = &buf[line_start..buf.len()-1];
                if not_whitespace.len() >= 3  &&  not_whitespace.iter().all(|&c| c == b'-' ) {
                    quotes.push(Box::from(&buf[..line_start]));
                    buf.clear();
                }
            }
        }
    }
    if buf.len() > 0 {
        quotes.push(buf.into_boxed_slice());
    }
    if quotes.is_empty() {
        eprintln!("No quotes in {:?}, Sending fallback quote instead", path);
        return Rc::from(vec![Box::from(FALLBACK_QOTD)]);
    }
    quotes.shuffle(&mut rand::thread_rng());
    Rc::from(quotes)
}

impl QotdSocket {
    pub fn setup(server: &mut Server) {
        let quotes = read_qotes(QOTD_FILE.as_ref());
        listen_tcp(server, "qotd", QOTD_PORT, &mut|listener, Token(_)| {
            ServiceSocket::Qotd(QotdSocket::TcpListener(listener, quotes.clone(), 0))
        });
        listen_udp(server, "qotd", QOTD_PORT, Ready::readable() | Ready::writable(),
            &mut|socket, Token(_)| {
                ServiceSocket::Qotd(QotdSocket::Udp(socket, HashSet::new(), quotes.clone(), 0))
            }
        );
        #[cfg(feature="udplite")]
        listen_udplite(server, "qotd", QOTD_PORT, Ready::readable() | Ready::writable(), Some(0),
            &mut|socket, Token(_)| {
                ServiceSocket::Qotd(QotdSocket::UdpLite(socket, HashSet::new(), quotes.clone(), 0))
            }
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("qotd", server, &mut|listener, Token(_)| {
            ServiceSocket::Qotd(QotdSocket::UnixStreamListener(listener, quotes.clone(), 0))
        });
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("qotd", Ready::all(), server,
            &mut|socket, Token(_)| {
                let state = Box::new((Vec::new(), quotes.clone(), 0));
                ServiceSocket::Qotd(QotdSocket::UnixDatagram(socket, state))
            }
        );
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("qotd", server, &mut|listener, Token(_)| {
            ServiceSocket::Qotd(QotdSocket::UnixSeqpacketListener(listener, quotes.clone(), 0))
        });
        #[cfg(feature="posixmq")]
        listen_posixmq(server, "qotd", Ready::writable(),
            posixmq::OpenOptions::writeonly()
                .mode(0o644)
                .max_msg_len(quotes.iter().map(|quote| quote.len() ).max().unwrap_or(0))
                .capacity(1),
            &mut|mq, Token(_)| ServiceSocket::Qotd(QotdSocket::PosixMq(mq, quotes.clone(), 0))
        );
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut QotdSocket::TcpListener(ref listener, ref quotes, ref mut pos) => {
                let status = tcp_shortsend_accept_loop(
                        listener,
                        server,
                        &"qotd",
                        &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixStreamListener(ref listener, ref quotes, ref mut pos) => {
                let status = unix_stream_shortsend_accept_loop(
                        listener,
                        server,
                        &"qotd",
                        &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            #[cfg(feature="seqpacket")]
            &mut QotdSocket::UnixSeqpacketListener(ref listener, ref quotes, ref mut pos) => {
                let status = unix_seqpacket_shortsend_accept_loop(
                    listener,
                    server,
                    &"qotd",
                    &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            &mut QotdSocket::Udp(ref socket, ref mut outstanding, ref quotes, ref mut pos) => {
                let status = udp_shortsend(
                        socket,
                        server,
                        "qotd",
                        readiness,
                        outstanding,
                        &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            #[cfg(feature="udplite")]
            &mut QotdSocket::UdpLite(ref socket, ref mut outstanding, ref quotes, ref mut pos) => {
                let status = udplite_shortsend(
                    socket,
                    server,
                    "qotd",
                    readiness,
                    outstanding,
                    &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            #[cfg(unix)]
            &mut QotdSocket::UnixDatagram(ref socket, ref mut boxed) => {
                let tuple: &mut(_, _, _) = &mut*boxed;
                let &mut(ref mut outstanding, ref quotes, ref mut pos) = tuple;
                let status = unix_datagram_shortsend(
                        socket,
                        "qotd",
                        readiness,
                        outstanding,
                        &quotes[*pos as usize]
                );
                *pos += 1;
                *pos %= quotes.len() as u32;
                status
            }
            #[cfg(feature="posixmq")]
            &mut QotdSocket::PosixMq(ref mq, ref quotes, ref mut pos) => {
                loop {
                    match mq.send(0, &quotes[*pos as usize]) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error sending to posix message queue /qotd: {}, removing it.", e);
                            break Remove;
                        }
                        Ok(()) => *pos = (*pos+1) % quotes.len() as u32
                    }
                }
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &QotdSocket::TcpListener(ref listener, _, _) => Some(listener),
            &QotdSocket::Udp(ref socket, _, _, _) => Some(socket),
            #[cfg(feature="udplite")]
            &QotdSocket::UdpLite(ref socket, _, _, _) => Some(socket),
            #[cfg(unix)]
            &QotdSocket::UnixStreamListener(ref listener, _, _) => Some(&**listener),
            #[cfg(unix)]
            &QotdSocket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(feature="seqpacket")]
            &QotdSocket::UnixSeqpacketListener(ref listener, _, _) => Some(&**listener),
            #[cfg(feature="posixmq")]
            &QotdSocket::PosixMq(ref mq, _, _) => Some(&**mq),
        }
    }
}


const TIME32_PORT: u16 = 37;

#[derive(Debug)]
pub enum Time32Socket {
    TcpListener(TcpListener),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Vec<UnixSocketAddr>),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>),
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
        #[cfg(feature="udplite")]
        listen_udplite(server, "time32", TIME32_PORT, Ready::readable() | Ready::writable(), Some(0),
            &mut|socket, Token(_)| {
                ServiceSocket::Time32(Time32Socket::UdpLite(socket, HashSet::new()))
            }
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("time32", server, &mut|listener, Token(_)| {
            ServiceSocket::Time32(Time32Socket::UnixStreamListener(listener))
        });
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("time32", Ready::all(), server,
            &mut|socket, Token(_)| {
                ServiceSocket::Time32(Time32Socket::UnixDatagram(socket, Vec::new()))
            }
        );
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("time32", server, &mut|listener, Token(_)| {
            ServiceSocket::Time32(Time32Socket::UnixSeqpacketListener(listener))
        });
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
            #[cfg(feature="seqpacket")]
            &mut Time32Socket::UnixSeqpacketListener(ref listener) => {
                unix_seqpacket_shortsend_accept_loop(listener, server, &"time32", &sometime)
            }
            &mut Time32Socket::Udp(ref socket, ref mut outstanding) => {
                udp_shortsend(socket, server, "time32", readiness, outstanding, &sometime)
            }
            #[cfg(feature="udplite")]
            &mut Time32Socket::UdpLite(ref socket, ref mut outstanding) => {
                udplite_shortsend(socket, server, "time32", readiness, outstanding, &sometime)
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
            #[cfg(feature="udplite")]
            &Time32Socket::UdpLite(ref socket, _) => Some(socket),
            #[cfg(unix)]
            &Time32Socket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &Time32Socket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(feature="seqpacket")]
            &Time32Socket::UnixSeqpacketListener(ref listener) => Some(&**listener),
        }
    }
}


const DAYTIME_PORT: u16 = 13;

#[derive(Debug)]
pub enum DaytimeSocket {
    TcpListener(TcpListener),
    Udp(UdpSocket, HashSet<SocketAddr>),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket, HashSet<SocketAddr>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Vec<UnixSocketAddr>),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>),
}

/// Cet the current time in some^* timezone.
///
/// The timezone is rounded to hours, and is based on a random number
/// and centered on the local timezone.
/// The distribution of the random number is Uniform(0..1)^2
/// which is apparently called a beta distribution with paramaters 𝛼=1/n and 1:
/// https://en.wikipedia.org/wiki/Uniform_distribution_(continuous)#Related_distributions
fn new_daytime() -> String {
    let now_utc: NaiveDateTime = Utc::now().naive_utc();
    let random_hour_offset: i32 = {
        let now_local: NaiveDateTime = chrono::Local::now().naive_local();
        // there is a race condition in here if the hour changes between
        // Utc::now() and Local::now(), but the offset is only used for
        // centering the distribution, so it won't be visible.
        let local_offset = (now_local.timestamp() - now_utc.timestamp()) as i32 / (60*60);
        let random01 = rand::random::<f32>();
        let random11 = (random01-0.5)*2.0;
        let uneven = random11 * random11.abs(); // FIXME namee of this distribution
        let hours = (uneven * 13.0/*exclusive*/) as i32;
        match hours + local_offset {
            fine @ -12..=12 => fine,
            west_overflow @ -36..=-13 => west_overflow+24,
            east_overflow @ 13..=36 => east_overflow-24,
            unexpected => {
                eprintln!("{} Created unexpected timezone offset {} from {}+{}",
                        now()/*ugh*/, unexpected, hours, local_offset
                );
                -11 // should be quite rare
            }
        }
    };
    let tz: FixedOffset = FixedOffset::east(random_hour_offset*60*60);
    let now_somewhere: DateTime<FixedOffset> = tz.from_utc_datetime(&now_utc);
    now_somewhere.format("%Y-%m-%d %H:%M:%S %Z\n").to_string()
}

impl DaytimeSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "daytime", DAYTIME_PORT,
            &mut|listener, Token(_)| ServiceSocket::Daytime(DaytimeSocket::TcpListener(listener))
        );
        listen_udp(server, "daytime", DAYTIME_PORT, Ready::readable() | Ready::writable(),
            &mut|socket, Token(_)| {
                ServiceSocket::Daytime(DaytimeSocket::Udp(socket, HashSet::new()))
            }
        );
        #[cfg(feature="udplite")]
        listen_udplite(server, "daytime", DAYTIME_PORT, Ready::readable() | Ready::writable(), Some(10),
            &mut|socket, Token(_)| {
                ServiceSocket::Daytime(DaytimeSocket::UdpLite(socket, HashSet::new()))
            }
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("daytime", server, &mut|listener, Token(_)| {
            ServiceSocket::Daytime(DaytimeSocket::UnixStreamListener(listener))
        });
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("daytime", Ready::all(), server,
            &mut|socket, Token(_)| {
                ServiceSocket::Daytime(DaytimeSocket::UnixDatagram(socket, Vec::new()))
            }
        );
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("daytime", server, &mut|listener, Token(_)| {
            ServiceSocket::Daytime(DaytimeSocket::UnixSeqpacketListener(listener))
        });
    }

    pub fn ready(&mut self,  readiness: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        let somewhere = new_daytime().into_bytes();
        match self {
            &mut DaytimeSocket::TcpListener(ref listener) => {
                tcp_shortsend_accept_loop(listener, server, &"daytime", &somewhere)
            }
            #[cfg(unix)]
            &mut DaytimeSocket::UnixStreamListener(ref listener) => {
                unix_stream_shortsend_accept_loop(listener, server, &"daytime", &somewhere)
            }
            #[cfg(feature="seqpacket")]
            &mut DaytimeSocket::UnixSeqpacketListener(ref listener) => {
                unix_seqpacket_shortsend_accept_loop(listener, server, &"daytime", &somewhere)
            }
            &mut DaytimeSocket::Udp(ref socket, ref mut outstanding) => {
                udp_shortsend(socket, server, "daytime", readiness, outstanding, &somewhere)
            }
            #[cfg(feature="udplite")]
            &mut DaytimeSocket::UdpLite(ref socket, ref mut outstanding) => {
                udplite_shortsend(socket, server, "daytime", readiness, outstanding, &somewhere)
            }
            #[cfg(unix)]
            &mut DaytimeSocket::UnixDatagram(ref socket, ref mut outstanding) => {
                unix_datagram_shortsend(socket, "daytime", readiness, outstanding, &somewhere)
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &DaytimeSocket::TcpListener(ref listener) => Some(listener),
            &DaytimeSocket::Udp(ref socket, _) => Some(socket),
            #[cfg(feature="udplite")]
            &DaytimeSocket::UdpLite(ref socket, _) => Some(socket),
            #[cfg(unix)]
            &DaytimeSocket::UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &DaytimeSocket::UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(feature="seqpacket")]
            &DaytimeSocket::UnixSeqpacketListener(ref listener) => Some(&**listener),
        }
    }
}
