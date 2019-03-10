/* tiprotd - A toy server implementing trivial network protocols with a twist
 * Copyright (C) 2019  Torbjørn Birch Moltu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod assigned_addr;
mod client_limiter;
use client_limiter::ClientLimiter;

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, Shutdown};
use std::io::{self, ErrorKind, Read, Write, stdout};
use std::error::Error;
use std::rc::Rc;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

extern crate mio;
use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::net::{TcpListener, TcpStream, UdpSocket};

extern crate slab;
use slab::Slab;

extern crate chrono;
use chrono::Local;

const ECHO_PORT: u16 = 7; // read and write
const DISCARD_PORT: u16 = 9; // only need to read
const QOTD_PORT: u16 = 17; // only need to write
const TIME32_PORT: u16 = 37; // only bother reading multiple times

const QOTD: &[u8] = b"No quote today, the DB has gone away\n";

const ANY: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
const NONRESERVED_PORT_OFFSET: u16 = 10_000;

/// Maximum duration for which stats that count toward various DoS-preventing
/// limits are remembered.
const LIMITS_DURATION: Duration = Duration::from_secs(10*60);
/// Hom many UDP bytes + packets can be sent to a client per `LIMITS_DURATION`
const UDP_SEND_LIMIT: u32 = 1*1024*1024;
/// How many resources a client is allowwed to consume at any point
const RESOURCE_LIMIT: u32 = 500*1024;
/// How many bytes an open connection should count as.
/// This should include buffers and structs used by the OS as well as structs
/// and fixed tiny buffers used by this program.
const CONNECTION_COST: usize = 2000; // guess

#[derive(Clone)]
enum TcpStreamState {
    Echo{ unsent: VecDeque<u8>, recv_shutdown: bool },
    Discard,
    Qotd{ sent: usize },
    Time32, // assume it can be sent in one go, figure out response at send time
}

enum UdpState {
    Echo{ unsent: VecDeque<(SocketAddr,Rc<[u8]>)> }, // completely unordered
    Discard,
    Qotd{ outstanding: VecDeque<SocketAddr> },
    Time32{ outstanding: VecDeque<SocketAddr> },
}

enum ConnState {
    TcpListener {
        listener: Rc<TcpListener>,
        start_state: TcpStreamState,
        poll_streams_for: Ready,
        name: &'static str,
    },
    Udp {
        socket: UdpSocket,
        state: UdpState,
    },
    TcpStream {
        stream: TcpStream,
        /// peer / remote / client address.
        /// Need this for ClientLimiter because stream.peer_addr() can fail
        /// after IO errors.
        addr: SocketAddr,
        state: TcpStreamState,
    },
}

struct Server {
    poll: Poll,
    conns: Slab<ConnState>,
    limits: ClientLimiter,
    port_offset: Option<u16>,
}
impl Server {
    fn new() -> Self {
        Server {
            poll: Poll::new().expect("Cannot create selector"),
            conns: Slab::with_capacity(512),
            limits: ClientLimiter::new(LIMITS_DURATION, UDP_SEND_LIMIT, RESOURCE_LIMIT),
            port_offset: None,
        }
    }

    fn end_stream(&mut self,  token: Token,  and_release: usize,
            cause: io::Result<usize>,  err_op: &str,
    ) {
        let (stream, addr) = match self.conns.remove(token.0) {
            ConnState::TcpStream{stream, addr, ..} => (stream, addr),
            _ => panic!("Removed wrong type of token")
        };
        self.limits.release_resources(addr, CONNECTION_COST+and_release);
        if let Err(e) = cause {
            eprintln!("tcp://{} error {}: {}, closing", addr, err_op, e.description());
        } else if let Err(e) = stream.shutdown(Shutdown::Both) {
            eprintln!("tcp://{} error shutting down socket: {}", addr, e);
        }
        // TODO if length < 1/4 capacaity and above some minimum, recreate slab and reregister;
        // shrink_to_fit() doesn't do much: https://github.com/carllerche/slab/issues/38
        if let Err(e) = self.poll.deregister(&stream) {
            eprintln!("tcp://{} error deregistering stream: {}", addr, e);
        }
        eprintln!("{} tcp://{} connection closed", now(), addr);
    }

    fn try_bind<S: mio::Evented>(&mut self,  port: u16,  protocol_name: &str,
            poll_for: Ready,  binder: fn(SocketAddr)->io::Result<S>,
    ) -> Option<(S, slab::VacantEntry<ConnState>)> {
        let on = SocketAddr::from((ANY, port+self.port_offset.unwrap_or(0)));
        match binder(on) {
            Ok(socket) => {
                let entry = self.conns.vacant_entry();
                self.poll.register(&socket, Token(entry.key()), poll_for, PollOpt::edge())
                    .expect("Cannot register listener");
                Some((socket, entry))
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied && self.port_offset == None => {
                eprintln!("Lacks permission to listen on reserved ports, falling back to 10_000+port");
                self.port_offset = Some(NONRESERVED_PORT_OFFSET);
                self.try_bind(port, protocol_name, poll_for, binder)
            }
            Err(e) => {
                eprintln!("Cannot listen on {}://{}: {}", protocol_name, on, e.description());
                None
            }
        }
    }

    fn listen_tcp(&mut self,  port: u16,  name: &'static str,
            start_state: TcpStreamState,  poll_streams_for: Ready,
    ) {
        let (listener, entry) = self.try_bind(port, "tcp", Ready::readable(),
            |addr| TcpListener::bind(&addr)
        ).unwrap_or_else(|| std::process::exit(1) );
        entry.insert(ConnState::TcpListener {
            listener: Rc::new(listener),
            start_state,
            poll_streams_for,
            name,
        });
    }

    fn listen_udp(&mut self,  port: u16,  state: UdpState,  poll_for: Ready) {
        let (socket, entry) = self.try_bind(port, "udp", poll_for,
            |addr| UdpSocket::bind(&addr)
        ).unwrap_or_else(|| std::process::exit(1) );
        entry.insert(ConnState::Udp { socket, state });
    }
}

// returns false if a WouldBlock error was returned, and logs errors
fn send_udp(from: &UdpSocket,  msg: &[u8],  to: &SocketAddr,  prot: &str) -> bool {
    match from.send_to(msg, to) {
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return false,
        Err(e) => {
            eprintln!("udp://{} error sending {} response: {}",
                native_addr(*to), prot, e.description()
            );
        }
        Ok(len) if len != msg.len() => {
            eprintln!("udp://{} could only send {}/{} bytes of {} response",
                native_addr(*to), len, msg.len(), prot
            );
        },
        Ok(_) => {}
    }
    true
}

fn do_tcp_echo(server: &mut Server,  read_buf: &mut[u8],  token: Token,  readiness: Ready) {
    let (stream, addr, unsent, recv_shutdown) = match &mut server.conns[token.0] {
        ConnState::TcpStream{ stream, addr, state: TcpStreamState::Echo{ unsent, recv_shutdown } } => {
            (stream, *addr, unsent, recv_shutdown)
        },
        _ => panic!("connection is not a TCP echo stream"),
    };
    if !*recv_shutdown && readiness.is_readable() {
        loop {
            match stream.read(read_buf) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) if len > 0 => {
                    if server.limits.request_resources(addr, 2*len) {
                        unsent.extend(&read_buf[..len]);
                        unsent.extend(&read_buf[..len]);
                    }
                }
                Ok(0) => {
                    *recv_shutdown = true;
                    break;
                }
                end => {
                    let discard = unsent.len();
                    server.end_stream(token, discard, end, "reading bytes to echo");
                    return;
                }
            }
        }
    }
    // if the socket is write ready but we don't have anything to write,
    // we cannot drain the readiness, so always try to write when we get some
    // if there is data to write, we need to try writing it even if no more
    // data is received
    while !unsent.is_empty() {
        match stream.write(unsent.as_slices().0) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(len @ 1..=std::usize::MAX) => {
                server.limits.release_resources(addr, len);
                unsent.drain(..len).for_each(|_| {} );
            }
            end => {
                let discard = unsent.len(); // make borrowck happy
                server.end_stream(token, discard, end, "sending echo");
                return;
            }
        }
    }
    if *recv_shutdown && unsent.is_empty() {
        server.end_stream(token, 0, Ok(0), "finishing echo");
    }
}

fn anti_discard(from: SocketAddr,  protocol: &str,  bytes: &[u8]) {
    print!("{} {}://{} discards {} bytes: ", now(), protocol, from, bytes.len());
    stdout().write(bytes).expect("Writing to stdout failed");
    if bytes.last().cloned() != Some(b'\n') {
        println!();
    }
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

/// Converts ::ffff:0.0.0.0/96 and ::0.0.0.0/96 ( except ::1 and ::) to IPv4 socket addresses.
///
/// When listening on :: IPv4 clienst are represented as IPv4-mapped addresses
/// (::ffff:0.0.0.0). These are less readable when printed, and might not be
/// detected as eg. multicast or loopback.
///
/// Using std's Ipv6Addr.to_ipv4() directly would convert some actual IPv6
/// addresses such as ::1 and :: because it also converts ::0.0.0.0/96
/// (IPv4-compatible addresses).
fn native_addr(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4() {
            if v4 > Ipv4Addr::new(0, 0, 0, 255) && v6.scope_id() == 0 && v6.flowinfo() == 0 {
                return SocketAddr::from((v4, v6.port()));
            }
        }
    }
    addr
}

fn now() -> impl Display {
    Local::now().format("%Y-%m-%d %H:%M:%S")
}

fn main() {
    let mut server = Server::new();

    server.listen_tcp(ECHO_PORT, "echo",
        TcpStreamState::Echo{unsent: VecDeque::new(), recv_shutdown: false},
        Ready::readable() | Ready::writable(),
    );
    server.listen_tcp(DISCARD_PORT, "discard",
        TcpStreamState::Discard,
        Ready::readable(),
    );
    server.listen_tcp(QOTD_PORT, "QOTD",
        TcpStreamState::Qotd{sent: 0},
        Ready::writable(),
    );
    server.listen_tcp(TIME32_PORT, "time32",
        TcpStreamState::Time32,
        Ready::writable(),
    ); // FIXME make this Oneshot (create a builder)

    server.listen_udp(ECHO_PORT,
        UdpState::Echo{unsent: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );
    server.listen_udp(DISCARD_PORT,
        UdpState::Discard,
        Ready::readable(),
    );
    server.listen_udp(QOTD_PORT,
        UdpState::Qotd{outstanding: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );
    server.listen_udp(TIME32_PORT,
        UdpState::Time32{outstanding: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );

    let mut read_buf = [0u8; 4096];
    let mut events = Events::with_capacity(1024);
    loop {
        server.poll.poll(&mut events, None).expect("Cannot poll selector");
        //println!("connections: {}, events: {}", server.conns.len(), events.iter().count());
        for event in events.iter() {
            let token = event.token();
            //println!("\t{:?}", event);
            if !server.conns.contains(token.0) {
                eprintln!("Unknown mio token: {}", token.0);
                continue;
            }
            match &mut server.conns[token.0] {
                &mut ConnState::TcpListener{ ref listener, ref start_state, poll_streams_for, name } => {
                    // clone to end borrow of conns so that we can insert streams
                    let listener = listener.clone();
                    let start_state = start_state.clone();
                    loop {
                        match listener.accept() {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) => eprintln!("Error accepting TCP connection: {}", e),
                            Ok((stream, addr)) => {
                                if !server.limits.request_resources(addr, CONNECTION_COST) {
                                    // once the connection is ready to accept(),
                                    // the work to establish the connection has
                                    // already been performed by the OS. The
                                    // best we can do is to immediately close
                                    // it, to not let it consume more resources.
                                    continue;
                                }
                                let entry = server.conns.vacant_entry();
                                let res = server.poll.register(&stream,
                                    Token(entry.key()),
                                    poll_streams_for,
                                    PollOpt::edge(),
                                );
                                if let Err(e) = res {
                                    eprintln!("Cannot register TCP connection: {}", e);
                                } else {
                                    let addr = native_addr(addr);
                                    eprintln!("{} tcp://{} {} connection established",
                                        now(), addr, name
                                    );
                                    entry.insert(ConnState::TcpStream {
                                        stream,
                                        addr,
                                        state: start_state.clone(),
                                    });
                                }
                            }
                        }
                    }
                }

                &mut ConnState::TcpStream{ ref mut stream, addr, state: TcpStreamState::Discard } => loop {
                    match stream.read(&mut read_buf) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Ok(len) if len > 0 => anti_discard(addr, "tcp", &read_buf[..len]),
                        end => {
                            server.end_stream(token, 0, end, "reading bytes to discard");
                            break;
                        }
                    }
                }
                ConnState::TcpStream{ stream, state: TcpStreamState::Qotd{sent}, .. } => loop {
                    match stream.write(&QOTD[*sent..]) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Ok(len) if len > 0 && *sent+len < QOTD.len() => {
                            *sent += len;
                        }
                        closing => {
                            server.end_stream(token, 0, closing, "sending qotd");
                            break;
                        }
                    }
                }
                ConnState::TcpStream{ state: TcpStreamState::Echo{..}, .. } => {
                    do_tcp_echo(&mut server, &mut read_buf, token, event.readiness());
                }
                ConnState::TcpStream{ stream, addr, state: TcpStreamState::Time32 } => {
                    let sometime = new_time32();
                    match stream.write(&sometime) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {},
                        progress => {
                            if let Ok(len @ 1..=3) = progress {
                                eprintln!("Only sent {} of 4 bytes to {} o_O", len, addr);
                            }
                            server.end_stream(token, 0, progress, "sending time32");
                        }
                    }
                }

                // don't count UDP data toward resource limits, as sending
                // is only limited by the OS's socket buffer, and not by the
                // client or network. A client should not be able to cause an
                // issue here before hitting its UDP send limit.
                ConnState::Udp{ socket, state: UdpState::Echo{unsent} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match socket.recv_from(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => eprintln!("Error receiving UDP packet to echo: {}", e),
                                Ok((len, from)) => {
                                    if server.limits.allow_unacknowledged_send(from, 2*len) {
                                        eprintln!("{} udp://{} sends {} bytes to echo",
                                            now(), native_addr(from), len
                                        );
                                        let msg = Rc::<[u8]>::from(&read_buf[..len]);
                                        unsent.push_back((from, msg.clone()));
                                        unsent.push_back((from, msg));
                                    }
                                }
                            }
                        }
                    }
                    while let Some((addr,msg)) = unsent.front() {
                        if send_udp(socket, msg, addr, "echo") {
                            let _ = unsent.pop_front();
                        } else {
                            break;
                        }
                    }
                }
                ConnState::Udp{ socket, state: UdpState::Discard } => loop {
                    match socket.recv_from(&mut read_buf) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => eprintln!("Error receiving UDP packet to discard: {}", e),
                        Ok((len, from)) => {
                            let addr = native_addr(from);
                            // TODO rate limit this to prevent filling up the disk
                            eprintln!("{} udp://{} sends {} bytes to discard",
                                now(), addr, len
                            );
                            anti_discard(addr, "udp", &read_buf[..len]);
                        }
                    }
                }
                ConnState::Udp{ socket, state: UdpState::Qotd{outstanding} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match socket.recv_from(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => eprintln!("Error receiving QOTD UDP packet: {}", e),
                                Ok((len, from)) => {
                                    if server.limits.allow_unacknowledged_send(from, QOTD.len()) {
                                        eprintln!("{} udp://{} sends {} bytes for QOTD",
                                            now(), native_addr(from), len
                                        );
                                        outstanding.push_back(from);
                                    }
                                }
                            }
                        }
                    }
                    while let Some(addr) = outstanding.front() {
                        if send_udp(socket, QOTD, addr, "qotd") {
                            let _ = outstanding.pop_front();
                        } else {
                            break;
                        }
                    }
                }
                ConnState::Udp{ socket, state: UdpState::Time32{outstanding} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match socket.recv_from(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => eprintln!("Error receiving time (32bit) UDP packet: {}", e),
                                Ok((len, from)) => {
                                    if server.limits.allow_unacknowledged_send(from, 4) {
                                        eprintln!("{} udp://{} sends {} bytes for time32",
                                            now(), native_addr(from), len
                                        );
                                        outstanding.push_back(from);
                                    }
                                }
                            }
                        }
                    }
                    let sometime = new_time32();
                    while let Some(addr) = outstanding.front() {
                        if send_udp(socket, &sometime, addr, "time32") {
                            let _ = outstanding.pop_front();
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }
}
