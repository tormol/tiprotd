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

use std::net::{SocketAddr, IpAddr, Ipv4Addr, Shutdown};
use std::io::{ErrorKind, Read, Write, stdout};
use std::rc::Rc;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

extern crate mio;
use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::net::{TcpListener, TcpStream, UdpSocket};

extern crate slab;
use slab::Slab;

const ECHO_PORT: u16 = 7; // read and write
const DISCARD_PORT: u16 = 9; // only need to read
const QOTD_PORT: u16 = 17; // only need to write
const TIME32_PORT: u16 = 37; // only bother reading multiple times

const QOTD: &[u8] = b"No quote today, the DB has gone away\n";

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const NONRESERVED_PORT_OFFSET: u16 = 10_000;

/// Maximum duration for which stats that count toward various DoS-preventing
/// limits are remembered.
const LIMITS_DURATION: Duration = Duration::from_secs(10*60);
/// Hom many UDP bytes + packets can be sent to a client per `LIMITS_DURATION`
const UDP_SEND_LIMIT: u32 = 1*1024*1024;

#[derive(Clone)]
enum TcpStreamState {
    Echo{ unsent: VecDeque<u8> },
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
    },
    Udp {
        socket: UdpSocket,
        state: UdpState,
    },
    TcpStream {
        stream: TcpStream,
        state: TcpStreamState,
    },
}

fn end_stream(token: Token,  conns: &mut Slab<ConnState>,  poll: &Poll) {
    let stream = match conns.remove(token.0) {
        ConnState::TcpStream{stream, state: _} => stream,
        _ => unreachable!("Removed wrong type of token")
    };
    // TODO if length < 1/4 capacaity and above some minimum, recreate slab and reregister;
    // shrink_to_fit() doesn't do much: https://github.com/carllerche/slab/issues/38
    if let Err(e) = stream.shutdown(Shutdown::Both) {
        eprintln!("Error shutting down {:?}: {}", stream, e);
    }
    if let Err(e) = poll.deregister(&stream) {
        eprintln!("Error deregistering {:?}: {}", stream, e);
    }
}

fn listen_tcp(poll: &Poll,  conns: &mut Slab<ConnState>, on: SocketAddr,
              start_state: TcpStreamState,  poll_streams_for: Ready,
) {
    let listener = TcpListener::bind(&on).unwrap_or_else(|e| {
        eprintln!("Cannot listen to {}: {}", on, e);
        let fallback = SocketAddr::new(LOCALHOST, on.port()+NONRESERVED_PORT_OFFSET);
        eprintln!("Trying {} instead", fallback);
        TcpListener::bind(&fallback).expect("Cannot listen to this port either. Aborting")
    });
    let entry = conns.vacant_entry();
    poll.register(&listener, Token(entry.key()), Ready::readable(), PollOpt::edge())
        .expect("Cannot register listener");
    entry.insert(ConnState::TcpListener {
        listener: Rc::new(listener),
        start_state,
        poll_streams_for,
    });
}

fn listen_udp(poll: &Poll,  conns: &mut Slab<ConnState>, on: SocketAddr,
              state: UdpState,  poll_for: Ready,
) {
    let socket = UdpSocket::bind(&on).unwrap_or_else(|e| {
        eprintln!("Cannot bind to {}: {}", on, e);
        let fallback = SocketAddr::new(LOCALHOST, on.port()+NONRESERVED_PORT_OFFSET);
        eprintln!("Trying {} instead", fallback);
        UdpSocket::bind(&fallback).expect("Cannot bind to this port either. Aborting")
    });
    let entry = conns.vacant_entry();
    poll.register(&socket, Token(entry.key()), poll_for, PollOpt::edge())
        .expect("Cannot register listener");
    entry.insert(ConnState::Udp { socket, state });
}

// returns false if a WouldBlock error was returned, and logs errors
fn send_udp(from: &UdpSocket,  msg: &[u8],  to: &SocketAddr,  prot: &str) -> bool {
    match from.send_to(msg, to) {
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return false,
        Err(e) => eprintln!("Error sending {} UDP response to {}: {}", prot, to, e),
        Ok(len) if len != msg.len() => {
            eprintln!("Only sent {}/{} bytes of {} UDP response to {}",
                len, msg.len(), prot, to
            );
        },
        Ok(_) => {}
    }
    true
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
        1 => 0x7fffff00 | (now & 0xff), // can you handle it
        2 => now.wrapping_sub(60*60*24*365*100), // a blast from the past
        3 => now ^ 0xff, // going backwards
        _ => unreachable!()
    };
    [// as bytes in network order
        (sometime >> 24) as u8 & 0xff,
        (sometime >> 16) as u8 & 0xff,
        (sometime >>  8) as u8 & 0xff,
        sometime as u8
    ]
}

fn main() {
    let mut read_buf = [0u8; 4096];

    // Create a poll instance
    let poll = Poll::new().expect("Cannot create selector");
    let mut conns = Slab::with_capacity(512);

    listen_tcp(&poll, &mut conns,
        SocketAddr::new(ANY, ECHO_PORT),
        TcpStreamState::Echo{unsent: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );
    listen_tcp(&poll, &mut conns,
        SocketAddr::new(LOCALHOST, DISCARD_PORT),
        TcpStreamState::Discard,
        Ready::readable(),
    );
    listen_tcp(&poll, &mut conns,
        SocketAddr::new(ANY, QOTD_PORT),
        TcpStreamState::Qotd{sent: 0},
        Ready::writable(),
    );
    listen_tcp(&poll, &mut conns,
        SocketAddr::new(ANY, TIME32_PORT),
        TcpStreamState::Time32,
        Ready::writable(),
    ); // FIXME make this Oneshot (create a builder)

    listen_udp(&poll, &mut conns,
        SocketAddr::new(ANY, ECHO_PORT),
        UdpState::Echo{unsent: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );
    listen_udp(&poll, &mut conns,
        SocketAddr::new(ANY, DISCARD_PORT),
        UdpState::Discard,
        Ready::readable(),
    );
    listen_udp(&poll, &mut conns,
        SocketAddr::new(ANY, QOTD_PORT),
        UdpState::Qotd{outstanding: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );
    listen_udp(&poll, &mut conns,
        SocketAddr::new(ANY, TIME32_PORT),
        UdpState::Time32{outstanding: VecDeque::new()},
        Ready::readable() | Ready::writable(),
    );

    let mut limits = client_limiter::ClientLimiter::new(LIMITS_DURATION, UDP_SEND_LIMIT);

    let mut events = Events::with_capacity(1024);
    loop {
        poll.poll(&mut events, None).expect("Cannot poll selector");
        println!("connections: {}, events: {}", conns.len(), events.iter().count());
        for event in events.iter() {
            let token = event.token();
            println!("\t{:?}", event);
            if !conns.contains(token.0) {
                eprintln!("Unknown mio token: {}", token.0);
                continue;
            }
            match &mut conns[token.0] {
                &mut ConnState::TcpListener{ ref listener, ref start_state, poll_streams_for } => {
                    // clone to end borrow of conns so that we can insert streams
                    let listener = listener.clone();
                    let start_state = start_state.clone();
                    loop {
                        match listener.accept() {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) => eprintln!("Error accepting TCP connection: {}", e),
                            Ok((stream, _addr)) => {
                                let entry = conns.vacant_entry();
                                let res = poll.register(&stream,
                                    Token(entry.key()),
                                    poll_streams_for,
                                    PollOpt::edge(),
                                );
                                if let Err(e) = res {
                                    eprintln!("Cannot register TCP connection: {}", e);
                                } else {
                                    entry.insert(ConnState::TcpStream {
                                        stream,
                                        state: start_state.clone(),
                                    });
                                }
                            }
                        }
                    }
                }

                ConnState::TcpStream{ stream, state: TcpStreamState::Discard } => loop {
                    match stream.read(&mut read_buf) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => {
                            eprintln!("Error reading data to discard: {}, closing", e);
                            end_stream(token, &mut conns, &poll);
                            break;
                        }
                        Ok(0) => {
                            eprintln!("ending {:?}", stream);
                            end_stream(token, &mut conns, &poll);
                            break;
                        }
                        Ok(len) => {
                            println!("len: {}", len);
                            stdout().write(&read_buf[..len]).expect("Writing to stdout failed");
                        }
                    }
                }
                ConnState::TcpStream{ stream, state: TcpStreamState::Qotd{sent} } => loop {
                    match stream.write(&QOTD[*sent..]) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => {
                            eprintln!("Error sending qotd: {}, closing", e);
                            end_stream(token, &mut conns, &poll);
                            break;
                        }
                        Ok(0) => {
                            end_stream(token, &mut conns, &poll);
                            break;
                        }
                        Ok(len) => {
                            *sent += len;
                            if *sent >= QOTD.len() {
                                end_stream(token, &mut conns, &poll);
                                break;
                            }
                        }
                    }
                }
                ConnState::TcpStream{ stream, state: TcpStreamState::Echo{unsent} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match stream.read(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    eprintln!("Error reading data to echo: {}, hope the write errors too", e);
                                    break;
                                }
                                Ok(0) => break,
                                Ok(len) => {
                                    // TODO add max size, but must be done per IP
                                    unsent.extend(&read_buf[..len]);
                                    unsent.extend(&read_buf[..len]);
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
                            Err(e) => {
                                eprintln!("Error sending echo: {}, closing", e);
                                end_stream(token, &mut conns, &poll);
                                break;
                            }
                            Ok(0) => {
                                end_stream(token, &mut conns, &poll);
                                break;
                            }
                            Ok(len) => unsent.drain(..len).for_each(|_| {} ),
                        }
                    }
                }
                ConnState::TcpStream{ stream, state: TcpStreamState::Time32 } => {
                    let sometime = new_time32();
                    match stream.write(&sometime) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {},
                        Err(e) => {
                            eprintln!("Error sending time32: {}, closing", e);
                            end_stream(token, &mut conns, &poll);
                        }
                        Ok(len) => {
                            if len > 0  &&  len != 4 {
                                let remote = match stream.peer_addr() {
                                    Ok(addr) => addr.to_string(),
                                    Err(e) => format!("unknown IP (?: {})", e),
                                };
                                eprintln!("Only sent {} of 4 bytes to {} o_O", len, remote);
                            }
                            end_stream(token, &mut conns, &poll);
                        }
                    }
                }

                ConnState::Udp{ socket, state: UdpState::Echo{unsent} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match socket.recv_from(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => eprintln!("Error receiving UDP packet to echo: {}", e),
                                Ok((len, from)) => {
                                    if limits.allow_unacknowledged_send(from, 2*len) {
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
                        Ok((len, from)) => eprintln!("Received {} bytes to discard from {}", len, from),
                    }
                }
                ConnState::Udp{ socket, state: UdpState::Qotd{outstanding} } => {
                    if event.readiness().is_readable() {
                        loop {
                            match socket.recv_from(&mut read_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => eprintln!("Error receiving qotd UDP packet: {}", e),
                                Ok((_, from)) => {
                                    if limits.allow_unacknowledged_send(from, QOTD.len()) {
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
                                Ok((_, from)) => {
                                    if limits.allow_unacknowledged_send(from, 4) {
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
