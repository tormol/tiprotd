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

extern crate chrono;
extern crate slab;
extern crate mio;
#[cfg(unix)]
extern crate mio_uds;
#[cfg(any(target_os="linux", target_os="freebsd", target_os="dragonfly", target_os="netbsd"))]
extern crate posixmq;

mod assigned_addr;
mod client_limiter;
use client_limiter::ClientLimiter;
mod helpers;
use helpers::*;
mod discard;
mod echo;
mod shortsend;

use std::error::Error;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::mem;
use std::time::Duration;

use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::net::{TcpListener, UdpSocket};
use mio_uds::{UnixListener, UnixStream, UnixDatagram};
use slab::Slab;


const ANY: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
const NONRESERVED_PORT_OFFSET: u16 = 10_000;

/// Maximum duration for which stats that count toward various DoS-preventing
/// limits are remembered.
const LIMITS_DURATION: Duration = Duration::from_secs(10*60);
/// Hom many UDP bytes + packets can be sent to a client per `LIMITS_DURATION`
const UDP_SEND_LIMIT: u32 = 1*1024*1024;
/// How many resources a client is allowwed to consume at any point
const RESOURCE_LIMIT: u32 = 500*1024;

pub enum ServiceSocket {
    Discard(discard::DiscardSocket),
    Echo(echo::EchoSocket),
    Qotd(shortsend::QotdSocket),
    Time32(shortsend::Time32Socket),
    CurrentlyMoved
}
impl ServiceSocket {
    fn setup(server: &mut Server) {
        discard::DiscardSocket::setup(server);
        echo::EchoSocket::setup(server);
        shortsend::QotdSocket::setup(server);
        shortsend::Time32Socket::setup(server);
    }
    fn ready(&mut self,  readiness: Ready,  this_token: Token,  server: &mut Server)
    -> helpers::EntryStatus {
        match self {
            ServiceSocket::Discard(discard) => discard.ready(readiness, this_token, server),
            ServiceSocket::Echo(echo) => echo.ready(readiness, this_token, server),
            ServiceSocket::Qotd(qotd) => qotd.ready(readiness, this_token, server),
            ServiceSocket::Time32(time32) => time32.ready(readiness, this_token, server),
            ServiceSocket::CurrentlyMoved => {
                unreachable!("CurrentlyMoved at {} not replaced or removed", this_token.0)
            }
        }
    }
}


pub struct Server {
    poll: Poll,
    sockets: Slab<ServiceSocket>,
    limits: ClientLimiter,
    buffer: [u8; 4096],
    port_offset: Option<u16>,
    #[cfg(unix)]
    path_base: &'static str,
}
impl Server {
    fn new() -> Self {
        Server {
            poll: Poll::new().expect("Cannot create selector"),
            sockets: Slab::with_capacity(64),
            limits: ClientLimiter::new(LIMITS_DURATION, UDP_SEND_LIMIT, RESOURCE_LIMIT),
            buffer: [0; 4096],
            port_offset: None,
            #[cfg(unix)]
            path_base: "/var/run/",
        }
    }

    fn try_bind_ip<S: mio::Evented>(&mut self,  port: u16,
            service_name: &str,  protocol_name: &str,
            poll_for: Ready,  binder: fn(SocketAddr)->io::Result<S>,
    ) -> Option<(S, slab::VacantEntry<ServiceSocket>)> {
        let on = SocketAddr::from((ANY, port+self.port_offset.unwrap_or(0)));
        match binder(on) {
            Ok(socket) => {
                let entry = self.sockets.vacant_entry();
                self.poll.register(&socket, Token(entry.key()), poll_for, PollOpt::edge())
                    .expect(&format!("Cannot register {} listener", protocol_name));
                Some((socket, entry))
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied && self.port_offset == None => {
                eprintln!("Doesn't have permission to listen on reserved ports, falling back to 10_000+port");
                self.port_offset = Some(NONRESERVED_PORT_OFFSET);
                self.try_bind_ip(port, protocol_name, service_name, poll_for, binder)
            }
            Err(e) => {
                eprintln!("Cannot listen on {}://{}:{} (for {}): {}",
                    protocol_name, on, port, service_name, e.description()
                );
                None
            }
        }
    }

    #[cfg(unix)]
    fn try_bind_unix<S: mio::Evented>(&mut self,
            service_name: &str,  protocol_name: &str,
            poll_for: Ready,  binder: fn(&str)->io::Result<S>,
    ) -> Option<(S, slab::VacantEntry<ServiceSocket>)> {
        let on = format!("{}{}.{}_socket", self.path_base, service_name, protocol_name);
        match binder(&on) {
            Ok(socket) => {
                let entry = self.sockets.vacant_entry();
                self.poll.register(&socket, Token(entry.key()), poll_for, PollOpt::edge())
                    .expect(&format!("Cannot register {} listener", protocol_name));
                Some((socket, entry))
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied
            && self.path_base.starts_with("/") => {
                eprintln!("Doesn't have permission to create socket in {}, trying current directory instead",
                    self.path_base
                );
                self.path_base = "";
                self.try_bind_unix(service_name, protocol_name, poll_for, binder)
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
                                self.try_bind_unix(service_name, protocol_name, poll_for, binder)
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

    fn listen_tcp(&mut self,  port: u16,  service_name: &'static str,
            encapsulate: &mut dyn FnMut(TcpListener, Token)->ServiceSocket
    ) {
        let res = self.try_bind_ip(port, service_name, "tcp", Ready::readable(),
            |addr| TcpListener::bind(&addr)
        );
        if let Some((listener, entry)) = res {
            let token = Token(entry.key()); // make borrowck happy
            entry.insert(encapsulate(listener, token));
        } else {
            std::process::exit(1);
        }
    }

    fn listen_udp(&mut self,  port: u16,  poll_for: Ready,  service_name: &'static str,
            encapsulate: &mut dyn FnMut(UdpSocket, Token)->ServiceSocket
    ) {
        let (socket, entry) = self.try_bind_ip(port, service_name, "udp", poll_for,
            |addr| UdpSocket::bind(&addr)
        ).unwrap_or_else(|| std::process::exit(1) );
        let token = Token(entry.key()); // make borrowck happy
        entry.insert(encapsulate(socket, token));
    }

    #[cfg(unix)]
    fn listen_unix_stream(&mut self,  service_name: &'static str,
            encapsulate: &mut dyn FnMut(UnixListener, Token)->ServiceSocket
    ) {
        let res = self.try_bind_unix(service_name, "stream", Ready::readable(),
            |path| UnixListener::bind(path)
        );
        if let Some((listener, entry)) = res {
            let token = Token(entry.key()); // make borrowck happy
            entry.insert(encapsulate(listener, token));
        } else {
            std::process::exit(1);
        }
    }

    #[cfg(unix)]
    fn listen_unix_datagram(&mut self,  poll_for: Ready,  service_name: &'static str,
            encapsulate: &mut dyn FnMut(UnixDatagram, Token)->ServiceSocket
    ) {
        let res = self.try_bind_unix(service_name, "dgram", poll_for,
            |path| UnixDatagram::bind(path)
        );
        if let Some((socket, entry)) = res {
            let token = Token(entry.key()); // make borrowck happy
            entry.insert(encapsulate(socket, token));
        } else {
            std::process::exit(1);
        }
    }

    fn trigger(&mut self,  readiness: Ready,  mut socket: ServiceSocket,  token: Token) {
        match socket.ready(readiness, token, self) {
            Drained => {
                match mem::replace(&mut self.sockets[token.0], socket) {
                    ServiceSocket::CurrentlyMoved => {},
                    _ => eprintln!("Replaced non-moved socket entry at {}!", token.0),
                }
            }
            Remove => {
                match self.sockets.remove(token.0) {
                    ServiceSocket::CurrentlyMoved => {},
                    _ => eprintln!("Removed non-moved socket entry at {}!", token.0),
                }
            }
            Unfinished => unimplemented!()
        }
    }
}

fn main() {
    let mut server = Server::new();
    ServiceSocket::setup(&mut server);

    let mut events = Events::with_capacity(1024);
    while server.sockets.len() > 0 {
        server.poll.poll(&mut events, None).expect("Cannot poll selector");
        //println!("connections: {}, events: {}", server.sockets.len(), events.iter().count());
        for event in events.iter() {
            let entry = match server.sockets.get_mut(event.token().0) {
                Some(entry) => mem::replace(entry, ServiceSocket::CurrentlyMoved),
                None => {
                    eprintln!("Unknown mio token: {}", event.token().0);
                    continue;
                }
            };
            server.trigger(event.readiness(), entry, event.token());
        }
        if server.sockets.capacity() > 20
        && server.sockets.capacity() / 8 > server.sockets.len() {
            // TODO compactreregister
            server.sockets.shrink_to_fit();
        }
    }
}
