/* tiprotd - A toy server implementing trivial network protocols with a twist
 * Copyright (C) 2019, 2021 Torbjørn Birch Moltu
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
extern crate rand;
extern crate slab;
extern crate mio;
#[cfg(feature="sctp")]
extern crate sctp as sctp_crate;
#[cfg(feature="udplite")]
extern crate udplite;
#[cfg(unix)]
extern crate uds;
#[cfg(feature="posixmq")]
extern crate posixmq;
#[cfg(unix)]
extern crate nix;
#[cfg(unix)]
extern crate libc;

mod assigned_addr;
mod client_limiter;
use client_limiter::ClientLimiter;
#[cfg(feature="sctp")]
mod sctp;
mod helpers;
use helpers::*;
mod discard;
mod echo;
mod chargen;
mod shortsend;
mod signal;

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::mem;
use std::time::Duration;

use mio::{Poll, Events, Interest, Token};
use mio::event::{Source, Event};
use slab::Slab;


const ANY: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
const NONRESERVED_PORT_OFFSET: u16 = 10_000;

/// Maximum duration for which stats that count toward various DoS-preventing
/// limits are remembered.
const LIMITS_DURATION: Duration = Duration::from_secs(10*60);
/// Hom many UDP bytes + packets can be sent to a client per `LIMITS_DURATION`
const UDP_SEND_LIMIT: u32 = 1*1024*1024;
/// How many resources a client is allowwed to consume at any point, in bytes.
/// 256 kB is much higher than any honest client will need,
/// but high enough to exceed the capacity of client's default receive buffer,
/// which simplifies testing. It is still low enough to prevent somebody with a
/// /24 block from DoSing.
const RESOURCE_LIMIT: u32 = 256*1024;

#[derive(Debug)]
pub enum ServiceSocket {
    #[cfg(unix)]
    SignalReceiver(signal::SignalReceiver),
    Discard(discard::DiscardSocket),
    Echo(echo::EchoSocket),
    CharGen(chargen::CharGenSocket),
    Qotd(shortsend::QotdSocket),
    Time32(shortsend::Time32Socket),
    Daytime(shortsend::DaytimeSocket),
    Sysstat(shortsend::SysstatSocket),
    CurrentlyMoved
}
impl ServiceSocket {
    fn setup(server: &mut Server) {
        discard::DiscardSocket::setup(server);
        echo::EchoSocket::setup(server);
        chargen::CharGenSocket::setup(server);
        shortsend::QotdSocket::setup(server);
        shortsend::Time32Socket::setup(server);
        shortsend::DaytimeSocket::setup(server);
        shortsend::SysstatSocket::setup(server);
        #[cfg(unix)]
        signal::SignalReceiver::setup(server);
    }
    fn ready(&mut self,  event: &Event,  server: &mut Server)
    -> helpers::EntryStatus {
        match self {
            ServiceSocket::Discard(discard) => discard.ready(event, server),
            ServiceSocket::Echo(echo) => echo.ready(event, server),
            ServiceSocket::CharGen(chargen) => chargen.ready(event, server),
            ServiceSocket::Qotd(qotd) => qotd.ready(event, server),
            ServiceSocket::Time32(time32) => time32.ready(event, server),
            ServiceSocket::Daytime(daytime) => daytime.ready(event, server),
            ServiceSocket::Sysstat(sysstat) => sysstat.ready(event, server),
            #[cfg(unix)]
            ServiceSocket::SignalReceiver(sr) => sr.ready(event, server),
            ServiceSocket::CurrentlyMoved => {
                unreachable!(
                    "CurrentlyMoved at {} not replaced or removed",
                    event.token().0,
                )
            }
        }
    }
    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            ServiceSocket::Discard(discard) => discard.inner_descriptor(),
            ServiceSocket::Echo(echo) => echo.inner_descriptor(),
            ServiceSocket::CharGen(chargen) => chargen.inner_descriptor(),
            ServiceSocket::Qotd(qotd) => qotd.inner_descriptor(),
            ServiceSocket::Time32(time32) => time32.inner_descriptor(),
            ServiceSocket::Daytime(daytime) => daytime.inner_descriptor(),
            ServiceSocket::Sysstat(sysstat) => sysstat.inner_descriptor(),
            #[cfg(unix)]
            ServiceSocket::SignalReceiver(sr) => sr.inner_descriptor(),
            ServiceSocket::CurrentlyMoved => None
        }
    }
}

pub struct Server {
    poll: Poll,
    sockets: Slab<ServiceSocket>,
    limits: ClientLimiter,
    buffer: [u8; 4096],
    internally_shutdown: u32,
    port_offset: Option<u16>,
    #[cfg(unix)]
    path_base: &'static str,
    failed_protocols: Vec<Protocol>, // few elements, limited number of lookups
}
impl Server {
    fn new() -> Self {
        Server {
            poll: Poll::new().expect("Cannot create selector"),
            sockets: Slab::with_capacity(64),
            limits: ClientLimiter::new(LIMITS_DURATION, UDP_SEND_LIMIT, RESOURCE_LIMIT),
            buffer: [0; 4096],
            internally_shutdown: 0,
            port_offset: None,
            #[cfg(unix)]
            path_base: "/var/run/",
            failed_protocols: Vec::new(),
        }
    }

    fn try_bind_ip<S: Source>(&mut self,
            protocol_name: &str,  service_name: &str,  port: u16,
            interest: Interest,  binder: fn(SocketAddr)->io::Result<S>,
    ) -> Option<(S, slab::VacantEntry<ServiceSocket>)> {
        let on = SocketAddr::from((ANY, port+self.port_offset.unwrap_or(0)));
        match binder(on) {
            Ok(mut socket) => {
                let entry = self.sockets.vacant_entry();
                self.poll.registry().register(&mut socket, Token(entry.key()), interest)
                    .expect(&format!("Cannot register {} listener", protocol_name));
                Some((socket, entry))
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied && self.port_offset == None => {
                eprintln!("Doesn't have permission to listen on reserved ports, falling back to 10_000+port");
                self.port_offset = Some(NONRESERVED_PORT_OFFSET);
                self.try_bind_ip(protocol_name, service_name, port, interest, binder)
            }
            Err(e) => {
                eprintln!("Cannot listen on {}://{} (for {}): {}",
                    protocol_name, on, service_name, e
                );
                None
            }
        }
    }

    fn trigger(&mut self,  event: &Event,  mut socket: ServiceSocket) {
        let Token(index) = event.token();
        match socket.ready(event, self) {
            Drained => {
                match mem::replace(&mut self.sockets[index], socket) {
                    ServiceSocket::CurrentlyMoved => {},
                    _ => eprintln!("Replaced non-moved socket entry at {}!", index),
                }
            }
            Remove => {
                match self.sockets.remove(index) {
                    ServiceSocket::CurrentlyMoved => {},
                    _ => eprintln!("Removed non-moved socket entry at {}!", index),
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
    while server.sockets.len() > server.internally_shutdown as usize {
        server.poll.poll(&mut events, None).expect("Cannot poll selector");
        //println!("connections: {}, events: {}", server.sockets.len(), events.iter().count());
        for event in events.iter() {
            let entry = match server.sockets.get_mut(event.token().0) {
                Some(entry) => mem::replace(entry, ServiceSocket::CurrentlyMoved),
                None => {
                    // can happen if multiple events for the same token and
                    // handling the first one causes the entry to be removed
                    eprintln!("Unknown mio token: {}", event.token().0);
                    continue;
                }
            };
            server.trigger(event, entry);
        }
        if server.sockets.capacity() > 20
        && server.sockets.capacity() / 8 > server.sockets.len() {
            // TODO compactreregister
            server.sockets.shrink_to_fit();
        }
        // println!("entries: {}", server.sockets.len());
    }
}
