use std::net::{SocketAddr, IpAddr, Ipv4Addr, Shutdown};
use std::io::{ErrorKind, Read, Write, stdout};
use std::{usize,u16};

extern crate mio;
use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::net::{TcpListener, TcpStream};

extern crate slab;
use slab::Slab;

const DISCARD_PORT: u16 = 9; // only need to read
const QOTD_PORT: u16 = 17; // only need to write
const DISCARD_TCP: Token = Token(0);
const QOTD: &[u8] = b"No quote today, the DB has gone away\n";
const QOTD_TCP: Token = Token(1);

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const NONRESERVED_OFFSET: u16 = 10_000;

#[derive(Clone,Copy)]
enum TcpConnection {
    Discard,
    Qotd{sent: usize},
}

struct Streams {
    min_token: Token,
    streams: Slab<(TcpStream,TcpConnection)>,
}
impl Streams {
    fn new(min_token: Token) -> Self {
        Streams { min_token: min_token,  streams: Slab::with_capacity(1024) }
    }
    fn add(&mut self,  source: &TcpListener,  typ: TcpConnection,  look_for: Ready, poll: &Poll) {
        loop {
            match source.accept() {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => eprintln!("Error accepting echo TCP connection: {}", e),
                Ok((stream, _addr)) => {
                    let key = self.streams.insert((stream, typ));
                    let token = Token(key+self.min_token.0);
                    let stream = &self.streams[key].0;
                    if let Err(e) = poll.register(stream, token, look_for, PollOpt::edge()) {
                        eprintln!("Cannot register TCP connection: {}", e);
                        self.streams.remove(key);
                    }
                }
            }
        }
    }
    fn get_mut(&mut self,  token: Token) -> Option<&mut(TcpStream,TcpConnection)> {
        self.streams.get_mut(token.0-self.min_token.0)
    }
    fn remove(&mut self,  token: Token,  poll: &Poll) {
        let (stream, _) = self.streams.remove(token.0-self.min_token.0);
        // TODO if length < 1/4 capacaity and above some minimum, recreate slab and reregister;
        // shrink_to_fit() doesn't do much: https://github.com/carllerche/slab/issues/38
        if let Err(e) = stream.shutdown(Shutdown::Both) {
            eprintln!("Error shutting down {:?}: {}", stream, e);
        }
        if let Err(e) = poll.deregister(&stream) {
            eprintln!("Error deregistering {:?}: {}", stream, e);
        }
    }
}

fn main() {
    // Create a poll instance
    let poll = Poll::new().expect("Cannot create selector");

    let discard_standard = SocketAddr::new(LOCALHOST, DISCARD_PORT);
    let discard_server = TcpListener::bind(&discard_standard).unwrap_or_else(|e| {
        eprintln!("Cannot listen to {}: {}", discard_standard, e);
        let discard_local = SocketAddr::new(LOCALHOST, NONRESERVED_OFFSET+DISCARD_PORT);
        eprintln!("Trying {} instead", discard_local);
        TcpListener::bind(&discard_local).expect("Cannot listen to this port either. Aborting")
    });
    poll.register(&discard_server, DISCARD_TCP, Ready::readable(),
                PollOpt::edge()).expect("Cannot register listener");
    let mut discard_buf = vec![0u8; 4096].into_boxed_slice();

    let qotd_global = SocketAddr::new(ANY, QOTD_PORT);
    let qotd_server = TcpListener::bind(&qotd_global).unwrap_or_else(|e| {
        eprintln!("Cannot listen to {}: {}", qotd_global, e);
        let qotd_local = SocketAddr::new(LOCALHOST, NONRESERVED_OFFSET+QOTD_PORT);
        eprintln!("Trying {} instead", qotd_local);
        TcpListener::bind(&qotd_local).expect("Cannot listen to this port either. Aborting")
    });
    poll.register(&qotd_server, QOTD_TCP, Ready::readable(),
                PollOpt::edge()).expect("Cannot register listener");

    let mut streams = Streams::new(Token(999));
    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, None).expect("Cannot poll selector");
        println!("connections: {}, events: {}", streams.streams.len(), events.iter().count());
        for event in events.iter() {
            println!("\t{:?}", event);
            match event.token() {
                DISCARD_TCP => streams.add(&discard_server, TcpConnection::Discard, Ready::readable(), &poll),
                QOTD_TCP => streams.add(&qotd_server, TcpConnection::Qotd{sent: 0}, Ready::writable(), &poll),
                conn_token => {
                    let (stream, typ) = match streams.get_mut(conn_token) {
                        Some(oe) => oe,
                        None => {
                            eprintln!("Unknown mio token: {}", conn_token.0);
                            continue;
                        }
                    };
                    match typ {
                        TcpConnection::Discard => loop {
                            match stream.read(&mut discard_buf) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    eprintln!("Error reading data to discard: {}, closing", e);
                                    streams.remove(conn_token, &poll);
                                    break;
                                }
                                Ok(0) => {
                                    eprintln!("ending {:?}", stream);
                                    streams.remove(conn_token, &poll);
                                    break;
                                }
                                Ok(len) => {
                                    println!("len: {}", len);
                                    stdout().write(&discard_buf[..len]).expect("Writing to stdout failed");
                                }
                            }
                        }
                        TcpConnection::Qotd{sent} => loop {
                             match stream.write(&QOTD[*sent..]) {
                                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    eprintln!("Error sending qotd: {}, closing", e);
                                    streams.remove(conn_token, &poll);
                                    break;
                                }
                                Ok(0) => {
                                    streams.remove(conn_token, &poll);
                                    break;
                                }
                                Ok(len) => {
                                    *sent += len;
                                    if *sent >= QOTD.len() {
                                        streams.remove(conn_token, &poll);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
