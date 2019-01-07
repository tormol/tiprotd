use std::net::{SocketAddr, IpAddr, Ipv4Addr, Shutdown};
use std::io::{ErrorKind, Read, Write, stdout};
use std::rc::Rc;

extern crate mio;
use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::net::{TcpListener, TcpStream};

extern crate slab;
use slab::Slab;

const DISCARD_PORT: u16 = 9; // only need to read
const QOTD_PORT: u16 = 17; // only need to write
const QOTD: &[u8] = b"No quote today, the DB has gone away\n";

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const NONRESERVED_PORT_OFFSET: u16 = 10_000;

#[derive(Clone)]
enum TcpStreamState {
    Discard,
    Qotd{ sent: usize },
}

enum ConnState {
    Listener {
        listener: Rc<TcpListener>,
        start_state: TcpStreamState,
        poll_streams_for: Ready,
    },
    Stream {
        stream: TcpStream,
        state: TcpStreamState,
    },
}

fn end_stream(token: Token,  conns: &mut Slab<ConnState>,  poll: &Poll) {
    let stream = match conns.remove(token.0) {
        ConnState::Stream{stream, state: _} => stream,
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
    entry.insert(ConnState::Listener {
        listener: Rc::new(listener),
        start_state,
        poll_streams_for,
    });
}

fn main() {
    // Create a poll instance
    let poll = Poll::new().expect("Cannot create selector");
    let mut conns = Slab::with_capacity(512);

    listen_tcp(&poll, &mut conns,
        SocketAddr::new(LOCALHOST, DISCARD_PORT),
        TcpStreamState::Discard,
        Ready::readable(),
    );
    let mut discard_buf = vec![0u8; 4096].into_boxed_slice();

    listen_tcp(&poll, &mut conns,
        SocketAddr::new(ANY, QOTD_PORT),
        TcpStreamState::Qotd{sent: 0},
        Ready::writable(),
    );

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
                &mut ConnState::Listener{ ref listener, ref start_state, poll_streams_for } => {
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
                                    entry.insert(ConnState::Stream {
                                        stream,
                                        state: start_state.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
                ConnState::Stream{ stream, state: TcpStreamState::Discard } => loop {
                    match stream.read(&mut discard_buf) {
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
                            stdout().write(&discard_buf[..len]).expect("Writing to stdout failed");
                        }
                    }
                }
                ConnState::Stream{ stream, state: TcpStreamState::Qotd{sent} } => loop {
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
            }
        }
    }
}
