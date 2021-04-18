use std::collections::VecDeque;
use std::rc::Rc;
use std::path::Path;
use std::fmt::{self, Debug};
use std::io::{ErrorKind, Write, IoSlice};
use std::net::{Shutdown, SocketAddr};

use mio::{Interest, Token, event::Event};
use mio::net::{TcpListener, UdpSocket};
#[cfg(feature="udplite")]
use udplite::UdpLiteSocket;
#[cfg(unix)]
use uds::{UnixSocketAddr, UnixDatagramExt};
#[cfg(unix)]
use mio::net::{UnixDatagram, UnixListener};
#[cfg(feature="seqpacket")]
use uds::nonblocking::UnixSeqpacketListener;

use crate::Server;
use crate::ServiceSocket;
use crate::helpers::*;
use crate::client_limiter::ClientState;

const CHARGEN_PORT: u16 = 19; // write-only

pub struct CharGenContent {
    text: &'static[u8],
    paragraphs_end: Vec<u32>,
}

impl Debug for CharGenContent {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("CharGenContent")
            .field("text length", &self.text.len())
            .field("paragraphs", &self.paragraphs_end.len())
            .finish()
    }
}

impl Default for CharGenContent {
    fn default() -> Self {
        Self {
            text: vec![0; 1_000_000].leak(),
            paragraphs_end: (1..=1_000).map(|x| x*1000 ).collect(),
        }
    }
}

impl CharGenContent {
    fn from_file(file: &Path) -> Option<Rc<Self>> {
        match std::fs::read_to_string(file) {
            Ok(text) => {
                let mut paragraphs_end = Vec::new();
                let mut start = 0;
                while let Some(end) = text[start..].find("\n\n") {
                    start += end + 2;
                    paragraphs_end.push(start as u32);
                }
                paragraphs_end.push(text.len() as u32);
                
                Some(Rc::new(CharGenContent {
                    text: Vec::leak(text.into_bytes()),
                    paragraphs_end,
                }))
            }
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                eprintln!("No {:?} to use as chargen output. Sending a megabyte of NUL instead.", file);
                Some(Rc::new(Self::default()))
            }
            Err(e) => {
                eprintln!("Cannot read {:?}: {}", file, e);
                None
            }
        }
    }    

    pub fn get_paragraph(&self,  paragraph_index: u16) -> &'static[u8] {
        let paragraph_end = self.paragraphs_end[paragraph_index as usize] as usize;
        let paragraph_start = if paragraph_index == 0 {
            0
        } else {
            self.paragraphs_end[paragraph_index as usize-1] as usize
        };
        &self.text[paragraph_start..paragraph_end]
    }
}

#[derive(Debug)]
pub enum CharGenSocket {
    TcpListener(TcpListener, &'static[u8]),
    TcpConn(TcpStreamWrapper, &'static[u8], u32),
    Udp(UdpSocket, Rc<CharGenContent>, VecDeque<(SocketAddr,u16)>),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket, Rc<CharGenContent>, VecDeque<(SocketAddr,u16)>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>, &'static[u8]),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper, &'static[u8], usize),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>, &'static[u8]),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, Rc<CharGenContent>, VecDeque<(UnixSocketAddr,u16)>),
    // TODO posixmq and maybe pipe
}

use self::CharGenSocket::*;

impl CharGenSocket {
    pub fn setup(server: &mut Server) {
        let content = CharGenContent::from_file("LICENSE.md".as_ref()).unwrap();
        listen_tcp(server, "chargen", CHARGEN_PORT,
            &mut|listener, Token(_)| ServiceSocket::CharGen(TcpListener(listener, content.text))
        );
        listen_udp(server, "chargen", CHARGEN_PORT, Interest::READABLE | Interest::WRITABLE,
            &mut|socket, Token(_)| {
                ServiceSocket::CharGen(Udp(socket, content.clone(), VecDeque::new()))
            }
        );
        #[cfg(feature="udplite")]
        listen_udplite(
            server, "chargen", CHARGEN_PORT,
            Interest::READABLE | Interest::WRITABLE,
            Some(0),
            &mut|socket, Token(_)| {
                ServiceSocket::CharGen(UdpLite(socket, content.clone(), VecDeque::new()))
            }
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("chargen", server,
            &mut|listener, Token(_)| {
                ServiceSocket::CharGen(UnixStreamListener(listener, content.text))
            }
        );
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("chargen", server,
            &mut|listener, Token(_)| {
                ServiceSocket::CharGen(UnixSeqpacketListener(listener, content.text))
            }
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket(
            "chargen",
            Interest::READABLE | Interest::WRITABLE,
            server,
            &mut|socket, Token(_)| {
                ServiceSocket::CharGen(UnixDatagram(socket, content.clone(), VecDeque::new()))
            }
        );
    }

    pub fn ready(&mut self,  readiness: &Event,  server: &mut Server) -> EntryStatus {
        match self {
            &mut TcpListener(ref listener, text) => {
                tcp_accept_loop(listener, server, &"chargen", Interest::WRITABLE,
                    |stream| {
                        if stream.shutdown(Shutdown::Read) == Remove {
                            None
                        } else {
                            Some(())
                        }
                    },
                    |stream, (), Token(_)| {
                        ServiceSocket::CharGen(TcpConn(stream, text, 0))
                    },
                )
            }
            &mut TcpConn(ref mut stream, text, ref mut sent_offset) => {
                loop {
                    *sent_offset %= text.len() as u32;
                    let (sent, remaining) = text.split_at(*sent_offset as usize);
                    let result = stream.write_vectored(&[
                        IoSlice::new(remaining),
                        IoSlice::new(sent),
                    ]);
                    match result {
                        Ok(sent) => *sent_offset += sent as u32,
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Drained,
                        e => {
                            stream.end(e, "spamming character");
                            return Remove;
                        }
                    }
                }
            }
            &mut Udp(ref socket, ref content, ref mut unsent) => {
                if readiness.is_readable() {
                    let result = udp_receive(socket, server, "chargen", |_, from, server| {
                        if server.limits.get_unacknowledged_send_state(from)
                        == ClientState::Unlimited {
                            eprintln!("{} udp://{} starts a round of chargen",
                                now(), native_addr(from)
                            );
                            for i in 0..content.paragraphs_end.len() as u16 {
                                unsent.push_back((from, i));
                            }
                        }
                    });
                    if result == Remove {
                        return Remove;
                    }
                }
                while let Some(&(ref addr, paragraph_index)) = unsent.front() {
                    if udp_send(socket, content.get_paragraph(paragraph_index), addr, "chargen") {
                        let _ = unsent.pop_front();
                    } else {
                        break;
                    }
                }
                if unsent.capacity() > 10  &&  unsent.capacity()/8 > unsent.len() {
                    unsent.shrink_to_fit();
                }
                Drained
            }
            #[cfg(feature="udplite")]
            &mut UdpLite(ref socket, ref content, ref mut unsent) => {
                if readiness.is_readable() {
                    let result = udplite_receive(socket, server, "chargen", |_, from, server| {
                        if server.limits.get_unacknowledged_send_state(from)
                        == ClientState::Unlimited {
                            eprintln!("{} udp://{} starts a round of chargen",
                                now(), native_addr(from)
                            );
                            for i in 0..content.paragraphs_end.len() as u16 {
                                unsent.push_back((from, i));
                            }
                        }
                    });
                    if result == Remove {
                        return Remove;
                    }
                }
                while let Some(&(ref addr, paragraph_index)) = unsent.front() {
                    let paragraph = content.get_paragraph(paragraph_index);
                    if udplite_send(socket, paragraph, addr, "chargen") {
                        let _ = unsent.pop_front();
                    } else {
                        break;
                    }
                }
                if unsent.capacity() > 10  &&  unsent.capacity()/8 > unsent.len() {
                    unsent.shrink_to_fit();
                }
                Drained
            }
            #[cfg(unix)]
            &mut UnixDatagram(ref socket, ref content, ref mut unsent) => {
                if readiness.is_readable() {
                    loop {
                        match socket.recv_from_unix_addr(&mut server.buffer) {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            // send errors might be returned on the next read
                            Err(e) => {
                                eprintln!(
                                    "{} unix datagram chargen error (on receive): {}",
                                    now(), e
                                );
                                return Remove;
                            }
                            Ok((_, from)) => {
                                eprintln!("{} uddg://{} starts a round of chargen", now(), from);
                                for i in 0..content.paragraphs_end.len() as u16 {
                                    unsent.push_back((from, i));
                                }
                            }
                        }
                    }
                }
                while let Some(&(ref addr, paragraph_index)) = unsent.front() {
                    let paragraph = content.get_paragraph(paragraph_index);
                    if unix_datagram_send(socket, paragraph, &addr, "chargen") {
                        let _ = unsent.pop_front();
                    } else {
                        break;
                    }
                }
                if unsent.capacity() > 10  &&  unsent.capacity()/8 > unsent.len() {
                    unsent.shrink_to_fit();
                }
                Drained
            }
            #[cfg(unix)]
            &mut UnixStreamListener(ref listener, text) => {
                unix_stream_accept_loop(listener, server, &"chargen", Interest::WRITABLE,
                    |stream| {
                        if stream.shutdown(Shutdown::Read) {
                            return None;
                        }
                        match stream.write(text) {
                            Ok(all) if all == text.len() => None,
                            Ok(sent) => Some(sent),
                            Err(_) => Some(0),
                        }
                    },
                    |stream, sent, Token(_)| {
                        ServiceSocket::CharGen(UnixStreamConn(stream, text, sent))
                    }
                )
            }
            #[cfg(unix)]
            &mut UnixStreamConn(ref mut conn, text, ref mut sent) => {
                match conn.write(&text[*sent..]) {
                    Ok(remaining) if *sent+remaining == text.len() => Remove,
                    Ok(partial) => {*sent += partial; Drained},
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => Drained,
                    e => {
                        conn.end(e, "sending remaining chargen to");
                        Remove
                    }
                }
            }
            #[cfg(feature="seqpacket")]
            &mut UnixSeqpacketListener(ref listener, text) => {
                unix_seqpacket_accept_loop(listener, server, &"chargen", Interest::WRITABLE,
                    |conn| {
                        match conn.send(text) {
                            Ok(all) if all == text.len() => {},
                            Ok(partial) if partial > 0 => eprintln!(
                                "{} Could only send {} of {} bytes of chargen to udsq://{}",
                                now(), partial, text.len(), conn.peer_unix_addr().unwrap()
                            ),
                            e => conn.end(e, "send the chargen packet")
                        }
                        None
                    },
                    |_, (), Token(_)| unreachable!("chargen unix seqpacket connections cannot be stored")
                )
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &TcpListener(ref listener, ..) => Some(listener),
            &Udp(ref socket, ..) => Some(socket),
            #[cfg(feature="udplite")]
            &UdpLite(ref socket, ..) => Some(socket),
            &TcpConn(ref conn, ..) => Some(&**conn),
            #[cfg(unix)]
            &UnixStreamListener(ref listener, ..) => Some(&**listener),
            #[cfg(feature="seqpacket")]
            &UnixSeqpacketListener(ref listener, ..) => Some(&**listener),
            #[cfg(unix)]
            &UnixDatagram(ref socket, ..) => Some(&**socket),
            #[cfg(unix)]
            &UnixStreamConn(ref conn, ..) => Some(&**conn),
        }
    }
}
