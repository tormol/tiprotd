use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write, IoSlice};
use std::net::{Shutdown, SocketAddr};
use std::rc::Rc;

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

const ECHO_PORT: u16 = 7; // read and write

#[cfg(feature="seqpacket")]
/// State of an unix domain seqpacket connection
#[derive(Debug, Default)]
pub struct EchoSeqpacketConnState {
    /// Size of each received packet that has not been sent back yet.
    ///
    /// Size is not usize because the receive buffer is much smaller than 4 GB.
    unsent_packets: VecDeque<u32>,
    /// Stores the unsent received bytes to echo
    content_buf: VecDeque<u8>,
    /// Implements sending each received packet twice
    ///
    /// Is toggled after a packet is sent,
    /// and only if it was true is unsent_packets popped and content_buf drained.
    /// Starts out as false from the derived Default impl.
    sent_once: bool,
    /// Signal that end of connection has been reached.
    ///
    /// Is set to true when recv() has returned Ok(0) two times in a row.
    /// (two recv()s are required as Ok(0) can also signal an empty packet.)
    /// After this, the connection will be closed after all unsent packets
    /// have been sent.
    recv_shutdown: bool,
    last_was_empty: bool,
}

#[derive(Debug)]
pub enum EchoSocket {
    TcpListener(TcpListener),
    TcpConn(TcpStreamWrapper, VecDeque<u8>, bool),
    Udp(UdpSocket, VecDeque<(SocketAddr,Rc<[u8]>)>),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket, VecDeque<(SocketAddr,Rc<[u8]>)>),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper, VecDeque<u8>, bool),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketConn(UnixSeqpacketConnWrapper, EchoSeqpacketConnState),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>, VecDeque<(UnixSocketAddr,Rc<[u8]>)>),
}

fn tcp_echo(conn: &mut TcpStreamWrapper,  unsent: &mut VecDeque<u8>,  recv_shutdown: &mut bool,
        buffer: &mut[u8],  event: &Event,
) -> EntryStatus {
    if !*recv_shutdown && event.is_readable() {
        loop {
            match conn.read(buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) if len > 0 => {
                    // if unsent.is_empty() {
                    //     // try to send without copying
                    //     match conn.write_bufs(&[buffer[..len].into(), buffer[..len].into()]) {
                    //         Ok(wrote) => {

                    //         }
                    //     }
                    // }
                    if conn.limit_counters.request_resources(2*len) {
                        unsent.extend(&buffer[..len]);
                        unsent.extend(&buffer[..len]);
                    } else {
                        return Remove;
                    }
                }
                Ok(0) => {
                    *recv_shutdown = true;
                    break;
                }
                end => {
                    conn.limit_counters.release_resources(unsent.len());
                    conn.end(end, "reading bytes to echo");
                    return Remove;
                }
            }
        }
    }
    // if the socket is write ready but we don't have anything to write,
    // we cannot drain the readiness, so always try to write when we get some
    // if there is data to write, we need to try writing it even if no more
    // data is received
    while !unsent.is_empty() {
        // use vectored io to send both slices of the deque at once
        // IoVec can't be empty though, so need to special case
        let (first, second) = unsent.as_slices();
        match conn.write_vectored(&[IoSlice::new(first), IoSlice::new(second)]) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(len @ 1..=std::usize::MAX) => {
                conn.limit_counters.release_resources(len);
                unsent.drain(..len).for_each(|_| {} );
            }
            end => {
                conn.limit_counters.release_resources(unsent.len());
                conn.end(end, "echoing");
                return Remove;
            }
        }
    }
    if *recv_shutdown && unsent.is_empty() {
        conn.shutdown(Shutdown::Both);
        Remove
    } else {
        Drained
    }
}

#[cfg(unix)]
fn unix_stream_echo(conn: &mut UnixStreamWrapper,  unsent: &mut VecDeque<u8>,
        recv_shutdown: &mut bool,  buffer: &mut[u8],  event: &Event,
) -> EntryStatus {
    if !*recv_shutdown && event.is_readable() {
        loop {
            match conn.read(buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok(len) if len > 0 => {
                    unsent.extend(&buffer[..len]);
                    unsent.extend(&buffer[..len]);
                }
                Ok(0) => {
                    *recv_shutdown = true;
                    break;
                }
                end => {
                    conn.end(end, "reading bytes to echo");
                    return Remove;
                }
            }
        }
    }
    while !unsent.is_empty() {
        // use vectored io to send both slices of the deque at once
        // IoVec can't be empty though, so need to special case
        let (first, second) = unsent.as_slices();
        match conn.write_vectored(&[IoSlice::new(first), IoSlice::new(second)]) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(len @ 1..=std::usize::MAX) => {
                unsent.drain(..len).for_each(|_| {} );
            }
            end => {
                conn.end(end, "echoing");
                return Remove;
            }
        }
    }
    if *recv_shutdown && unsent.is_empty() {
        conn.shutdown(Shutdown::Both);
        Remove
    } else {
        Drained
    }
}

#[cfg(feature="seqpacket")]
fn unix_seqpacket_echo(
        conn: &mut UnixSeqpacketConnWrapper,
        state: &mut EchoSeqpacketConnState,
        buffer: &mut[u8],
        event: &Event,
) -> EntryStatus {
    if !state.recv_shutdown && event.is_readable() {
        loop {
            match conn.recv(buffer) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Ok((len, truncated)) if len > 0 => {
                    if state.last_was_empty {
                        state.unsent_packets.push_back(0);
                        state.last_was_empty = false;
                    }
                    if truncated {
                        eprintln!(
                            "{} echo udsq://{} received packet was truncated",
                            now(), conn.addr
                        );
                    }
                    state.unsent_packets.push_back(len as u32);
                    state.content_buf.extend(&buffer[..len]);
                }
                Ok((0, _)) => {
                    if state.last_was_empty {
                        state.recv_shutdown = true;
                        break;
                    } else {
                        state.last_was_empty = true;
                    }
                }
                end => {
                    conn.end(end.map(|(bytes, _)| bytes ), "receiving bytes to echo");
                    return Remove;
                }
            }
        }
    }
    while let Some(&packet_size) = state.unsent_packets.front() {
        let parts = match state.content_buf.as_slices() {
            (contigious, _) if contigious.len() >= packet_size as usize => [
                IoSlice::new(&contigious[..packet_size as  usize]),
                IoSlice::new(&[]),
            ],
            (first, second) => [
                IoSlice::new(first),
                IoSlice::new(&second[..(packet_size as usize - first.len())]),
            ],
        };
        match conn.send_vectored(&parts) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(sent @ 1..=std::usize::MAX) => {
                if sent < packet_size as usize {
                    eprintln!(
                        "{} echo udsq://{} sent packet was truncated to {} of {} bytes",
                        now(), conn.addr, sent, packet_size
                    );
                }
                if state.sent_once {
                    state.unsent_packets.pop_front();
                    state.content_buf.drain(..packet_size as usize).for_each(|_| {} );
                    state.sent_once = false;
                } else {
                    state.sent_once = true;
                }
            }
            end => {
                conn.end(end, "echoing");
                return Remove;
            }
        }
    }
    if state.recv_shutdown && state.unsent_packets.is_empty() {
        conn.shutdown(Shutdown::Both);
        Remove
    } else {
        Drained
    }
}

use self::EchoSocket::*;

impl EchoSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "echo", ECHO_PORT,
            &mut|listener, Token(_)| ServiceSocket::Echo(TcpListener(listener))
        );
        listen_udp(server, "echo", ECHO_PORT, Interest::READABLE | Interest::WRITABLE,
            &mut|socket, Token(_)| ServiceSocket::Echo(Udp(socket, VecDeque::new()))
        );
        #[cfg(feature="udplite")]
        listen_udplite(server, "echo", ECHO_PORT, Interest::READABLE | Interest::WRITABLE, None,
            &mut|socket, Token(_)| ServiceSocket::Echo(UdpLite(socket, VecDeque::new()))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("echo", server,
            &mut|listener, Token(_)| ServiceSocket::Echo(UnixStreamListener(listener))
        );
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("echo", server,
            &mut|listener, Token(_)| ServiceSocket::Echo(UnixSeqpacketListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket(
            "echo",
            Interest::READABLE | Interest::WRITABLE,
            server,
            &mut|socket, Token(_)| ServiceSocket::Echo(UnixDatagram(socket, VecDeque::new()))
        );
    }

    pub fn ready(&mut self,  event: &Event,  server: &mut Server) -> EntryStatus {
        match self {
            &mut TcpListener(ref listener) => {
                tcp_accept_loop(listener, server, &"echo", Interest::READABLE | Interest::WRITABLE,
                    |_| Some(()),
                    |stream, (), Token(_)| {
                        ServiceSocket::Echo(TcpConn(stream, VecDeque::new(), false))
                    },
                )
            }
            &mut TcpConn(ref mut stream, ref mut unsent, ref mut read_shutdown) => {
                tcp_echo(stream, unsent, read_shutdown, &mut server.buffer, event)
            }
            // don't count stored UDP data toward resource limits, as sending
            // is only limited by the OS's socket buffer, and not by the
            // client or network. A client should not be able to cause an
            // issue here before hitting its UDP send limit.
            &mut Udp(ref socket, ref mut unsent) => {
                if event.is_readable() {
                    let result = udp_receive(socket, server, "echo", |len, from, server| {
                        if server.limits.get_unacknowledged_send_state(from)
                        == ClientState::Unlimited {
                            eprintln!("{} udp://{} sends {} bytes to echo echo",
                                now(), native_addr(from), len
                            );
                            // TODO send directly if unsent.is_empty()
                            let msg = Rc::<[u8]>::from(&server.buffer[..len]);
                            unsent.push_back((from, msg.clone()));
                            unsent.push_back((from, msg));
                        } else if server.limits.allow_unacknowledged_send(from, len-len/2) {
                            eprintln!("{} udp://{} sends {} bytes to echo half",
                                now(), native_addr(from), len
                            );
                            let msg = &server.buffer[len/2..len];
                            let sent = unsent.is_empty() && udp_send(socket, msg, &from, "echo");
                            if !sent {
                                unsent.push_back((from, Rc::<[u8]>::from(msg)));
                            }
                        }
                    });
                    if result == Remove {
                        return Remove;
                    }
                }
                while let Some((addr,msg)) = unsent.front() {
                    if udp_send(socket, msg, addr, "echo") {
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
            &mut UdpLite(ref socket, ref mut unsent) => {
                if event.is_readable() {
                    let result = udplite_receive(socket, server, "echo", |len, from, server| {
                        if server.limits.get_unacknowledged_send_state(from)
                        == ClientState::Unlimited {
                            eprintln!("{} udplite://{} sends {} bytes to echo echo",
                                now(), native_addr(from), len
                            );
                            // TODO send directly if unsent.is_empty()
                            let msg = Rc::<[u8]>::from(&server.buffer[..len]);
                            unsent.push_back((from, msg.clone()));
                            unsent.push_back((from, msg));
                        } else if server.limits.allow_unacknowledged_send(from, len-len/2) {
                            eprintln!("{} udplite://{} sends {} bytes to echo half",
                                now(), native_addr(from), len
                            );
                            let msg = &server.buffer[len/2..len];
                            let mut sent = false;
                            if unsent.is_empty() {
                                sent = udplite_send(socket, msg, &from, "echo");
                            }
                            if !sent {
                                unsent.push_back((from, Rc::<[u8]>::from(msg)));
                            }
                        }
                    });
                    if result == Remove {
                        return Remove;
                    }
                }
                while let Some((addr,msg)) = unsent.front() {
                    let coverage = (msg.len() / 2) as u16;
                    if let Err(e) = socket.set_send_checksum_coverage(Some(coverage)) {
                        eprintln!(
                            "{} UDP-lite echo cannot set response checksum coverage to {} of {}: {}",
                            now(), coverage, msg.len(), e
                        );
                    }
                    if udplite_send(socket, msg, addr, "echo") {
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
            &mut UnixDatagram(ref socket, ref mut unsent) => {
                if event.is_readable() {
                    loop {
                        match socket.recv_from_unix_addr(&mut server.buffer) {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            // send errors might be returned on the next read
                            Err(e) => eprintln!("unix datagram echo error (on receive): {}", e),
                            Ok((len, from)) => {
                                eprintln!("{} uddg://{} sends {} bytes to echo",
                                    now(), from, len
                                );
                                // TODO send directly if unsent.is_empty()
                                let msg = Rc::<[u8]>::from(&server.buffer[..len]);
                                unsent.push_back((from, msg.clone()));
                                unsent.push_back((from, msg));
                            }
                        }
                    }
                }
                while let Some((addr,msg)) = unsent.front() {
                    if unix_datagram_send(socket, msg, &addr, "echo") {
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
            &mut UnixStreamListener(ref listener) => {
                unix_stream_accept_loop(
                    listener,
                    server,
                    &"echo",
                    Interest::READABLE | Interest::WRITABLE,
                    |_| Some(()),
                    |stream, (), Token(_)| {
                        ServiceSocket::Echo(UnixStreamConn(stream, VecDeque::new(), false))
                    }
                )
            }
            #[cfg(unix)]
            &mut UnixStreamConn(ref mut conn, ref mut unsent, ref mut read_shutdown) => {
                unix_stream_echo(conn, unsent, read_shutdown, &mut server.buffer, event)
            }
            #[cfg(feature="seqpacket")]
            &mut UnixSeqpacketListener(ref listener) => {
                unix_seqpacket_accept_loop(
                    listener,
                    server,
                    &"echo",
                    Interest::READABLE | Interest::WRITABLE,
                    |_| Some(()),
                    |conn, (), Token(_)| {
                        let clean_state = EchoSeqpacketConnState::default();
                        ServiceSocket::Echo(UnixSeqpacketConn(conn, clean_state))
                    }
                )
            }
            #[cfg(feature="seqpacket")]
            &mut UnixSeqpacketConn(ref mut conn, ref mut state) => {
                unix_seqpacket_echo(conn, state, &mut server.buffer, event)
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &TcpListener(ref listener) => Some(listener),
            &Udp(ref socket, _) => Some(socket),
            #[cfg(feature="udplite")]
            &UdpLite(ref socket, _) => Some(socket),
            &TcpConn(ref conn, _, _) => Some(&**conn),
            #[cfg(unix)]
            &UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(feature="seqpacket")]
            &UnixSeqpacketListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &UnixDatagram(ref socket, _) => Some(&**socket),
            #[cfg(unix)]
            &UnixStreamConn(ref conn, _, _) => Some(&**conn),
            #[cfg(feature="seqpacket")]
            &UnixSeqpacketConn(ref conn, _) => Some(&**conn),
        }
    }
}
