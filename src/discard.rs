use std::fmt::Debug;
use std::net::Shutdown;
use std::io::{self, ErrorKind, Read, Write, stdout};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(unix)]
use std::ffi::CString;

use mio::{Ready, Token};
use mio::net::{TcpListener, UdpSocket};
#[cfg(unix)]
use mio::{PollOpt, Poll};
#[cfg(feature="udplite")]
use udplite::UdpLiteSocket;
#[cfg(unix)]
use mio_uds::{UnixDatagram, UnixListener};
#[cfg(feature="seqpacket")]
use uds::nonblocking::UnixSeqpacketListener;

use crate::Server;
use crate::ServiceSocket;
use crate::helpers::*;

const DISCARD_PORT: u16 = 9;

/// discard specific because only reading can be don non-blockingly
#[cfg(unix)]
#[derive(Debug)]
pub struct NamedPipe {
    path: &'static str,
    fd: RawFd,
}
#[cfg(unix)]
impl Drop for NamedPipe {
    fn drop(&mut self) {
        if unsafe { nix::libc::close(self.fd) } != 0 {
            eprintln!("Cannot close fd for pipe {}: {}",
                self.path, std::io::Error::last_os_error()
            );
        }
        if self.path != "" {
            if let Err(e) = std::fs::remove_file(self.path) {
                eprintln!("Cannot remove {}: {}", self.path, e);
            }
        }
    }
}
#[cfg(unix)]
impl NamedPipe {
    pub fn create_readable_nonblocking(path: &'static str) -> Result<Self, io::Error> {
        let c_path = CString::new(path)?;
        if unsafe { nix::libc::mkfifo(c_path.as_ptr(), 0o777) } == -1 {
            let e = io::Error::last_os_error();
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        let flags = nix::libc::O_RDONLY | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC;
        match unsafe { nix::libc::open(c_path.as_ptr(), flags, 0) } {
            -1 => Err(io::Error::last_os_error()),
            fd => Ok(Self { path, fd }),
        }
    }
}
#[cfg(unix)]
impl AsRawFd for NamedPipe {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
#[cfg(unix)]
impl mio::Evented for NamedPipe {
    fn register(&self,  poll: &Poll,  token: Token,  interests: Ready,  options: PollOpt)
    -> Result<(), io::Error> {
        mio::unix::EventedFd(&self.fd).register(poll, token, interests, options)
    }
    fn reregister(&self,  poll: &Poll,  token: Token,  interests: Ready,  options: PollOpt)
    -> Result<(), io::Error> {
        mio::unix::EventedFd(&self.fd).reregister(poll, token, interests, options)
    }
    fn deregister(&self,  poll: &Poll) -> Result<(), io::Error> {
        mio::unix::EventedFd(&self.fd).deregister(poll)
    }
}
#[cfg(unix)]
impl Read for NamedPipe {
    fn read(&mut self,  buf: &mut[u8]) -> Result<usize, io::Error> {
        loop {
            let ptr = buf.as_mut_ptr() as *mut nix::libc::c_void;
            let read = unsafe { nix::libc::read(self.fd, ptr, buf.len()) };
            if read != -1 {
                return Ok(read as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(unix)]
fn create_and_register_pipe(path: &'static str,  server: &mut Server) {
    let pipe = match NamedPipe::create_readable_nonblocking(path) {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("Cannot create discard.pipe: {}", e);
            return;
        }
    };
    let entry = server.sockets.vacant_entry();
    let register_result =  server.poll.register(
            &pipe,
            Token(entry.key()),
            Ready::readable(),
            PollOpt::edge()
    );
    // let mut info: nix::libc::stat = unsafe { std::mem::zeroed() };
    // unsafe { nix::libc::fstat(pipe.as_raw_fd(), &mut info) };
    // println!("is pipe regular: {}", (info.st_mode & nix::libc::S_IFMT) == nix::libc::S_IFREG);
    if let Err(e) = register_result {
        if e.kind() == ErrorKind::PermissionDenied {
            eprintln!("Cannot register {} with mio, it's probably not a pipe", pipe.path);
        } else {
            eprintln!("Cannot register pipe with mio: {}", e);
        }
        return;
    }
    entry.insert(ServiceSocket::Discard(NamedPipe(pipe)));
}

#[derive(Debug)]
pub enum DiscardSocket {
    // On *nix I could merge many of these, using read() directly,
    // but need to release resources
    TcpListener(TcpListener),
    TcpConn(TcpStreamWrapper),
    Udp(UdpSocket),
    #[cfg(feature="udplite")]
    UdpLite(UdpLiteSocket),
    #[cfg(unix)]
    UnixStreamListener(UnixSocketWrapper<UnixListener>),
    #[cfg(unix)]
    UnixStreamConn(UnixStreamWrapper),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketListener(UnixSocketWrapper<UnixSeqpacketListener>),
    #[cfg(feature="seqpacket")]
    UnixSeqpacketConn(UnixSeqpacketConnWrapper, bool),
    #[cfg(unix)]
    UnixDatagram(UnixSocketWrapper<UnixDatagram>),
    #[cfg(unix)]
    NamedPipe(NamedPipe),
    #[cfg(feature="posixmq")]
    PosixMq(PosixMqWrapper),
}

use self::DiscardSocket::*;

fn anti_discard(from: &dyn Debug,  protocol: &str,  bytes: &[u8]) {
    let now = now();
    eprintln!("{} {}://{:?} discards {} bytes", now, protocol, from, bytes.len());
    // TODO rate limit logging to prevent filling up disk
    print!("{} {}://{:?} discards {} bytes: ", now, protocol, from, bytes.len());
    // TODO escape to printable characters
    stdout().write(bytes).expect("Writing to stdout failed");
    if bytes.last().cloned() != Some(b'\n') {
        println!();
    }
}

impl DiscardSocket {
    pub fn setup(server: &mut Server) {
        listen_tcp(server, "discard", DISCARD_PORT,
            &mut|listener, Token(_)| ServiceSocket::Discard(TcpListener(listener))
        );
        listen_udp(server, "discard", DISCARD_PORT, Ready::readable(),
            &mut|socket, Token(_)| ServiceSocket::Discard(Udp(socket))
        );
        #[cfg(feature="udplite")]
        listen_udplite(server, "discard", DISCARD_PORT, Ready::readable(), None,
            &mut|socket, Token(_)| ServiceSocket::Discard(UdpLite(socket))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_stream_listener("discard", server,
            &mut|listener, Token(_)| ServiceSocket::Discard(UnixStreamListener(listener))
        );
        #[cfg(unix)]
        UnixSocketWrapper::create_datagram_socket("discard", Ready::readable(), server,
            &mut|socket, Token(_)| ServiceSocket::Discard(UnixDatagram(socket))
        );
        #[cfg(unix)]
        create_and_register_pipe("discard.pipe", server);
        #[cfg(feature="seqpacket")]
        UnixSocketWrapper::create_seqpacket_listener("discard", server,
            &mut|listener, Token(_)| ServiceSocket::Discard(UnixSeqpacketListener(listener))
        );
        #[cfg(feature="posixmq")]
        listen_posixmq(server, "discard", Ready::readable(),
            posixmq::OpenOptions::readonly()
                .mode(0o622)
                .max_msg_len(server.buffer.len())
                .capacity(2),
            &mut|mq, Token(_)| ServiceSocket::Discard(PosixMq(mq))
        );
    }

    pub fn ready(&mut self,  _: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        match self {
            &mut TcpListener(ref listener) => {
                tcp_accept_loop(listener, server,  &"discard", Ready::readable(),
                    |stream| {stream.shutdown(Shutdown::Write); Some(())}, // likely long-lived
                    |stream, (), Token(_)| ServiceSocket::Discard(TcpConn(stream)),
                )
            }
            &mut TcpConn(ref mut stream) => {
                loop {
                    match stream.read(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Ok(len) if len > 0 => {
                            anti_discard(&stream.native_addr, "tcp", &server.buffer[..len]);
                        }
                        end => {
                            stream.end(end, "reading bytes to discard");
                            break Remove;
                        }
                    }
                }
            }
            &mut Udp(ref socket) => {
                loop {
                    match socket.recv_from(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("{} discard UDP error: {}", now(), e);
                            break Remove; // some errors should probably be ignored, but see what happens
                        }
                        Ok((len, from)) => {
                            anti_discard(&native_addr(from), "udp", &server.buffer[..len]);
                        }
                    }
                }
            }
            #[cfg(feature="udplite")]
            &mut UdpLite(ref socket) => {
                loop {
                    match socket.recv_from(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("{} discard UDP-lite error: {}", now(), e);
                            break Remove; // some errors should probably be ignored, but see what happens
                        }
                        Ok((len, from)) => {
                            anti_discard(&native_addr(from), "udplite", &server.buffer[..len]);
                        }
                    }
                }
            }
            #[cfg(unix)]
            &mut UnixStreamListener(ref mut listener) => {
                unix_stream_accept_loop(listener, server, &"discard", Ready::readable(),
                    |stream| {stream.shutdown(Shutdown::Write); Some(())}, // likely long-lived
                    |stream, (), Token(_)| ServiceSocket::Discard(UnixStreamConn(stream))
                )
            }
            #[cfg(unix)]
            &mut UnixStreamConn(ref mut stream) => {
                loop {
                    match stream.read(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Ok(len) if len > 0 => anti_discard(&stream.addr, "uds", &server.buffer[..len]),
                        end => {
                            stream.end(end, "reading bytes to discard");
                            break Remove;
                        }
                    }
                }
            }
            #[cfg(feature="seqpacket")]
            &mut UnixSeqpacketListener(ref mut listener) => {
                unix_seqpacket_accept_loop(listener, server, &"discard", Ready::readable(),
                    |conn| {conn.shutdown(Shutdown::Write); Some(())}, // likely long-lived
                    |conn, (), Token(_)| ServiceSocket::Discard(UnixSeqpacketConn(conn, false))
                )
            }
            #[cfg(feature="seqpacket")]
            &mut UnixSeqpacketConn(ref mut conn, ref mut last_was_empty) => {
                loop {
                    match conn.recv(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                            break Drained
                        }
                        Ok((len, truncated)) if len > 0 => {
                            if *last_was_empty {
                                anti_discard(&conn.addr, "udsq", &[]);
                                *last_was_empty = false;
                            }
                            if truncated {
                                eprintln!(
                                    "{} udsq://{} received packet was truncated",
                                    now(), conn.addr,
                                );
                            }
                            anti_discard(&conn.addr, "udsq", &server.buffer[..len]);
                        }
                        end => {
                            if *last_was_empty {
                                conn.end(
                                    end.map(|(bytes, _)| bytes ),
                                    "receiving bytes to discard"
                                );
                                break Remove;
                            } else {
                                *last_was_empty = true;
                            }
                        }
                    }
                }
            }
            #[cfg(unix)]
            &mut UnixDatagram(ref socket) => {
                loop {
                    match socket.recv_from(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error receiving unix datagram packet to discard: {}", e);
                            break Remove;
                        }
                        Ok((len, from)) => {
                            anti_discard(&from, "uddg", &server.buffer[..len]);
                        }
                    }
                }
            }
            #[cfg(unix)]
            &mut NamedPipe(ref mut pipe) => {
                loop {
                    match pipe.read(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Cannot read from {}: {}, removing it", pipe.path, e);
                            break Remove;
                        }
                        Ok(0) => {
                            // reopen by replacing
                            create_and_register_pipe(pipe.path, server);
                            pipe.path = "";
                            break Remove;
                        }
                        Ok(n) => anti_discard(
                                &mut format_args!("somebody via {}", pipe.path),
                                "pipe",
                                &server.buffer[..n]
                        )
                    }
                }
            }
            #[cfg(feature="posixmq")]
            &mut PosixMq(ref mq) => {
                loop {
                    match mq.recv(&mut server.buffer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break Drained,
                        Err(e) => {
                            eprintln!("Error receiving from posix message queue /discard: {}, removing it.", e);
                            break Remove;
                        },
                        Ok((_priority, len)) => anti_discard(&"/discard", "mq", &server.buffer[..len]),
                    }
                }
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn Descriptor+'static)> {
        match self {
            &TcpListener(ref listener) => Some(listener),
            &Udp(ref socket) => Some(socket),
            #[cfg(feature="udplite")]
            &UdpLite(ref socket) => Some(socket),
            &TcpConn(ref conn) => Some(&**conn),
            #[cfg(unix)]
            &UnixStreamListener(ref listener) => Some(&**listener),
            #[cfg(feature="seqpacket")]
            &UnixSeqpacketListener(ref listener) => Some(&**listener),
            #[cfg(unix)]
            &UnixDatagram(ref socket) => Some(&**socket),
            #[cfg(unix)]
            &UnixStreamConn(ref conn) => Some(&**conn),
            #[cfg(feature="seqpacket")]
            &UnixSeqpacketConn(ref conn, _) => Some(&**conn),
            #[cfg(unix)]
            &NamedPipe(ref pipe) => Some(pipe),
            #[cfg(feature="posixmq")]
            &PosixMq(ref mq) => Some(&**mq),
        }
    }
}
