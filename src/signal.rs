//! Handle some signals on unix platforms:
//!  ^C: first time drop listeners and wait for connections to complete
//!         (dropping removes any relevant file)
//!      afterwards, abort
//! some other: print state
//! SIGHUP: ignore

// signal_hook crate doesn't appear to support selfpipe-then-abort,
// so therefore we do it the low-level way

#![cfg(unix)]

use std::os::unix::io::RawFd;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicIsize, Ordering};

use mio::{PollOpt, Ready, Token};
use mio::net::TcpStream;
use mio_uds::UnixStream;
use nix::fcntl;
use nix::sys::signal;
use nix::unistd::{read, write};

use crate::{Server, helpers::EntryStatus};

static SELFPIPE_WRITER: AtomicIsize = AtomicIsize::new(-1);

extern "C" fn signal_shutdown(sig: c_int) {
    let fd = SELFPIPE_WRITER.load(Ordering::SeqCst); // performance is a non-issue
    if write(fd as RawFd, b"\0") != Ok(1) {
        // TODO set an alarm to auto-terminate in ~20s?
        unsafe { nix::libc::raise(sig) }; // no way to convert to Signal
    }
}

extern "C" fn signal_stats(_: c_int) {
    let fd = SELFPIPE_WRITER.load(Ordering::SeqCst);
    let _ = write(fd as RawFd, &[1][..]);
    // writing a nice error to stderr without allocating is possible in
    // any reasonable case, but difficult enough that it's not worth it.
}

#[derive(Debug)]
pub struct SignalReceiver {
    reader: RawFd,
}
impl SignalReceiver {
    pub fn setup(server: &mut Server) {
        if let Err(e) = unsafe { signal::signal(signal::SIGHUP, signal::SigHandler::SigIgn) } {
            eprintln!("Cannot ignore SIGHUP: {}", e);
        }
        if let Err(e) = unsafe { signal::signal(signal::SIGTTIN, signal::SigHandler::SigIgn) } {
            eprintln!("Cannot ignore SIGTTIN: {}", e);
        }
        if let Err(e) = unsafe { signal::signal(signal::SIGTTOU, signal::SigHandler::SigIgn) } {
            eprintln!("Cannot ignore SIGTTOU: {}", e);
        }

        // TODO open as CLOEXEC and nonblocking
        let (reader, writer) = match nix::unistd::pipe() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Cannot create self-pipe: {}, aborting signal-handling", e);
                return;
            }
        };
        fcntl::fcntl(reader, fcntl::F_SETFL(fcntl::OFlag::O_NONBLOCK)).unwrap();
        // if let Ok(default_size) = fcntl::fcntl(reader, fcntl::F_GETPIPE_SZ) {
        //     println!("self-pipe buffer size is {}", default_size);
        // }
        #[cfg(any(target_os="linux", target_os="android"))]
        match fcntl::fcntl(reader, fcntl::F_SETPIPE_SZ(8)) {
            Ok(_set_size) => {/*println!("Set self-pipe buffer size to {}", set_size)*/},
            Err(e) => eprintln!("Cannot set self-pipe buffer size: {}", e),
        }

        let entry = server.sockets.vacant_entry();
        let result = server.poll.register(
            &mio::unix::EventedFd(&reader),
            Token(entry.key()),
            Ready::readable(),
            PollOpt::edge()
        );
        if let Err(e) = result {
            eprintln!("Cannot register self-pipe: {}, aborting signal-handling", e);
            return;
        }
        SELFPIPE_WRITER.store(writer as isize, Ordering::SeqCst);
        entry.insert(crate::ServiceSocket::SignalReceiver(SignalReceiver{reader}));
        server.internally_shutdown += 1;

        let shutdown_action = signal::SigAction::new(
            signal::SigHandler::Handler(signal_shutdown),
            signal::SaFlags::SA_RESETHAND,
            signal::SigSet::empty()
        );
        if let Err(e) = unsafe { signal::sigaction(signal::SIGINT, &shutdown_action) } {
            eprintln!("Cannot set SIGINT (^C) handler: {}", e);
        }
        if let Err(e) = unsafe { signal::sigaction(signal::SIGTERM, &shutdown_action) } {
            eprintln!("Cannot set SIGTERM handler: {}", e);
        }
        if let Err(e) = unsafe { signal::sigaction(signal::SIGPIPE, &shutdown_action) } {
            eprintln!("Cennot set SIGPIPE handler: {}", e);
        }

        let stats_action = signal::SigAction::new(
            signal::SigHandler::Handler(signal_stats),
            signal::SaFlags::empty(),
            signal::SigSet::empty()
        );
        if let Err(e) = unsafe { signal::sigaction(signal::SIGUSR1, &stats_action) } {
            eprintln!("Cannot set up SIGUSR1 handler: {}", e);
        }
        #[cfg(any(target_os="linux", target_os="android", target_os="emscripten"))]
        use signal::SIGPWR as SIGINFO;
        #[cfg(not(any(target_os="linux", target_os="android", target_os="emscripten")))]
        use signal::SIGINFO;
        if let Err(e) = unsafe { signal::sigaction(SIGINFO, &stats_action) } {
            eprintln!("Cannot set up SIGINFO handler: {}", e);
        }
    }

    pub fn ready(&mut self,  _: Ready,  _: Token,  server: &mut Server) -> EntryStatus {
        // println!("signal ready");
        loop {
            match read(self.reader, &mut server.buffer) {
                Err(ref e) if e.as_errno() == Some(nix::errno::EWOULDBLOCK) => return EntryStatus::Drained,
                Err(e) => {
                    eprintln!("Error reading from self-pipe: {}", e);
                    return EntryStatus::Remove;
                }
                Ok(signals) => {
                    for signal in 0..signals {
                        match server.buffer[signal] {
                            0 => start_shutdown(server),
                            1 => print_state(server),
                            unknown => eprintln!("Signal receiver read unknown type: {}", unknown),
                        }
                    }
                }
            }
        }
    }

    pub fn inner_descriptor(&self) -> Option<&(dyn crate::helpers::Descriptor+'static)> {
        None // TODO proper type
    }
}

fn start_shutdown(server: &mut Server) {
    // cannot use normal iterator because we might remove elements.
    // loop until .capacity() because .len() is the number of present elements
    // which will be less than some element's keys if there are holes.
    for i in 0..server.sockets.capacity() {
        let descriptor = match server.sockets.get(i).and_then(|entry| entry.inner_descriptor() ) {
            Some(descriptor) => descriptor.as_any(),
            None => continue, // this lets the self-pipe remain
        };
        if !descriptor.is::<TcpStream>() && !descriptor.is::<UnixStream>() {
            server.sockets.remove(i);
        }
        // FIXME own-goal: the entry for SignalReceiver remains, (due to returning None)
        // preventing the server from exiting!
        // but I want to keep it so that people can issue SIGINFO to get a list of remaining conns.
        // udp will just disappear without warning
        // datagram sockets should probably have a shutdown mode, where they stop accepting new
    }
}

fn print_state(server: &mut Server) {
    eprintln!("sockets: {}", server.sockets.len());
    for socket in &server.sockets {
        eprintln!("\t{:?}", socket);
    }
}
