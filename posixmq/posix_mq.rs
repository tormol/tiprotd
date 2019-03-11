use std::{io, mem, ptr};
use std::ffi::CStr;
#[cfg(any(target_os="linux", feature="mio"))]
use std::os::unix::io::{AsRawFd, RawFd};

extern crate libc;
use libc::{c_int, c_uint, c_long};
use libc::{mqd_t, mq_attr, mq_open, mq_send, mq_receive, close, mq_unlink};
use libc::{O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NONBLOCK, O_CLOEXEC};

#[cfg(feature="mio")]
extern crate mio;
#[cfg(feature="mio")]
use mio::event::Evented;
#[cfg(feature="mio")]
use mio::unix::EventedFd;
#[cfg(feature="mio")]
use mio::{Ready, Poll, PollOpt, Token};

#[derive(Clone,Copy, PartialEq,Eq)]
pub struct OpenOptions {
    mode: c_int,
    permissions: u32,
    capacity: usize,
    max_msg_len: usize,
}

// Cannot use std::fs's because it doesn't expose getters
impl OpenOptions {
    fn new(mode: c_int) -> Self {
        OpenOptions {
            mode,
            permissions: 0,
            capacity: 0,
            max_msg_len: 0,
        }
    }
    pub fn readonly() -> Self {
        OpenOptions::new(O_RDONLY)
    }
    pub fn writeonly() -> Self {
        OpenOptions::new(O_WRONLY)
    }
    pub fn readwrite() -> Self {
        OpenOptions::new(O_RDWR)
    }

    pub fn or_create(&mut self,  permissions: u32,  capacity: usize,  max_msg_len: usize)
    -> &mut Self {
        self.mode |= O_CREAT;
        self.mode &= !O_EXCL;
        self.permissions = permissions;
        self.capacity = capacity;
        self.max_msg_len = max_msg_len;
        self
    }
    pub fn create_new(&mut self,  permissions: u32,  capacity: usize,  max_msg_len: usize)
    -> &mut Self {
        self.mode |= O_CREAT | O_EXCL;
        self.permissions = permissions;
        self.capacity = capacity;
        self.max_msg_len = max_msg_len;
        self
    }

    pub fn nonblocking(&mut self) -> &mut Self {
        self.mode |= O_NONBLOCK;
        self
    }
    pub fn cloexec(&mut self) -> &mut Self {
        self.mode |= O_CLOEXEC;
        self
    }
}

pub struct PosixQueue {
    mqd: mqd_t
}

impl PosixQueue {
    pub fn open(name: &CStr,  opts: &OpenOptions) -> Result<Self, io::Error> {
        let mut capacites = unsafe { mem::zeroed::<mq_attr>() };
        let mut capacites_ref = None;
        if opts.capacity != 0 || opts.max_msg_len != 0 {
            capacites.mq_maxmsg = opts.capacity as c_long;
            capacites.mq_msgsize = opts.max_msg_len as c_long;
            capacites_ref = Some(&mut capacites);
        }
        Self::new_raw(name, opts.mode, opts.permissions as c_int, capacites_ref)
    }

    pub fn new_raw(name: &CStr,  opts: c_int,  perms: c_int,  capacities: Option<&mut mq_attr>)
    -> Result<Self, io::Error> {
        let name = name.as_ptr();
        let capacities = match capacities {
            Some(capacities) => capacities as *mut mq_attr,
            None => ptr::null_mut::<mq_attr>(), // default
        };
        let mqd = unsafe { mq_open(name, opts, perms, capacities) };
        if mqd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PosixQueue { mqd })
    }

    pub fn send(&self,  priority: u32,  msg: &[u8]) -> Result<usize, io::Error> {
        let bptr = msg.as_ptr() as *const i8;
        let sent = unsafe { mq_send(self.mqd, bptr, msg.len(), priority as c_uint) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sent as usize)
    }

    pub fn receive(&self,  msgbuf: &mut [u8]) -> Result<(usize,u32), io::Error> {
        let bptr = msgbuf.as_mut_ptr() as *mut i8;
        let mut priority = 0 as c_uint;
        let len = unsafe { mq_receive(self.mqd, bptr, msgbuf.len(), &mut priority) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        // c_uint is unlikely to differ from u32, but even if it's bigger, the
        // range of supported values will likely be far smaller.
        Ok((len as usize, priority as u32))
    }
}

// I'd expect this to work everywhere, but just in case I'll only implement it
// on platforms where I know it works or when it's required by another feature.
#[cfg(any(target_os="linux", features="mio"))]
impl AsRawFd for PosixQueue {
    fn as_raw_fd(&self) -> RawFd {
        self.mqd as RawFd
    }
}

impl Drop for PosixQueue {
    fn drop(&mut self) {
        unsafe { close(self.mqd) };
    }
}

#[cfg(feature="mio")]
impl Evented for PosixQueue {
    fn register(&self,  poll: &Poll,  token: Token,  interest: Ready,  opts: PollOpt)
    -> Result<(), io::Error> {
        EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }
    fn reregister(&self,  poll: &Poll,  token: Token,  interest: Ready,  opts: PollOpt)
    -> Result<(), io::Error> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }
    fn deregister(&self,  poll: &Poll) -> Result<(), io::Error> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}

pub fn unlink<N: AsRef<CStr>>(name: N) -> Result<(), io::Error> {
    let name = name.as_ref().as_ptr();
    let ret = unsafe { mq_unlink(name) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
