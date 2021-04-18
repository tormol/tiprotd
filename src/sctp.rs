use std::io;
use std::net::ToSocketAddrs;
use std::os::unix::io::{FromRawFd, AsRawFd, RawFd};
use std::ops::Deref;
use std::fmt::{self, Debug, Formatter};

use sctp_crate::SctpEndpoint;
use mio::{event::Source, unix::SourceFd, Registry, Token, Interest};
use libc::{ioctl, FIONBIO};

pub struct SctpSocket(SctpEndpoint);

impl SctpSocket {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let endpoiint = SctpEndpoint::bind(addr)?;
        #[cfg(unix)]
        unsafe {
            if ioctl(endpoiint.as_raw_fd(), FIONBIO, &mut 1) == -1{
                return Err(io::Error::last_os_error());
            }
        }
        Ok(SctpSocket(endpoiint))
    }
    pub fn bind_multiple<A: ToSocketAddrs>(addrs: &[A]) -> Result<Self, io::Error> {
        let endpoiint = SctpEndpoint::bindx(addrs)?;
        #[cfg(unix)]
        unsafe {
            if libc::ioctl(endpoiint.as_raw_fd(), libc::FIONBIO, &mut 1) == -1{
                return Err(io::Error::last_os_error());
            }
        }
        Ok(SctpSocket(endpoiint))
    }
}

impl Source for SctpSocket {
    fn register(&mut self,  registry: &Registry,  token: Token,  interest: Interest)
    -> Result<(), io::Error> {
        SourceFd(&self.0.as_raw_fd()).register(registry, token, interest)
    }
    fn reregister(&mut self,  registry: &Registry,  token: Token,  interest: Interest)
    -> Result<(), io::Error> {
        SourceFd(&self.0.as_raw_fd()).reregister(registry, token, interest)
    }
    fn deregister(&mut self,  registry: &Registry) -> Result<(), io::Error> {
        SourceFd(&self.0.as_raw_fd()).deregister(registry)
    }
}

impl AsRawFd for SctpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for SctpSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        SctpSocket(SctpEndpoint::from_raw_fd(fd))
    }
}

impl Deref for SctpSocket {
    type Target = SctpEndpoint;
    fn deref(&self) -> &SctpEndpoint {
        &self.0
    }
}

impl Debug for SctpSocket {
    fn fmt(&self,  fmtr: &mut Formatter) -> fmt::Result {
        fmtr.debug_struct("SctpSocket")
            .field("fd", &self.0.as_raw_fd())
            .finish()
    }
}
