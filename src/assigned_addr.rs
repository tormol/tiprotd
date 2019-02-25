#![allow(unused)]

use std::net::{IpAddr, Ipv6Addr, Ipv4Addr, SocketAddr, SocketAddrV6, SocketAddrV4};
use std::fmt::{Debug, Display, self};

/// The part of a public IP address not controlled by the average home network.
///
/// Useful for preventing UDP DDoS amplification / reflection attacks and other
/// forms of IP-based rate limiting.
/// 
/// # Details
/// 
/// It only stores 64 bits of IPv6 addressses, but (currently) stores
/// IPv4 addresses as-is. For most IPv6 addresses it is the most significant
/// half that is stored, but some ranges related to IPv4 transiton are
/// handled specially.
/// It fits both types into an `u64`, which should speed up comparisons and
/// hashes on 64bit architectures considerably compared to `std::net::IpAddr`.
///
/// # Rationale
/// 
/// On IPv6, everybody is supposed to get a /64 prefix, which they can manage
/// themselves. If every address is considered independently, an atacker would
/// have 2^64 addresses at his disposal which would render any limit pointless.
/// (He could even use a different IP for every request).
/// For UDP DDoS reflection, it would allow an attacker to reach the target's
/// network through 2^64 addresses.
/// People might have prefixes bigger than /64, but as long as this limits an
/// attacker to less than 2^16 addresses it helps.
///
/// This is intended for use by servers and relies on local routers or
/// firewalls to not allow through local addresses from the public interface.
/// It cannot protect against attackers who control significant address blocks
/// or can manipulate routes. For that one must either blacklist ranges or
/// depend on bigger players to handle the incident.
#[derive(Clone,Copy, PartialEq,Eq, Hash)]
// Fitting IPv4 addresses into the first half of IPv6 isn't as easy as I expected.
// even though 0::/8 is reserved.
// Here's the current mapping, it might not be the best one:
// 0x0001_0000_0000_0000..=0xffff_ffff_ffff_ffff => 1-ffff:xxxx:xxxx:xxxx::/64
// 0x0000_0000_0100_0000..=0x0000_0000_ffff_ffff => 1-255.xx.xx.xx/32
// 0x0000_ff9b_0000_0000..=0x0000_ff9b_ffff_ffff => 64:ff9b::xx.xx.xx.xx/128
// 0x0000_ffff_0000_0000..=0x0000_ffff_ffff_ffff => ::ffff:0::xx.xx.xx.xx/128
// 0x0000_0000_0000_0000..=0x0000_0000_0000_0001 => ::/128 and ::1/128
// _ => whatever makes the code simpler
pub struct AssignedAddr(u64);

impl AssignedAddr {
    pub fn is_ipv4(self) -> bool {
        self.0 <= 0x0000_0000_ff_ff_ff_ff && self.0 >= 0x0000_0000_00_01_00_00
    }
    pub fn is_ipv6(self) -> bool {
        !self.is_ipv4()
    }
    pub fn is_multicast(self) -> bool {
        let v6 = self.0 & 0xff00_0000_0000_0000 == 0xff00_0000_0000_0000;
        let v4 = self.0 & 0xffff_ffff_f0_00_00_00 == 0x0000_0000_e0_00_00_00;
        v6 || v4
    }
    pub fn is_loopback(self) -> bool {
        self.0 == 1 || self.0 >> 24 == 127
    }
    pub fn subnet_ip(self) -> IpAddr {
        if self.is_ipv4() {
            IpAddr::V4(Ipv4Addr::from(self.0 as u32))
        } else if self.0 & 0xffff_0000_00_00_00_00 != 0 {
            // normal IPv6
            IpAddr::V6(Ipv6Addr::from((self.0 as u128) << 64))
        } else if self.0 >> 32 == 0xff9b {
            // well-known 
            let v4_ab = (self.0 >> 16) as u16;
            let v4_cd = (self.0 >> 0) as u16;
            IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, v4_ab, v4_cd))
        } else {
            // SIIT or other
            let v4_ab = (self.0 >> 16) as u16;
            let v4_cd = (self.0 >> 0) as u16;
            let prefix = (self.0 >> 32) as u16;
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, prefix, 0, v4_ab, v4_cd))
        }
    }
    pub fn subnet_size(self) -> u32 {
        match self.0 {
            0x0001_0000_0000_0000..=0xffff_ffff_ffff_ffff => 64, // normal IPv6
            0x0000_0000_00_01_00_00..=0x0000_0000_ff_ff_ff_ff => 32, // IPv4
            _ => 128, // other
        }
        // or alternatively
        //[64, 128, 32, 128][(self.0 | 1).leading_zeros() as usize / 16]
    }
    pub fn covers<A: Into<IpAddr>>(self,  ip: A) -> bool {
        self == AssignedAddr::from(ip.into())
    }
}

impl Debug for AssignedAddr {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, fmtr)
    }
}

impl Display for AssignedAddr {
    fn fmt(&self,  fmtr: &mut fmt::Formatter) -> fmt::Result {
        write!(fmtr, "{}/{}", self.subnet_ip(), self.subnet_size())
    }
}

impl From<Ipv6Addr> for AssignedAddr {
    /// drops the host part
    fn from(ipv6: Ipv6Addr) -> Self {
        let whole = u128::from(ipv6);
        let prefix = (whole >> 64) as u64;

        const TRANSITION_MASK: u128 = 0xffff_ffff_ffff_ffff__ffff_ffff_0000_0000;
        // ::ffff.a.b.c.d/96, used by sockets to accept IPv4 connections to :: and ::1
        // (these addresses should never leave the host)
        //const MAPPED_PREFIX: u128 = 0x0000_0000_0000_0000__0000_ffff_0000_0000;
        // ::ffff:0:a.b.c.d/96, one form of IPv4-over-IPv6 routing
        //const SIIT_PREFIX: u128 = 0x0000_0000_0000_0000__ffff_0000_0000_0000;
        // 64:ff9b::a.b.c.d/96, 
        const WELLKNOWN_PREFIX: u128 = 0x0064_ff9b_0000_0000__0000_0000_0000_0000;
        // teredo tunneling (2001:0:a.b.c.d::*/32) doesn't need any special casing
        // same for 6to4 (2002:a.b.c.d::*//16)
        // 6rd is impossible to detect, but should give customers smaller prefix

        if prefix == 0 || whole & TRANSITION_MASK == WELLKNOWN_PREFIX {
            // IPv4 mapped, SIIT, 6to4 "well-known" prefix, or loopback.
            // To prevent SIIT addresses from being mixed up with multicast addresses,
            // ensure that the most significant byte is zero
            // Avoid merging different forms of transition addresses as it could be
            // used to block clients with the actual address.
            let bare = whole as u64 & 0x0000_0000_ff_ff_ff_ff;
            // move 0:xxxx:: to ::xxxx:0.0.0.0; selects ff9b from well-known and is 0 otherwise
            let u1 = (whole >> 64) as u64 & 0x0000_ffff_00_00_00_00;
            // move ::xxxx:0:0.0.0.0 to ::xxxx:0.0.0.0; selects ffff from SIIT and is 0 otherwise
            let u4 = (whole >> 8) as u64 & 0x0000_ffff_00_00_00_00;
            AssignedAddr(bare | u1 | u4)
        } else {
            // doesn't need any special casing
            AssignedAddr(prefix)
        }
    }
}

impl From<Ipv4Addr> for AssignedAddr {
    fn from(ipv4: Ipv4Addr) -> AssignedAddr {
        AssignedAddr(u64::from(u32::from(ipv4)))
    }
}

impl From<IpAddr> for AssignedAddr {
    /// drops the host part of IPv6 addresses but preserves IPv4 addresses
    fn from(ip: IpAddr) -> AssignedAddr {
        match ip {
            IpAddr::V4(ipv4) => Self::from(ipv4),
            IpAddr::V6(ipv6) => Self::from(ipv6),
        }
    }
}

impl From<SocketAddrV6> for AssignedAddr {
    /// drops the port number and the host part of the IP
    fn from(sockaddrv6: SocketAddrV6) -> AssignedAddr {
        Self::from(*sockaddrv6.ip())
    }
}

impl From<SocketAddrV4> for AssignedAddr {
    /// drops the port number
    fn from(sockaddrv4: SocketAddrV4) -> AssignedAddr {
        Self::from(*sockaddrv4.ip())
    }
}

impl From<SocketAddr> for AssignedAddr {
    /// drops the port number, and the host part of IPv6 addresses
    fn from(sockaddr: SocketAddr) -> AssignedAddr {
        match sockaddr {
            SocketAddr::V4(sockaddrv4) => Self::from(*sockaddrv4.ip()),
            SocketAddr::V6(sockaddrv6) => Self::from(*sockaddrv6.ip()),
        }
    }
}


/// Is the IP address multicast with a scope smaller than global?
///
/// Returns `None` for non-multicast addresses, `true` for addresses that are
/// known to be limited to organization or smaller scopes, and `false` for
/// known global, unspecified or reserved multicast addresses.
///
/// Based on https://en.wikipedia.org/wiki/Multicast_address
pub fn is_local_multicast<A: Into<IpAddr>>(addr: A) -> Option<bool> {
    match addr.into() {
        IpAddr::V6(ipv6) => {
            match ipv6.segments()[0] & 0xff_0f {
                0x00_00..=0xfe_ff => None, // not multicast
                0xff_01 => Some(true), // interface-local,
                0xff_02 => Some(true), // link-local
                0xff_03 => Some(true), // IPv4 local scope
                0xff_04 => Some(true), // admin-local
                0xff_05 => Some(true), // site-local
                0xff_08 => Some(true), // organization-local
                _ => Some(false), // global, reserved or unspecified
            }
        }
        IpAddr::V4(ipv4) => {
            match u32::from(ipv4) {
                0xe0_00_00_00..=0xe0_00_00_ff => Some(true), // local subnetwork 224.0.0.0/24
                0xef_00_00_00..=0xef_ff_ff_ff => Some(true), // administratively scoped 239.0.0.0/8
                0xe0_00_01_00..=0xee_ff_ff_ff => Some(false), // all other 224.0.0.0/4
                _ => None, // not multicast
            }
        }
    }
}
