use crate::assigned_addr::AssignedAddr;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Is added to the size of each sent packet to ensure that empty packets are
/// counted. This should at minimum be the header size for ethernet + IPv6 + UDP,
/// but can be greater to try to account for the resources required to handle
/// the packet.
const UDP_PACKET_COST: u32 = 200; // guesstimate

/// Imposes limits on clients to prevent various forms of denial-of-service.
/// 
/// What is considered a client is more coarse-grained than a `SocketAddr`,
/// as an attacker can create multiple of those. See [`AssignedAddr`](struct.AssignedAddr.html)
/// for details.
/// 
/// # Memory span
/// 
/// At some point, old traffic must be forgotten. This includes old "bans", or
/// we would need an unreasonable amount of space and also permaban unrelated
/// clients within the same address range.
///
/// For simplicity, all clients use the same timeout
///
/// # Limits
///
/// * The amount of sent UDP traffic to prevent DDoS amplification or
///   indirection. This is the most important limit as it affects other
///   computers.
/// * TODO unsent TCP data
/// * TODO TCP connections
#[derive(Debug)]
pub struct ClientLimiter {
    window_length: Duration,
    unacknowledged_send_limit: u32,

    window_end: Instant,
    // use secure default hasher because an attacker might have a bigger subnet
    unacknowledged_sent: HashMap<AssignedAddr,u32>,
}

impl ClientLimiter {
    pub fn new(window: Duration,  udp_send_limit: u32) -> Self {
        ClientLimiter {
            window_length: window,
            unacknowledged_send_limit: udp_send_limit,

            window_end: Instant::now(), // expires immediately
            unacknowledged_sent: HashMap::new(),
        }
    }
    pub fn allow_unacknowledged_send(&mut self,  addr: SocketAddr,  to_send: usize) -> bool {
        let assigned = AssignedAddr::from(addr);
        // multicast might require different limits, so block it unconditionally.
        if assigned.is_multicast() {
            return false;
        }
        // clear old entries
        let now = Instant::now();
        if now > self.window_end {
            // reallocate to not leak
            self.unacknowledged_sent = HashMap::new();
            self.window_end = now + self.window_length;
        }
        // store smaller type, but perform calculation on usize just in case we
        // ever receive multi-gigabyte packets
        let packet_cost = to_send + UDP_PACKET_COST as usize;
        let count = self.unacknowledged_sent.entry(assigned).or_insert(0);
        if *count as usize + packet_cost <= self.unacknowledged_send_limit as usize {
            *count += packet_cost as u32;
            true
        } else if *count == self.unacknowledged_send_limit {
            // limit previously reached - don't log
            false
        } else {
            // limit reached - don't send packet. Also don't send future
            // smaller packets, as that could be surprising
            *count = self.unacknowledged_send_limit;
            eprintln!("LIMIT EXCEEDED: unacknowledged (UDP) send to {}", assigned);
            false
        }
    }
}
