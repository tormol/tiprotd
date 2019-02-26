use crate::assigned_addr::AssignedAddr;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Is added to the size of each sent packet to ensure that empty packets are
/// counted. This should at minimum be the header size for ethernet + IPv6 + UDP,
/// but can be greater to try to account for the resources required to handle
/// the packet.
const UDP_PACKET_COST: u32 = 200; // guesstimate

#[derive(Clone,Copy, Default, Debug)]
struct ClientStats {
    /// from server to client
    unacknowledged_sent: u32,
    /// flag set when resources limit is reached to only log the event once
    exceeded_resource_limits: bool,

    /// resources currently held associated with this client
    /// This field is never reset (or the limit could be circumvented by waiting)
    /// Storing this in a separate map could reduce resource usage for
    /// stream-only clients as zero values does not need to be remembered,
    /// but if we ever start imposing time-based limits on streams storing
    /// everything in one map becomes more efficient.
    resources: u32,
}

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
/// * non-O(1) resources currently used to maintain state for the client, such
///   as unsent bytes and open connections
#[derive(Debug)]
pub struct ClientLimiter {
    window_length: Duration,
    unacknowledged_send_limit: u32,
    resources_limit: u32,

    window_end: Instant,
    /// Resources that hIs cleared periodically
    /// uses secure default hasher because an attacker might have a bigger subnet
    stats: HashMap<AssignedAddr,ClientStats>,
}

impl ClientLimiter {
    pub fn new(window: Duration,  udp_send: u32,  max_resources: u32) -> Self {
        ClientLimiter {
            window_length: window,
            unacknowledged_send_limit: udp_send,
            resources_limit: max_resources,

            window_end: Instant::now(), // expires immediately
            stats: HashMap::new(),
        }
    }
    /// handles whitelisting aand blacklisting of addresses, and
    /// removal of expired data
    fn register(&mut self,  addr: SocketAddr) -> Result<&mut ClientStats, bool> {
        let assigned = AssignedAddr::from(addr);
        // multicast might require different limits, so block it unconditionally.
        if assigned.is_multicast() {
            return Err(false);
        }
        // clear old entries
        let now = Instant::now();
        if now > self.window_end {
            // not reusing the map is important to allow the allocation to shrink
            self.stats = self.stats.iter()
                .filter(|&(_,v)| v.resources != 0 )
                .map(|(&k, &ClientStats { resources, .. })| {
                    (k, ClientStats {
                        resources,
                        ..ClientStats::default()
                    })
                 })
                .collect();
            self.window_end = now + self.window_length;
        }
        Ok(self.stats.entry(assigned).or_default())
    }

    pub fn allow_unacknowledged_send(&mut self,  addr: SocketAddr,  to_send: usize) -> bool {
        let limit = self.unacknowledged_send_limit; // make borrowck happy
        let count = match self.register(addr) {
            Ok(stats) => &mut stats.unacknowledged_sent,
            Err(special) => return special
        };
        // store smaller type, but perform calculation on usize just in case we
        // ever receive multi-gigabyte packets
        let packet_cost = to_send + UDP_PACKET_COST as usize;
        if *count as usize + packet_cost <= limit as usize {
            *count += packet_cost as u32;
            true
        } else if *count == limit {
            // limit previously reached - don't log
            false
        } else {
            // limit reached - don't send packet. Also don't send future
            // smaller packets, as that could be surprising
            *count = limit;
            eprintln!("LIMIT EXCEEDED: unacknowledged (UDP) send to {}", AssignedAddr::from(addr));
            false
        }
    }

    pub fn request_resources(&mut self,  addr: SocketAddr,  add: usize) -> bool {
        let limit = self.resources_limit; // make borrowck happy
        let (resources, already_reached) = match self.register(addr) {
            Ok(stats) => (&mut stats.resources, &mut stats.exceeded_resource_limits),
            Err(special) => return special
        };
        let after = *resources as usize + add;
        let ok = !*already_reached && after <= limit as usize;
        if ok {
            *resources = after as u32;
        } else if !*already_reached {
            // log when limit is reached, but only once
            eprintln!("LIMIT EXCEEDED: resources associated with {}", AssignedAddr::from(addr));
            *already_reached = true;
        }
        ok
    }

    pub fn release_resources(&mut self,  addr: SocketAddr,  sub: usize) {
        match self.register(addr) {
            Ok(stats) => stats.resources -= sub as u32,
            Err(true) => {},
            Err(false) => unreachable!("Tried to decrement counter for blacklisted IP {}", addr),
        }
    }
}
