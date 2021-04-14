use crate::assigned_addr::AssignedAddr;

use std::net::{Ipv4Addr, SocketAddr};
use std::cell::Cell;
use std::rc::Rc;
use std::mem;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The phase a client has reached in terms of being blocked from some resource.
///
/// Unlimited means the client is whitelisted or has done something to disable the limit.
/// New means the client hasn't been seen before or that this was the first operation (and it was permitted).
/// Allowed means the limit is partially used.
/// ReachedLimit means the client is at the limit - it's not blocked yet but any further usage will be.
/// CrossedLimit means one operation has been blocked or that the current operation is the first blocked.
/// AlreadyEexceeded means the client is blocked.
#[derive(Clone,Copy, Debug, PartialEq,Eq)]
#[repr(u16)]
pub enum ClientState { Unlimited, New, Allowed, ReachedLimit, CrossedLimit, AlreadyExceeded }
use ClientState::*;

impl ClientState {
    pub fn allowed(self) -> bool {
        match self {
            Unlimited | New | Allowed | ReachedLimit => true,
            CrossedLimit | AlreadyExceeded => false,
        }
    }
}

/// Additional wiggle room in which ReachedLimit is returned instead of ExceededLimit
const LAST_ALLOWWED_MARGIN: u32 = 100;
/// Is added to the size of each sent packet to ensure that empty packets are
/// counted. This should at minimum be the header size for ethernet + IPv6 + UDP,
/// but can be greater to try to account for the resources required to handle
/// the packet.
const UDP_PACKET_COST: u32 = 200; // guesstimate

#[derive(Clone, Debug)]
pub struct ClientStats {
    /// for use in log messages
    assigned_addr: AssignedAddr,
    whitelisted: bool,

    /// the state of the unacknowledged send limit.
    completed_handshake: Cell<ClientState>,
    /// from server to client.
    /// Inverted so that we don't need to know the limit for checking.
    available_unacknowledged_sent: Cell<u32>,

    /// resaources currently held associated with this client.
    /// This field is not periodically reset, or the limit could be
    /// circumvented by waiting.
    available_resources: Cell<u32>,
    /// flag set when resources limit is reached to only log the event once
    exceeded_resource_limits: Cell<bool>,
}
impl ClientStats {
    // private because ClientLimiter has the expiry time
    fn allow_unacknowledged_send(&self,  to_send: usize) -> ClientState {
        match self.completed_handshake.get() {
            Unlimited => Unlimited,
            AlreadyExceeded => AlreadyExceeded,
            CrossedLimit => {
                self.completed_handshake.set(AlreadyExceeded);
                AlreadyExceeded
            }
            ReachedLimit => {
                self.completed_handshake.set(CrossedLimit);
                eprintln!("LIMIT EXCEEDED: unacknowledged (UDP) send to {}", self.assigned_addr);
                CrossedLimit
            }
            was @ New | was @ Allowed => {
                // store smaller type, but perform calculation on usize just in case we
                // ever receive multi-gigabyte packets
                let packet_cost = to_send + UDP_PACKET_COST as usize;
                let before = self.available_unacknowledged_sent.get() as usize;
                if packet_cost > before + LAST_ALLOWWED_MARGIN as usize {
                    // limit reached - don't send packet. Also don't send future
                    // smaller packets, as that could be surprising
                    self.available_unacknowledged_sent.set(0);
                    self.completed_handshake.set(CrossedLimit);
                    eprintln!("LIMIT EXCEEDED: unacknowledged (UDP) send to {}", self.assigned_addr);
                    CrossedLimit
                } else {
                    let afterwards = before.saturating_sub(packet_cost) as u32;
                    self.available_unacknowledged_sent.set(afterwards);
                    if afterwards < LAST_ALLOWWED_MARGIN {
                        self.completed_handshake.set(ReachedLimit);
                        ReachedLimit
                    } else if was == New {
                        self.completed_handshake.set(Allowed);
                        New
                    } else {
                        Allowed
                    }
                }
            }
        }
    }

    pub fn get_unacknowledged_send_state(&self) -> ClientState {
        self.completed_handshake.get()
    }

    pub fn confirm_handshake_completed(&self) {
        self.completed_handshake.set(Unlimited);
    }

    pub fn request_resources(&self,  add: usize) -> bool {
        if let Some(afterwards) = self.available_resources.get().checked_sub(add as u32) {
            self.available_resources.set(afterwards);
            true
        } else if self.exceeded_resource_limits.get() {
            self.whitelisted
        } else {
            eprintln!("LIMIT EXCEEDED: resources associated with {}", self.assigned_addr);
            self.exceeded_resource_limits.set(true);
            false
        }
    }

    pub fn release_resources(&self,  sub: usize) {
        if !self.whitelisted {
            self.available_resources.set(self.available_resources.get() + sub as u32);
        }
    }
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
    /// uses secure default hasher to prevent colission in case an attacker has
    /// a bigger subnet.
    stats: HashMap<AssignedAddr, Rc<ClientStats>>,
    /// returned for whitelisted IPs to keep code simple
    whitelisted_stats: Rc<ClientStats>,
}

impl ClientLimiter {
    pub fn new(window: Duration,  udp_send: u32,  max_resources: u32) -> Self {
        ClientLimiter {
            window_length: window,
            unacknowledged_send_limit: udp_send,
            resources_limit: max_resources,

            window_end: Instant::now(), // expires immediately
            stats: HashMap::new(),
            whitelisted_stats: Rc::new(ClientStats {
                assigned_addr: AssignedAddr::from(Ipv4Addr::new(0, 0, 0, 0)),
                whitelisted: true,
                exceeded_resource_limits: Cell::new(true),
                available_resources: Cell::new(0), // could be any value
                available_unacknowledged_sent: Cell::new(!0),
                completed_handshake: Cell::new(Unlimited),
            }),
        }
    }

    fn client_default_values(&self,  assigned_addr: AssignedAddr) -> ClientStats {
        ClientStats {
            assigned_addr,
            whitelisted: false,
            available_unacknowledged_sent: Cell::new(self.unacknowledged_send_limit),
            exceeded_resource_limits: Cell::new(false),
            available_resources: Cell::new(self.resources_limit),
            completed_handshake: Cell::new(New),
        }
    }

    fn categorize_addr(addr: SocketAddr) -> Result<AssignedAddr, bool> {
        let assigned = AssignedAddr::from(addr);
        // multicast might require different limits, so block it unconditionally.
        if assigned.is_multicast() {
            Err(false)
        } else {
            Ok(assigned)
        }
    }

    /// handles whitelisting aand blacklisting of addresses, and
    /// removal of expired data
    fn register(&mut self,  addr: SocketAddr) -> Result<&Rc<ClientStats>, bool> {
        let assigned = Self::categorize_addr(addr)?;
        // clear old entries
        let now = Instant::now();
        if now > self.window_end {
            // not reusing the map is important to allow the allocation to shrink
            let prev = mem::replace(&mut self.stats, HashMap::new());
            self.stats = prev.into_iter()
                .inspect(|(ip, stats)| {
                    if stats.available_unacknowledged_sent.get() == 0
                    || stats.exceeded_resource_limits.get() {
                        eprintln!("Un-blacklisting {}", ip);
                    }
                    stats.available_unacknowledged_sent.set(self.unacknowledged_send_limit);
                    stats.exceeded_resource_limits.set(false);
                 })
                .filter(|&(_, ref stats)| stats.available_resources.get() != self.resources_limit )
                .collect();
            self.window_end = now + self.window_length;
        }

        let new = self.client_default_values(assigned);
        Ok(self.stats.entry(assigned).or_insert_with(|| Rc::new(new) ))
    }

    pub fn allow_unacknowledged_send(&mut self,  addr: SocketAddr,  to_send: usize) -> bool {
        match self.register(addr) {
            Ok(stats) => stats.allow_unacknowledged_send(to_send).allowed(),
            Err(true) => true,
            Err(false) => false,
        }
    }

    #[allow(unused)]
    pub fn confirm_handshake_completed(&mut self,  addr: SocketAddr) {
        if let Ok(stats) = self.register(addr) {
            stats.confirm_handshake_completed()
        }
    }

    pub fn get_unacknowledged_send_state(&self,  addr: SocketAddr) -> ClientState {
        match Self::categorize_addr(addr) {
            Ok(assigned) => match self.stats.get(&assigned) {
                Some(stats) => stats.get_unacknowledged_send_state(),
                None => New,
            },
            Err(true) => Unlimited,
            Err(false) => AlreadyExceeded,
        }
    }

    pub fn request_resources_ref(&mut self,  addr: SocketAddr,  add: usize)
    -> Option<Rc<ClientStats>> {
        match self.register(addr) {
            Ok(stats) if stats.request_resources(add) => Some(stats.clone()),
            Ok(_) => None,
            Err(true) => Some(self.whitelisted_stats.clone()),
            Err(false) => None,
        }
    }

    #[allow(unused)]
    pub fn request_resources(&mut self,  addr: SocketAddr,  add: usize) -> bool {
        match self.register(addr) {
            Ok(stats) => stats.request_resources(add),
            Err(true) => true,
            Err(false) => false,
        }
    }

    #[allow(unused)]
    pub fn release_resources(&mut self,  addr: SocketAddr,  sub: usize) {
        match self.register(addr) {
            Ok(stats) => stats.release_resources(sub),
            Err(true) => {},
            Err(false) => panic!("Tried to decrement counter for blacklisted IP {}", addr),
        }
    }
}
