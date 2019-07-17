use std::net::SocketAddr;

trait RefIterator {
    type Item: ?Sized;
    fn next(&mut self) -> Option<&Self::Item>;
}

trait Socket {
    fn try_send(&self, &[u8]) -> Option<usize>;
    fn boundaries_matter(&self) -> bool;
}

trait DelayedCompleter {
    fn try_send(&mut self,  &mut dyn Socket);
}

/*
datagram-based != connectionless, but stream-oriented => connection-oriented
sctp will be used in connection-less mode because that seems more efficient (less for the OS to manage)
must have:
 * echo not storing the response twice,
 * echo not copying from the receive buffer if response can be sent immediately
 * shutting down directions
 * doing protocol-specific things (udplite/dccp coverage flags, unix ancillary)
nice to have:
 * time32 not alowwing partial sends, being stateless with minimal overhead
 * not duplicating for stream-oriented, connection-based datagram and connectionless
 * support nesting (TCPMUX, SCTP-over-UDP)

Where should info for connection-less protocols be stored?
1. global:
   + simulates connection-based protocols
   - need common key type
   + one map instatiation
   * no effect on lookup time: hashmap is O(1), so already knowing
     protocol&Service doesn't help, but having to look it up again doesn't hurt either
   - need very general key
   - value must be trait object
   - repeated dispatch on protocol&service for value (already known from slab)
2. inside each service:
   - duplication of code, instatiations
   + doesn't need to store more than necessary
3. next to service
*/

#[derive(Clone,Copy, PartialEq,Eq,Hash, Debug)]
enum ProtocolCategory {Stream, DatagramConn, Connectionless}
impl ProtocolCategory {
    pub fn datagram_based(self) -> bool {
        match self {
            ProtocolCategory::Stream => false,
            ProtocolCategory::DatagramConn => true,
            ProtocolCategory::Connectionless => true,
        }
    }
    pub fn connection_oriented(self) -> bool {
        match self {
            ProtocolCategory::Stream => true,
            ProtocolCategory::DatagramConn => true,
            ProtocolCategory::Connectionless => false,
        }
    }
}

/// per-connection implementor of services
trait ConnServicer {
    /// Ok(false) => remove & drop
    fn handle(&mut self,  readiness: mio::Ready,  buffer: &mut[u8]) -> Result<bool, io::Error>;
}

/// socket that receives data or connections from possibly new clients
trait Receiver {}

trait Service {
    fn name(&self) -> &'static str;  // need self for objectability i think
    fn default_port(&self) -> u16;
    /// could have a method for each type, but then one needs to override multiple,
    /// and perf don't matter because this is only called at startup
    fn setup_receiver(&mut self,  receiver &mut dyn Receiver);
    /// for simple protocols
    /// Returning Cow allows avoiding allocations if the response can be sent
    /// immediately (content can both come from self and buffer), and returning
    /// a concrete type avoids extra boxing when storing together with connection
    /// Returned bool is true if connection should be closed after sending:
    ///  (always true for oneshots)
    fn general(&self,  buffer: &mut[u8],  received: usize)
    -> (Cow<[u8]>, bool);

    fn tcp_new(addr: SocketAddr,  conn: mio::tcp::TcpStream,  buffer: &mut[u8])
    -> (Option<Box<dyn Conn>>, bool);
    fn unix_stream_new(addr: &[u8],  conn: mio_uds::UnixStream,  buffer: &mut[u8])
    -> (Option<Box<dyn Conn>>, bool);
    fn udp_ready(socket: &mut mio::udp::UdpSocket,  buffer: &mut[u8])
    -> (Option<Box<dyn Conn>>, bool);
    fn unix_dgram_ready(socket: &mut mio_uds::UnixDatagram,  buffer: &mut[u8])
    -> (Option<Box<dyn Conn>>, bool);
}

// want to store data next to conn
// want to avoid downcast when type is known
// socketservice 

// Slab<Enum<(Rc<dyn Service>,ReceiverEnum),Box<dyn ConnServicer>>
// + easy implementation (usually only need to implement service)
// / mix of handling in event loop and behind dyn
// Slab<Box<dyn ReadinessHandler>>
// + everything behind dyn
// / double indirection for receivers, even if service can return custom types,
//    Box<Servicer>->Rc<ConcreteService>
//    but many services don't have any shared state
// - event loop cannot enforce limits alone

// forwarders might want to cancel other connections?

// this feels like it's getting close to tokio, and a bad mio example
// can i really not do this through helper functions instead?
// lots of helper functions also makes a bad example as the code becomes hard to follot

mod StructPocalypse {
    trait Service {
        fn identifiers() -> (&'static str, u16);
        // this will allow adding state as necessary
        fn setup_adjust(Vec<Box<Handler>>) -> Vec<Box<Handler>>;
        fn default_responder(&mut self,  ...) -> ...;
    }

    trait Handler {
        fn handle(&mut self,  self_token: Token,  readiness: Ready) -> bool remove;
    }
}

// mio is probably ok for one simple service, but this 


// service then socket: (enum Service(enum ${Service}Socket))
// the disadvantage of enum Socket(Service) is that many places must be updated
// to add a new service, and the code becomes spread out.
// with this, I might not need dynamic dispatch, and calling out to protocol
// helpers seems cleeaner than wrapping ourselves in them.
// adding a new protocol might be more work if no customization is applicable,
// but then those services can have common functions.
// this also avoids the dirty MqDiscard and later PipeDiscard
// Doesn't make mux much harder, as for conns it can replace with the appropiate type.

enum EchoSocket {
    TcpListener(TcpAccepter),
    TcpConn(TcpStream, VecDeque<Rc<[u8]>>),
    Udp(UdpSocket, HashMap<SocketAddr,VecDeque<Rc<[u8]>>>),
    UnixStreamListener(UnixAccepter),
    UnixStreamConn(UnixStream, VecDeque<Rc<[u8]>>),
    UnixDatagram(UnixSocket, HashMap<UnixSocketAddr,VecDeque<Rc<[u8]>>>),
}
enum Time32Socket {
    TcpListener(TcpAccepter),
    TcpConn(TcpStream),
    Udp(UdpSocket, HashSet<SocketAddr>),
    UnixStreamListener(UnixAccepter),
    UnixStreamConn(UnixStream),
    UnixDatagram(UnixSocket, HashSet<UnixSocketAddr>),
}
enum QotdSocket {
    TcpListener(TcpAccepter),
    TcpConn(TcpStream, Rc<[u8]>, u32),
    Udp(UdpSocket, HashSet<SocketAddr>),
    UnixStreamListener(UnixAccepter),
    UnixStreamConn(UnixStream, VecDeque<Rc<[u8]>>),
    UnixDatagram(UnixSocket, HashSet<UnixSocketAddr>),
}
enum MuxSocket {
    TcpListener(TcpAccepter),
    TcpConn(TcpStream), // is replaced with $type::TcpConn, // could use TCP_CORK
    UnixStreamConn(UnixStream),
    TcpConn(TcpStream), // is replaced with $type::UnixStreamConn

}

// RFC idea: OwnedObj, why can't the drop glue feield of a vtable be used to
// release the memory as well?
// You're already calling out to drop the value, might as well let it free the
// memory. 