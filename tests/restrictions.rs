//! Test that client limits and unix socket requirements are enforced.

use std::net::{Ipv4Addr, TcpStream, UdpSocket};
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::fs::remove_file;
#[cfg(unix)]
use std::env::{current_dir, set_current_dir};
use std::time::Duration;
use std::thread::sleep;
use std::usize;
use std::io::{ErrorKind::*, Read, Write};

// will break if any other test in this file uses tcp://127.0.0.1
#[test]
fn udp_ddos_amplification_prevention() {
    let mut buf = [0; 200];
    let bad = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 1234)).unwrap();
    bad.set_read_timeout(Some(Duration::new(0, 50_000_000))).unwrap();
    for i in 0..5000 {
        let port = 10000 + if i%2 == 0 {17} else {37};
        bad.send_to(&b"abcdefgh"[..i%8], (Ipv4Addr::new(127, 0, 0, 1), port)).unwrap();
        // sleep a bit so that packets aren't discarded
        sleep(Duration::new(0, 125_000));
    }
    let mut received = 0;
    for i in 0..5000 {
        received = i;
        match bad.recv_from(&mut buf) {
            Ok((_, _)) => {}
            Err(ref e) if e.kind() == TimedOut => {break;} // passed
            Err(ref e) if e.kind() == WouldBlock => {break;} // passed
            Err(e) => panic!("Unexpected udp receive error: {}", e)
        }
    }
    assert_ne!(received, 5000, "Udp send limit not reached");

    // try to echo (different protocol) from a different port on the same IP
    let echo = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 5678)).unwrap();
    echo.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    echo.send_to("1234567890".as_bytes(), (Ipv4Addr::new(127, 0, 0, 1), 10007)).unwrap();
    assert_eq!(echo.recv_from(&mut[0; 30]).unwrap_err().kind(), WouldBlock);

    // try from a different IP
    let other = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 5678)).unwrap();
    other.send_to("1234567890".as_bytes(), (Ipv4Addr::new(127, 0, 0, 1), 10007)).unwrap();
    assert_eq!(other.recv_from(&mut[0; 30]).unwrap().0, 10);
    assert_eq!(other.recv_from(&mut[0; 30]).unwrap().0, 10);
    other.send_to(&[], (Ipv4Addr::new(127, 0, 0, 1), 10037)).unwrap();
    assert_eq!(other.recv_from(&mut[0; 30]).unwrap().0, 4);

    // get IP whitelisted by establishing a TCP connection.
    let mut handshake = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 1), 10009)).unwrap();
    // ensure the server receives the connection before the next UDP packet
    assert_eq!(handshake.read(&mut[0; 10]).unwrap(), 0);
    handshake.shutdown(std::net::Shutdown::Both).unwrap();
    drop(handshake);

    // try again
    // FIXME heisenbug: the send isn't noticed unless server is run through strace
    // bad.send_to(&[], (Ipv4Addr::new(127, 0, 0, 1), 10007)).unwrap();
    // assert!(bad.recv_from(&mut[0; 30]).unwrap().0 > 0);
}

// hits the resource limit for ::1 temporarily, which might cause
// other tests in this file to fail.
#[test]
fn tcp_echo_max_unsent() {
    // use ~half of the capacity
    let mut first = TcpStream::connect(("::1", 10007)).unwrap();
    first.write_all(&vec![b'O'; 100*1024]).unwrap();
    first.read(&mut[0; 16]).unwrap();

    // can send a lot to discard
    let mut discard = TcpStream::connect(("::1", 10009)).unwrap();
    for _ in 0..10 {
        discard.write_all(&vec![0; 100*1024]).unwrap();
    }

    // use more of the capacity
    let mut second = TcpStream::connect(("::1", 10007)).unwrap();
    second.write_all(&vec![b'o'; 100*1024]).unwrap();
    second.read(&mut[0; 16]).unwrap();

    // test another connection
    let mut still_fine = TcpStream::connect(("::1", 10037)).unwrap();
    assert_eq!(still_fine.read_to_end(&mut vec![]).unwrap(), 4);
    drop(still_fine);

    // send the remaining and test that limit is now exceeded
    eprintln!("{}", second.write_all(&vec![b'0'; 8*1024*1024]).unwrap_err());
    if let Ok(bytes @ 300_000..=usize::MAX) = second.read_to_end(&mut Vec::new()) {
        panic!("Received too many bytes ({}) from `second` after exceeding limit", bytes);
    }
}

// will break any other unix socket test in this file, but there are none
#[cfg(unix)]
#[test]
fn unix_dgram_absolute_path() {
    let server_socket_abs = current_dir().unwrap().join("qotd_dgram.socket");
    set_current_dir("/tmp/").unwrap();
    let _ = remove_file("echo_dgram.socket");
    let relative = UnixDatagram::bind("echo_dgram.socket").unwrap();
    relative.send_to("hello".as_bytes(), server_socket_abs).unwrap();
    relative.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(relative.recv_from(&mut[0; 1]).unwrap_err().kind(), WouldBlock);
    remove_file("echo_dgram.socket").unwrap();
}
