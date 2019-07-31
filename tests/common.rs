//! Test standard protocols using types available in std.
//! Dosen't try to provoke intra-protocol&service bugs, but
//! does test some paralellism due to tests running in paralell.
//! These tests should run on macOS and the non-unix ones on windows.

use std::io::{ErrorKind::*, Read, Write};
use std::net::*;
#[cfg(unix)]
use std::{os::unix::net::*, fs::remove_file, env::current_dir};
use std::str;
use std::time::Duration;

macro_rules! assert_timeout {($op:expr) => {
    match $op {
        Err(ref e) if e.kind() == TimedOut || e.kind() == WouldBlock => {}
        Err(e) => panic!("{} did not time out but failed with {}", stringify!($op), e),
        Ok(ok) => panic!("{} unexpectedly produced {:?}", stringify!($op), ok)
    }
}}

#[test]
fn tcp_echo() {
    let mut buf = [0; 100];
    let mut stream = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 1), 10007)).unwrap();
    stream.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_timeout!(stream.read(&mut buf));
    assert_eq!(stream.write(&b"echo"[..]).unwrap(), 4);
    assert_eq!(stream.read(&mut buf).unwrap(), 8);
    assert_eq!(stream.write(&b"baah"[..]).unwrap(), 4);
    assert_eq!(stream.read(&mut buf[8..]).unwrap(), 8);
    assert_eq!(str::from_utf8(&buf[..16]).unwrap(), "echoechobaahbaah");
    assert_timeout!(stream.read(&mut buf));
    stream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(stream.read(&mut buf).unwrap(), 0);
}

#[test]
fn udp_echo() {
    let mut buf = [0; 100];
    let conn = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    conn.connect((Ipv4Addr::new(127, 0, 0, 1), 10007)).unwrap();
    assert_eq!(conn.send(&b"echo"[..]).unwrap(), 4);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"echo"[..]);
    assert_eq!(conn.send(&b"baah"[..]).unwrap(), 4);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"echo"[..]);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"baah"[..]);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"baah"[..]);
}

#[cfg(unix)]
#[test]
fn unix_stream_echo() {
    let mut buf = [0; 100];
    let mut stream = UnixStream::connect("echo.socket").unwrap();
    stream.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_timeout!(stream.read(&mut buf));
    assert_eq!(stream.write(&b"echo"[..]).unwrap(), 4);
    assert_eq!(stream.read(&mut buf).unwrap(), 8);
    assert_eq!(stream.write(&b"baah"[..]).unwrap(), 4);
    assert_eq!(stream.read(&mut buf[8..]).unwrap(), 8);
    assert_eq!(buf[..16], b"echoechobaahbaah"[..]);
    assert_timeout!(stream.read(&mut buf));
    stream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(stream.read(&mut buf).unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn unix_dgram_echo() {
    let mut buf = [0; 100];
    let name = current_dir().unwrap().join("echo_dgram_test.socket");
    let _ = remove_file(&name);
    let conn = UnixDatagram::bind(&name).unwrap();
    conn.connect("echo_dgram.socket").unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send(&b"echo"[..]).unwrap(), 4);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"echo"[..]);
    assert_eq!(conn.send(&b"baah"[..]).unwrap(), 4);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"echo"[..]);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"baah"[..]);
    assert_eq!(conn.recv(&mut buf).unwrap(), 4);
    assert_eq!(buf[..4], b"baah"[..]);
    remove_file(&name).unwrap();
}


#[test]
fn tcp_discard() {
    let mut stream = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 1), 10009)).unwrap();
    stream.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    stream.write(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    match stream.read(&mut[0; 1]) {
        Ok(0) => (),
        Err(ref e) if e.kind() == TimedOut || e.kind() == WouldBlock => (),
        wrong => panic!("Unexpected tcp discard read result: {:?}", wrong),
    }
}

#[test]
fn udp_discard() {
    let mut buf = [0; 1000];
    let conn = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    conn.connect((Ipv4Addr::new(127, 0, 0, 1), 10009)).unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_timeout!(conn.recv(&mut buf));
    assert_eq!(conn.send(&buf).unwrap(), 1000);
    assert_timeout!(conn.recv(&mut buf));
}

#[cfg(unix)]
#[test]
fn unix_stream_discard() {
    let mut stream = UnixStream::connect("discard.socket").unwrap();
    stream.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    stream.write(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    match stream.read(&mut[0; 1]) {
        Ok(0) => (),
        Err(ref e) if e.kind() == TimedOut || e.kind() == WouldBlock => (),
        wrong => panic!("Unexpected unix stream discard read result: {:?}", wrong),
    }
}

#[cfg(unix)]
#[test]
fn unix_dgram_discard() {
    let mut buf = [0; 1000];
    let name = current_dir().unwrap().join("discard_dgram_test.socket");
    let _ = remove_file(&name);
    let conn = UnixDatagram::bind(&name).unwrap();
    conn.connect("discard_dgram.socket").unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_timeout!(conn.recv(&mut buf));
    assert_eq!(conn.send(&buf).unwrap(), buf.len());
    assert_timeout!(conn.recv(&mut buf));
    remove_file(&name).unwrap();

    let conn = UnixDatagram::bind("").unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send_to(&buf, "discard_dgram.socket").unwrap(), buf.len());
    assert_timeout!(conn.recv(&mut buf));
}


#[test]
fn tcp_qotd() {
    let mut stream = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 1), 10017)).unwrap();
    let mut buf = [255; 120];
    assert_eq!(stream.read(&mut buf[..10]).unwrap(), 10);
    let len = 10 + stream.read(&mut buf[10..]).unwrap();
    assert!(len < 100);
    assert_eq!(stream.read(&mut[0; 1]).unwrap(), 0);
    assert!(buf[..len].is_ascii());
}

#[test]
fn udp_qotd() {
    let mut buf = [0; 1024];
    let conn = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    conn.connect((Ipv4Addr::new(127, 0, 0, 1), 10017)).unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send(&b""[..]).unwrap(), 0);
    let len_a = conn.recv(&mut buf[..512]).unwrap();
    assert_eq!(conn.send(&b"0"[..]).unwrap(), 1);
    let len_b = conn.recv(&mut buf[512..]).unwrap();
    assert!(buf[..len_a].is_ascii());
    assert_eq!(buf[..len_a], buf[512..512+len_b]);
    assert_timeout!(conn.recv(&mut buf));
}

#[cfg(unix)]
#[test]
fn unix_stream_qotd() {
    let mut stream = UnixStream::connect("qotd.socket").unwrap();
    let mut buf = [255; 120];
    assert_eq!(stream.read(&mut buf[..10]).unwrap(), 10);
    let len = 10 + stream.read(&mut buf[10..]).unwrap();
    assert!(len < 100);
    assert_eq!(stream.read(&mut[0; 1]).unwrap(), 0);
    assert!(buf[..len].is_ascii());
}

#[cfg(unix)]
#[test]
fn unix_dgram_qotd() {
    let mut buf = [0; 1024];
    let name = current_dir().unwrap().join("qotd_dgram_test.socket");
    let _ = remove_file(&name);
    let conn = UnixDatagram::bind(&name).unwrap();
    conn.connect("qotd_dgram.socket").unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send(&b""[..]).unwrap(), 0);
    let len_a = conn.recv(&mut buf[..512]).unwrap();
    assert_eq!(conn.send(&b"0"[..]).unwrap(), 1);
    let len_b = conn.recv(&mut buf[512..]).unwrap();
    assert!(buf[..len_a].is_ascii());
    assert_eq!(buf[..len_a], buf[512..512+len_b]);
    assert_timeout!(conn.recv(&mut buf));
    remove_file(&name).unwrap();
}


#[test]
fn tcp_time32() {
    let mut stream = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 1), 10037)).unwrap();
    assert_eq!(stream.read(&mut[0; 12]).unwrap(), 4);
    assert_eq!(stream.read(&mut[0; 12]).unwrap(), 0);
}

#[test]
fn udp_time32() {
    let mut buf = [0; 16];
    let conn = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    conn.connect((Ipv4Addr::new(127, 0, 0, 1), 10037)).unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send(&b""[..]).unwrap(), 0);
    assert_eq!(conn.recv(&mut buf[..8]).unwrap(), 4);
    assert_eq!(conn.send(&b"1"[..]).unwrap(), 1);
    assert_eq!(conn.recv(&mut buf[8..]).unwrap(), 4);
    assert_eq!(buf[0..4], buf[8..12]); // FIXME flaky
    assert_timeout!(conn.recv(&mut buf));
}

#[test]
fn unix_stream_time32() {
    let mut stream = UnixStream::connect("time32.socket").unwrap();
    assert_eq!(stream.read(&mut[0; 12]).unwrap(), 4);
    assert_eq!(stream.read(&mut[0; 12]).unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn unix_dgram_time32() {
    let mut buf = [0; 16];
    let name = current_dir().unwrap().join("time32_dgram_test.socket");
    let _ = remove_file(&name);
    let conn = UnixDatagram::bind(&name).unwrap();
    conn.connect("time32_dgram.socket").unwrap();
    conn.set_read_timeout(Some(Duration::new(0, 1_000_000))).unwrap();
    assert_eq!(conn.send(&b""[..]).unwrap(), 0);
    assert_eq!(conn.recv(&mut buf[..8]).unwrap(), 4);
    assert_eq!(conn.send(&b"1"[..]).unwrap(), 1);
    assert_eq!(conn.recv(&mut buf[8..]).unwrap(), 4);
    assert_eq!(buf[0..4], buf[8..12]); // FIXME flaky
    assert_timeout!(conn.recv(&mut buf));
    remove_file(&name).unwrap();
}
