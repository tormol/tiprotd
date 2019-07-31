#![cfg(any(target_os="linux", target_os="freebsd"))]

extern crate posixmq;

use std::thread::sleep;
use std::time::Duration;

use posixmq::PosixMq;

#[test]
fn posixmq_discard() {
    let mq = posixmq::PosixMq::open("/discard").unwrap();
    let attrs = mq.attributes();
    let content = vec![b'i'; attrs.max_msg_len];
    assert_eq!(attrs.current_messages, 0);
    assert!(attrs.capacity < 200);
    for i in 0..200 {
        mq.send(i%64, &content[10*(i as usize %16)..]).unwrap();
    }
    sleep(Duration::new(0, 10_000_000));
    assert_eq!(mq.attributes().current_messages, 0);
}

#[test]
fn posixmq_qotd() {
    let mq = PosixMq::open("/qotd").unwrap();
    let attrs = mq.attributes();
    assert_eq!(attrs.capacity, 1);
    assert_eq!(attrs.current_messages, 1);
    let mut buf = vec![b'i'; attrs.max_msg_len];
    let (priority, len) = mq.receive(&mut buf).unwrap();
    assert_eq!(priority, 0);
    assert!(buf[..len].is_ascii());
    sleep(Duration::new(0, 10_000_000));
    assert_eq!(mq.attributes().current_messages, 1);
    let (priority, len) = mq.receive(&mut buf).unwrap();
    assert_eq!(priority, 0);
    assert!(buf[..len].is_ascii());
}
