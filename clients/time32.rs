//! A simple client for the binary time32 protocol, supporting both TCP,
//! UDP and reading from stdin.

use std::env::args_os;
use std::str::FromStr;
use std::net::{TcpStream, UdpSocket};
use std::io::{Error, Read, stdin};

fn timestamp_to_date(mut ts: i32) -> [u16; 6] {
    // std::time cannot format, and this is not worth pulling in chrono for

    let sign: i32 = if ts < 0 {-1} else {1};
    let mut days = ts / (60*60*24);
    ts %= 60*60*24;
    let mut year: i32 = 1970;
    fn isleap(year: i32) -> bool {year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)}
    fn daysinyear(year: i32) -> i32 {if isleap(year) {366} else {365}}
    if sign >= 0 {
        while days >= daysinyear(year) {
            days -= daysinyear(year);
            year += 1;
        }
    } else {// pre 1970
        if ts != 0 {// not 00:00:00
            ts += 60*60*24;
            days -= 1;
        }
        loop {
            year -= 1;
            days += daysinyear(year);
            if days >= 0 {
                break;
            }
        }
    }
    // println!("year: {}, is leap year: {}, day of year: {}, second of day: {}", year, isleap(year), days, ts);
    let feb = if isleap(year) {29} else {28};
    let days_in_month = [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut months = 0;
    while days >= days_in_month[months] {
        days -= days_in_month[months];
        months += 1;
    }

    let hour = ts / (60*60);
    ts %= 60*60;
    let minute = ts / 60;
    ts %= 60;
    [year as u16, months as u16+1, days as u16+1, hour as u16, minute as u16, ts as u16]
}

#[derive(Clone,Copy)]
enum Protocol {Tcp, Udp, Stdin}

fn protocol_from_str(s: &str) -> Result<Protocol,String> {
    match s {
        "-t" | "--tcp" | "tcp" | "TCP" => Ok(Protocol::Tcp),
        "-u" | "--udp" | "udp" | "UDP" => Ok(Protocol::Udp),
        "-" => Ok(Protocol::Stdin),
        _ => Err(format!("{} is not a supported protocol", s))
    }
}

fn protocol_to_str(p: Protocol) -> &'static str {
    match p { Protocol::Tcp => "tcp", Protocol::Udp => "udp", Protocol::Stdin => "stdin" }
}

fn retrieve(protocol: Protocol,  remote: (&str,u16),  buf: &mut[u8]) -> Result<usize,Error> {
    match protocol {
        Protocol::Tcp => {
            let mut stream = TcpStream::connect(remote)?;
            stream.read(buf)
        }
        Protocol::Udp => {
            let socket = UdpSocket::bind(("::",0))?;
            socket.connect(remote)?;
            socket.send(&mut[])?;
            socket.recv(buf)
        }
        Protocol::Stdin => {
            stdin().read(buf)
        }
    }
}

fn main() {
    debug_assert_eq!(timestamp_to_date(0), [1970, 1, 1, 0, 0, 0]);
    debug_assert_eq!(timestamp_to_date(60*60*24-1), [1970, 1, 1, 23, 59, 59]);
    debug_assert_eq!(timestamp_to_date(60*60*24*(31+1)), [1970, 2, 2, 0, 0, 0]);
    debug_assert_eq!(timestamp_to_date(31536000), [1971, 1, 1, 0, 0, 0]);
    debug_assert_eq!(timestamp_to_date(39274217), [1971, 3, 31, 13, 30, 17]);
    debug_assert_eq!(timestamp_to_date(68214896), [1972, 2, 29, 12, 34, 56]);
    debug_assert_eq!(timestamp_to_date(119731017), [1973, 10, 17, 18, 36, 57]);
    debug_assert_eq!(timestamp_to_date(951854402), [2000, 2, 29, 20, 00, 02]);
    debug_assert_eq!(timestamp_to_date(1551441600), [2019, 3, 1, 12, 00, 00]);
    debug_assert_eq!(timestamp_to_date(2147483647), [2038, 1, 19, 3, 14, 7]);
    debug_assert_eq!(timestamp_to_date(-1), [1969, 12, 31, 23, 59, 59]);
    debug_assert_eq!(timestamp_to_date(-60*60*24), [1969, 12, 31, 0, 0, 0]);
    debug_assert_eq!(timestamp_to_date(-60*60*24*365), [1969, 1, 1, 0, 0, 0]);
    debug_assert_eq!(timestamp_to_date(-60*60*24*365-1), [1968, 12, 31, 23, 59, 59]);
    debug_assert_eq!(timestamp_to_date(-63154739), [1968, 1, 1, 1, 1, 1]);
    debug_assert_eq!(timestamp_to_date(-89679601), [1967, 2, 28, 0, 59, 59]);
    debug_assert_eq!(timestamp_to_date(-1834750129), [1911, 11, 11, 11, 11, 11]);
    debug_assert_eq!(timestamp_to_date(-2147483648), [1901, 12, 13, 20, 45, 52]);

    let (mut address, mut port, mut protocol) = ("127.0.0.1".to_string(), 37, Protocol::Tcp);
    for (i, arg) in args_os().enumerate().skip(1) {
        let mut arg = match arg.into_string() {
            Ok(arg) => arg,
            Err(_) => {eprintln!("Argument {} is invalid", i); return;},
        };
        if let Ok(p) = u16::from_str(&arg) {
            port = p;
        } else if let Ok(p) = protocol_from_str(&arg) {
            protocol = p;
        } else if let Some(split) = arg.rfind(':') {
            port = match u16::from_str(&arg[split+1..]) {
                Ok(p) => p,
                Err(_) => {eprintln!("{} is not a port number", &arg[split+1..]); return;}
            };
            arg.truncate(split);
            address = arg;
        } else {
            address = arg;
        }
    }

    let mut bytes = [0; 8];
    match retrieve(protocol, (&address, port), &mut bytes) {
        Ok(4) => {}
        Ok(few @ 0..=3) => {eprintln!("Only received {} of 4 bytes", few); return;}
        Ok(_) => {eprintln!("Received too many bytes"); return;}
        Err(e) => {
            eprintln!("Cannot connect to {}://{}:{} : {}",
                protocol_to_str(protocol), address, port, e
            );
            return;
        }
    }
    println!("bytes:    \t\\x{:02x}\\x{:02x}\\x{:02x}\\x{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    );

    let timestamp = (bytes[0] as i32) << 24
                  | (bytes[1] as i32) << 16
                  | (bytes[2] as i32) << 8
                  | (bytes[3] as i32);
    println!("timestamp:\t{}", timestamp);

    let [year, month, day, hour, minute, second] = timestamp_to_date(timestamp);
    println!("date:     \t{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hour, minute, second
    );
}
