CC?=gcc
CFLAGS?=-Wall -Wextra -Wpedantic -std=c11 -g
RUSTFLAGS?=--edition=2018 -C debuginfo=2

all: tcp udp sctp1 udplite dccp unix_stream unix_dgram unix_seqpacket mq time32

clean:
	rm -f tcp udp sctp1 sctp udplite dccp unix_stream unix_dgram unix_seqpacket mq time32

.PHONY: clean all

tcp: tcp.c
	$(CC) -o tcp tcp.c $(CFLAGS)

udp: udp.c
	$(CC) -o udp udp.c $(CFLAGS)

sctp1: sctp1.c
	$(CC) -o sctp1 sctp1.c $(CFLAGS)

udplite: udplite.c
	$(CC) -o udplite udplite.c $(CFLAGS)

dccp: dccp.c
	$(CC) -o dccp dccp.c $(CFLAGS)

unix_stream: unix_stream.c
	$(CC) -o unix_stream unix_stream.c $(CFLAGS)

unix_dgram: unix_dgram.c
	$(CC) -o unix_dgram unix_dgram.c $(CFLAGS)

unix_seqpacket: unix_seqpacket.c
	$(CC) -o unix_seqpacket unix_seqpacket.c $(CFLAGS)

mq: mq.c
	$(CC) -o mq mq.c -lrt $(CFLAGS)

time32: time32.rs
	rustc -o time32 time32.rs $(RUSTFLAGS)
