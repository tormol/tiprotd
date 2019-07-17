CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -std=c11 -g

tcp: tcp.c
	$(CC) -o tcp tcp.c $(CFLAGS)

udp: udp.c
	$(CC) -o udp udp.c $(CFLAGS)

udplite: udplite.c
	$(CC) -o udplite udplite.c $(CFLAGS)

dccp: dccp.c
	$(CC) -o dccp dccp.c $(CFLAGS)

time32: time32.rs
	rustc -o time32 time32.rs

mq: mq.c
	$(CC) -o mq mq.c -lrt $(CFLAGS)

unix_stream: unix_stream.c
	$(CC) -o unix_stream unix_stream.c $(CFLAGS)