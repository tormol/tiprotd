CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -std=gnu11 -g

tcp: tcp.c
	$(CC) -o tcp tcp.c

time32: time32.rs
	rustc -o time32 time32.rs
