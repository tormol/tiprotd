// A barebones SCTP client and server, with minimal differences from tcp.c

#define _POSIX_C_SOURCE 200809L // 2008.09 needed for SA_RESETHAND and the S_IF* fd types
#include <sys/socket.h> // socket(), struct sockaddr, ...
#include <netinet/in.h> // struct inaddr_in{,6}, ...
#include <arpa/inet.h> // inet_ntop()
#include <netdb.h> // getaddrinfo() and struct addrinfo
#include <sys/un.h> // support unix sockets in sockaddr2str()
#include <sys/select.h> // to avoid blocking on either stdin or the socket when the other has data
#include <fcntl.h> // for making stdin nonblocking
#include <sys/stat.h> // for checking which kind of file stdin is
#include <signal.h> // for restoring stdin on Ctrl-C
#include <errno.h>
#include <string.h> // strlen() and strerror()
#include <stdio.h>
#include <stdlib.h> // exit() and strtoul()
#include <unistd.h> // close() and read()
#include <stdarg.h> // used by checkerr()
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define LISTEN_BACKLOG 1


/* helper functions */

// print error messages and exit if `ret` is negative,
// otherwise pass it through to caller.
int checkerr(int ret, const char *desc, ...) {
    if (ret >= 0) {
        return ret;
    }
    int err = errno;
    fprintf(stderr, "Failed to ");
    va_list args;
    va_start(args, desc);
    vfprintf(stderr, desc, args);
    va_end(args);
    fprintf(stderr, ": %s\n", strerror(err));
    exit(1);
}

// parse string as unsigned short and detect and handle invalid input
in_port_t parseport(const char *arg) {
    char *end;
    unsigned long num = strtoul(arg, &end, 10);
    if (*arg < '0' || *arg > '9' || *end != '\0' || num > 0xffff) {
        fprintf(stderr, "Bad port number %s\n", arg);
        exit(1);
    }
    return (in_port_t)num;
}

// format a socket address, using a global buffer to avoid needing to free()
char* sockaddr2str(const struct sockaddr *sa) {
    static char ipstr[100];
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in*)sa;
        // let inet_ntop handle endianness of the uint32_t address
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        snprintf(&ipstr[strlen(ipstr)], sizeof(ipstr)-strlen(ipstr), ":%d", ntohs(ipv4->sin_port));
        return ipstr;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)sa;
        // special-case IPv4-in-IPv6 addresses ::ffff:AABB:CCDD
        const uint8_t v4in6[12] = {0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff};
        if (!memcmp(ipv6->sin6_addr.s6_addr, v4in6, sizeof(v4in6))) {
            snprintf(ipstr, sizeof(ipstr), "[%d.%d.%d.%d]:%d",
                ipv6->sin6_addr.s6_addr[12], ipv6->sin6_addr.s6_addr[13],
                ipv6->sin6_addr.s6_addr[14], ipv6->sin6_addr.s6_addr[15],
                ntohs(ipv6->sin6_port)
            );
        } else {
            ipstr[0] = '[';
            // let inet_ntop handle the smart formatting of IPv6 addresses
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), &ipstr[1], sizeof(ipstr)-1);
            size_t len = strlen(ipstr);
            if (ipv6->sin6_scope_id != 0) {
                len += snprintf(&ipstr[len], sizeof(ipstr)-len, "%%%d", ipv6->sin6_scope_id);
            }
            snprintf(&ipstr[len], sizeof(ipstr)-len, "]:%d", ntohs(ipv6->sin6_port));
        }
        return ipstr;
    } else {
        snprintf(ipstr, sizeof(ipstr), "{address of unexpected type %d}", sa->sa_family);
        return ipstr;
    }
}

// get the local address of the socket and format it using sockaddr2str()
char* local2str(int sock) {
    struct sockaddr_storage local;
    socklen_t len = sizeof(struct sockaddr_storage);
    checkerr(getsockname(sock, (struct sockaddr*)&local, &len),
        "get local address of socket %d", sock);
    return sockaddr2str((struct sockaddr*)&local);
}


/* simple socket-creation functions avoiding the complexity of getaddrinfo() for common cases */

// create a socket and listen on any interface (both IPv6 and IPv4) at the given port
int listen_any(const char *port) {
    struct sockaddr_in6 any;
    memset(&any, 0, sizeof(struct sockaddr_in6));
    any.sin6_family = AF_INET6;
    any.sin6_port = port==NULL ? 0 : htons(parseport(port));
    any.sin6_addr = in6addr_any; // not really necessary; it's already zero
    int listener = checkerr(socket(any.sin6_family, SOCK_STREAM, IPPROTO_SCTP),
        "create SCTP socket");
    // you probably want to set SO_REUSEADDR, see try_bind() below
    checkerr(bind(listener, (struct sockaddr*)&any, sizeof(struct sockaddr_in6)),
        "bind to %s", sockaddr2str((struct sockaddr*)&any));
    // query socket address because it might have changed if port was 0
    checkerr(listen(listener, LISTEN_BACKLOG), "listen on %s", local2str(listener));
    return listener;
}

// create a socket and connect it to the IPv4 loopback address 127.0.0.1
int connect_to_localhost(const char *port) {
    port = port==NULL ? "23" : port; // connect to telnet port if unspecified
    struct sockaddr_in localhost;
    memset(&localhost, 0, sizeof(struct sockaddr_in));
    localhost.sin_family = AF_INET;
    localhost.sin_port = htons(parseport(port));
    localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int conn = checkerr(socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP), "create SCTP socket");
    checkerr(connect(conn, (struct sockaddr*)&localhost, sizeof(struct sockaddr_in)),
        "connect to %s", sockaddr2str((struct sockaddr*)&localhost));
    return conn;
}


/* robust socket-creation functions wrapping getaddrinfo() */

// resolve an address with getaddrinfo(), calling use() for each option
void resolve(
        const char *addr, const char *port,
        bool(*use)(const struct addrinfo*, int*), int *sock
) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; // both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_SCTP;
    struct addrinfo *ai;
    int gai_ret = getaddrinfo(addr, port, &hints, &ai);
    // for some reason, getaddrinfo uses a different set of error codes
    if (gai_ret != 0) {
        fprintf(stderr, "Failed to resolve %s:%s: %s\n", addr, port, gai_strerror(gai_ret));
        exit(1);
    }
    struct addrinfo *root = ai; // need to free later
    bool succeeded = false;
    while (ai != NULL && !succeeded) {
        succeeded = use(ai, sock);
        ai = ai->ai_next;
    }
    freeaddrinfo(root);
    if (!succeeded) {
        fprintf(stderr, "All options failed for %s:%s\n", addr, port);
        exit(1);
    }
}

// create a socket and bind it to ai->ai_addr
bool try_bind(const struct addrinfo *ai, int *sock) {
    fprintf(stderr, "Trying to bind to %s\n", sockaddr2str(ai->ai_addr));
    *sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (*sock == -1) {
        fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
        return false;
    }
    // enable re-binding to the address immediately after another process stopped using it
    const int yes = 1;
    if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        fprintf(stderr, "Cannot set SO_REUSEADDR, bind()ing anyway\n");
    }
    if (bind(*sock, ai->ai_addr, ai->ai_addrlen) == -1) {
        fprintf(stderr, "Cannot bind to %s: %s\n", sockaddr2str(ai->ai_addr), strerror(errno));
        checkerr(close(*sock), "close the failed socket");
        *sock = -1;
        return false;
    }
    fprintf(stderr, "Local address: %s\n", local2str(*sock));
    return true;
}

// connect a socket to ai->ai_addr, creating a socket if it doesn't exists
bool try_connect(const struct addrinfo *ai, int *sock) {
    bool new_socket = *sock == -1;
    fprintf(stderr, "Trying to connect to %s\n", sockaddr2str(ai->ai_addr));
    if (new_socket) {
        *sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (*sock == -1) {
            fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
            return false;
        }
    }
    if (connect(*sock, ai->ai_addr, ai->ai_addrlen) == -1) {
        fprintf(stderr, "Cannot connect to %s", sockaddr2str(ai->ai_addr));
        // split because sockaddr2str() reuses string buffer
        fprintf(stderr, " (from %s): %s\n", local2str(*sock), strerror(errno));
        if (new_socket) {
            checkerr(close(*sock), "close the failed socket");
            *sock = -1;
        }
        return false;
    }
    return true;
}

// create a socket and listen on the address
int listen_on(const char *addr, const char *port) {
    addr = addr==NULL ? "localhost" : addr;
    port = port==NULL ? "0" : port;
    int listener; // try_bind() always creates a new socket
    resolve(addr, port, try_bind, &listener);
    checkerr(listen(listener, LISTEN_BACKLOG), "listen on %s", local2str(listener));
    return listener;
}

// connect to domain:port after binding to ip:port
int connect_from_to(
        const char *from_ip, const char *from_port,
        const char *to_domain, const char *to_port
) {
    from_port = from_port==NULL ? "0" : from_port;
    to_port = to_port==NULL ? "23" : to_port; // connect to telnet port if unspecified
    int conn; // try_bind() always creates a new socket
    resolve(from_ip, from_port, try_bind, &conn);
    resolve(to_domain, to_port, try_connect, &conn);
    return conn;
}

// connect to domain:port without binding
int connect_to(const char *domain, const char *port) {
    domain = domain==NULL ? "localhost" : domain;
    port = port==NULL ? "23" : port; // connect to telnet port if unspecified
    int conn = -1; // tells try_connect() to also create a socket
    resolve(domain, port, try_connect, &conn);
    return conn;
}


/* program modes */

// accept a single incoming connection at a time,
// waiting until the client disconnects before accepting another
void accept_loop(int listener, ssize_t(*perform)(int)) {
    struct sockaddr_storage client;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    while (true) {
        int conn = checkerr(accept(listener, (struct sockaddr*)&client, &addrlen),
            "accept connection");
        char *client_str = sockaddr2str((struct sockaddr*)&client);
        fprintf(stderr, "Accepted connection from %s\n", client_str);
        int lastret = perform(conn);
        if (lastret == -1 && errno != EPIPE) {
            fprintf(stderr, "Error with %s: %s\n", client_str, strerror(errno));
        } else {
            fprintf(stderr, "Closed by client\n");
        }
        checkerr(close(conn), "close connection to %s", client_str);
    }
}

// call perform() then close() the socket
void client(int conn, ssize_t(*perform)(int)) {
    fprintf(stderr, "Connected, from %s\n", local2str(conn));
    ssize_t lastret = perform(conn);
    if (lastret == -1 && errno != EPIPE) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
    } else {
        fprintf(stderr, "Closed by server\n");
    }
    checkerr(close(conn), "close connection");
}

// send the received data back to the sender and to stdout
ssize_t echo(int conn) {
    char buf[BUFFER_SIZE];
    while (true) {
        ssize_t received = recv(conn, &buf, sizeof(buf), MSG_NOSIGNAL);
        if (received <= 0) {
            return received;
        }
        checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        ssize_t sent = 0;
        while (sent < received) {
            ssize_t this_send = send(conn, &buf[sent], received-sent, MSG_NOSIGNAL);
            if (this_send <= 0) {
                return this_send;
            }
            sent += this_send;
        }
    }
}

#define STDIN 0
#define STDOUT 1

// used to restore nonblocking-ness on exit, see interactive_async_read()
int original_stdin_flags; // is initialized by interactive_async_read() before use

void restore_stdin_flags() {
    fcntl(STDIN, F_SETFL, original_stdin_flags);
    // ignore any error; program is terminating already and printf() isn't signal-safe
}

void signal_handler(int signal) {
    restore_stdin_flags();
    raise(signal); // continue to default handler (this handler was registered as oneshot)
}

// send stdin to socket and socket to stdout using select() to avoid blocking on either side,
// and disconnect when peer has nothing more to send.
ssize_t interactive_async_read(int conn) {
    // set stdin to nonblocking mode unless it's a file
    // (because it would then never make progress on Linux)
    struct stat stdinfo;
    checkerr(fstat(STDIN, &stdinfo), "stat() stdin");
    // not sure about block devices, so treat it as file just in case
    if ((stdinfo.st_mode & S_IFMT) != S_IFREG && (stdinfo.st_mode & S_IFMT) != S_IFBLK) {
        original_stdin_flags = checkerr(fcntl(STDIN, F_GETFL, 0), "get flags for stdin");
        checkerr(fcntl(STDIN, F_SETFL, original_stdin_flags | O_NONBLOCK),
            "make stdin nonblocking");
        // restore blockingness on exit, otherwise `git add -p` and other commands stop working
        // afterwards. (The `reset` command doesn't restore this either, but invoking `bash` then
        // exiting fixes it).
        atexit(restore_stdin_flags);
        struct sigaction act;
        sigemptyset(&act.sa_mask);
        act.sa_handler = signal_handler;
        act.sa_flags = SA_RESETHAND; // resume with default handler after restoring
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGTERM, &act, NULL);
    }
    char buf[BUFFER_SIZE];
    ssize_t received;
    // main loop; runs until either stdin reaches EOF or peer disconnects
    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN, &readfds);
        FD_SET(conn, &readfds);
        fd_set errfds = readfds;
        checkerr(select(conn+1, &readfds, NULL, &errfds, NULL), "select()");
        while ((received = recv(conn, &buf, sizeof(buf), MSG_NOSIGNAL | MSG_DONTWAIT)) > 0) {
            checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        }
        if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return received;
        }
        ssize_t to_send;
        while ((to_send = read(STDIN, &buf, sizeof(buf))) > 0) {
            ssize_t sent = 0;
            while (sent < to_send) {
                ssize_t this_send = send(conn, &buf[sent], to_send-sent, MSG_NOSIGNAL);
                if (this_send <= 0) {
                    return this_send;
                }
                sent += this_send;
            }
        }
        if (to_send == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return to_send;
        }
    }
    // nothing more to send, but wait for response
    if (shutdown(conn, SHUT_WR) == -1) {
        fprintf(stderr, "Cannot shutdown send side: %s\n", strerror(errno));
        // don't exit()
    }
    while ((received = recv(conn, &buf, sizeof(buf), MSG_NOSIGNAL /*(do wait now)*/)) > 0) {
        checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
    }
    return received;
}


int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "listen")) {
        accept_loop(listen_any(argv[2]), interactive_async_read);
    } else if (argc == 4 && !strcmp(argv[1], "listen")) {
        accept_loop(listen_on(argv[2], argv[3]), interactive_async_read);
    } else if (argc == 3 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_any(argv[2]), echo);
    } else if (argc == 4 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_on(argv[2], argv[3]), echo);
    } else if (argc == 2) {
        client(connect_to_localhost(argv[1]), interactive_async_read);
    } else if (argc == 3) {
        client(connect_to(argv[1], argv[2]), interactive_async_read);
    } else if (argc == 5) {
        client(connect_from_to(argv[1], argv[2], argv[3], argv[4]), interactive_async_read);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\tsctp1 [[source_addr source_port] domain] port - select()-based client\n");
        fprintf(stderr, "\tsctp1 listen [addr] port - select()-based server\n");
        fprintf(stderr, "\tsctp1 echo [addr] port - echo server\n");
        exit(1);
    }
    return 0;
}

// This program mostly serves to test that SCTP works, with minimal differences from tcp.c.
// Things this program doesn't do:
// * Take advantage of SCTP being message-based, and remove code for handling short writes.
// * pass MSG_TRUNC to get real message length if too big for buffer.
// * Support multiple channels.
// * Use multi-homing.
// * Use SOCK_SEQPACKET mode for echo.
// * Retry accept() if it fails with ECONNABORTED, ECONNRESET, ECONNREFUSED.
// * Retry reads, writes, connect(), select() and accept() if they fail with EINTR.
// * Avoid using global variables, or at least make them thread-local.
// * Set CLOEXEC on created sockets. (using SOCK_CLOEXEC and accept4() where available)
// * Fall back to TCP if creating socket fails or connections cannot be established.
