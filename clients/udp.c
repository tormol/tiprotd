// A simple UDP client or server sporting some async features.

#ifdef __linux__
    #define _POSIX_C_SOURCE 200809L // 2008.09 needed for SA_RESETHAND and the S_IF* fd types with glibc
#endif

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

// create a socket and bind to any interface (both IPv6 and IPv4) at the given port
int bind_any(const char *port) {
    struct sockaddr_in6 any;
    memset(&any, 0, sizeof(struct sockaddr_in6));
    any.sin6_family = AF_INET6;
    any.sin6_port = port==NULL ? 0 : htons(parseport(port));
    any.sin6_addr = in6addr_any; // not really necessary; it's already zero
    int sock = checkerr(socket(any.sin6_family, SOCK_DGRAM, 0), "create UDP socket");
#ifndef __linux__ // disabled by default on Linux
    int only_ipv6 = 0;
    checkerr(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &only_ipv6, sizeof(int)),
        "make socket accept IPv4 in addition to IPv6");
#endif
    // you probably want to set SO_REUSEADDR, see try_bind() below
    checkerr(bind(sock, (struct sockaddr*)&any, sizeof(struct sockaddr_in6)),
        "bind to %s", sockaddr2str((struct sockaddr*)&any));
    return sock;
}

// create a socket and connect it to the IPv4 loopback address 127.0.0.1
int connect_to_localhost(const char *port) {
    port = port==NULL ? "23" : port; // connect to telnet port if unspecified
    struct sockaddr_in localhost;
    memset(&localhost, 0, sizeof(struct sockaddr_in));
    localhost.sin_family = AF_INET;
    localhost.sin_port = htons(parseport(port));
    localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int sock = checkerr(socket(AF_INET, SOCK_DGRAM, 0), "create UDP socket");
    checkerr(connect(sock, (struct sockaddr*)&localhost, sizeof(struct sockaddr_in)),
        "connect to %s", sockaddr2str((struct sockaddr*)&localhost));
    return sock;
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
    hints.ai_socktype = SOCK_DGRAM;
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

// create a socket and bind to the address
int bind_on(const char *addr, const char *port) {
    addr = addr==NULL ? "localhost" : addr;
    port = port==NULL ? "0" : port;
    int sock; // try_bind() always creates a new socket
    resolve(addr, port, try_bind, &sock);
    return sock;
}

// connect to domain:port after binding to ip:port
int connect_from_to(
        const char *from_ip, const char *from_port,
        const char *to_domain, const char *to_port
) {
    from_port = from_port==NULL ? "0" : from_port;
    to_port = to_port==NULL ? "23" : to_port; // connect to telnet port if unspecified
    int sock; // try_bind() always creates a new socket
    resolve(from_ip, from_port, try_bind, &sock);
    resolve(to_domain, to_port, try_connect, &sock);
    return sock;
}

// connect to domain:port without binding
int connect_to(const char *domain, const char *port) {
    domain = domain==NULL ? "localhost" : domain;
    port = port==NULL ? "23" : port; // connect to telnet port if unspecified
    int sock = -1; // tells try_connect() to also create a socket
    resolve(domain, port, try_connect, &sock);
    return sock;
}


/* program modes */

// reply to any received datagram with the same content, and print them to stdout
void echo(int sock) {
    char buf[BUFFER_SIZE];
    struct sockaddr_storage peer;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    while (true) {
        ssize_t received = recvfrom(sock, &buf, sizeof(buf), MSG_TRUNC,
            (struct sockaddr*)&peer, &addrlen);
        checkerr((int)received, "receive datagram");
        char *peer_str = sockaddr2str((struct sockaddr*)&peer);
        printf("%s sent %zd bytes to echo: ", peer_str, received);
        size_t stored = (size_t)received <= sizeof(buf) ? (size_t)received : sizeof(buf);
        checkerr(fwrite(&buf, stored, 1, stdout), "write to stdout");
        ssize_t sent = sendto(sock, &buf, stored, 0, (struct sockaddr*)&peer, addrlen);
        checkerr((int)sent, "sending to %s", peer_str);
    }
}

// connect() the socket to the first client, then call perform() and close() the socket afterwards
void serve_one(int sock, ssize_t(*perform)(int)) {
    struct sockaddr_storage peer;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    checkerr((int)recvfrom(sock, NULL, 0, MSG_PEEK, (struct sockaddr*)&peer, &addrlen),
        "receive datagram");
    char *peer_addr = sockaddr2str((struct sockaddr*)&peer);
    fprintf(stderr, "Received datagram from %s\n", peer_addr);
    checkerr(connect(sock, (struct sockaddr*)&peer, addrlen), "connect the socket");
    int lastret = perform(sock);
    if (lastret == -1) {
        fprintf(stderr, "Error with %s: %s\n", peer_addr, strerror(errno));
    }
    checkerr(close(sock), "close socket connected to %s", peer_addr);
}

// call perform() then close() the socket
void client(int sock, ssize_t(*perform)(int)) {
    fprintf(stderr, "Connected, from %s\n", local2str(sock));
    ssize_t lastret = perform(sock);
    if (lastret == -1) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
    }
    checkerr(close(sock), "close socket");
}

#define STDIN 0
#define STDOUT 1

// used to restore nonblocking-ness on exit
// is inititalized by make_stdin_nonblocking() if used
int original_stdin_flags;

void restore_stdin_flags() {
    fcntl(STDIN, F_SETFL, original_stdin_flags);
    // ignore any error; program is terminating already and printf() isn't signal-safe
}

void signal_handler(int signal) {
    restore_stdin_flags();
    raise(signal); // continue to default handler (this handler was registered as oneshot)
}

// set stdin to nonblocking mode and register functions to restore it at program exit
void make_stdin_nonblocking() {
    // set stdin to nonblocking mode unless it's a file
    // (because it would then never make progress on Linux)
    struct stat stdinfo;
    checkerr(fstat(STDIN, &stdinfo), "stat stdin");
    if ((stdinfo.st_mode & S_IFMT) != S_IFREG) {
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
}

// send stdin to socket and socket to stdout, using select() to avoid blocking on either side.
ssize_t interactive_async_read(int sock) {
    make_stdin_nonblocking();
    char buf[BUFFER_SIZE];
    ssize_t received;
    // main loop; runs until either stdin reaches EOF or peer disconnects
    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN, &readfds);
        FD_SET(sock, &readfds);
        fd_set errfds = readfds;
        checkerr(select(sock+1, &readfds, NULL, &errfds, NULL), "select()");
        while ((received = recv(sock, &buf, sizeof(buf), MSG_DONTWAIT)) != -1) {
            checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return received;
        }
        ssize_t to_send;
        while ((to_send = read(STDIN, &buf, sizeof(buf))) > 0) {
            // might have read more than what can be sent in one datagram
            ssize_t sent = 0;
            while (sent < to_send) {
                ssize_t this_send = send(sock, &buf[sent], to_send-sent, 0);
                if (this_send == -1) {
                    return this_send;
                }
                sent += this_send;
            }
        }
        if (to_send == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return to_send;
        }
    }
}


int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "listen")) {
        serve_one(bind_any(argv[2]), interactive_async_read);
    } else if (argc == 4 && !strcmp(argv[1], "listen")) {
        serve_one(bind_on(argv[2], argv[3]), interactive_async_read);
    } else if (argc == 3 && !strcmp(argv[1], "echo")) {
        echo(bind_any(argv[2]));
    } else if (argc == 4 && !strcmp(argv[1], "echo")) {
        echo(bind_on(argv[2], argv[3]));
    } else if (argc == 2) {
        client(connect_to_localhost(argv[1]), interactive_async_read);
    } else if (argc == 3) {
        client(connect_to(argv[1], argv[2]), interactive_async_read);
    } else if (argc == 5) {
        client(connect_from_to(argv[1], argv[2], argv[3], argv[4]), interactive_async_read);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\tudp [[source_addr source_port] domain] port - select()-based client\n");
        fprintf(stderr, "\tudp listen [addr] port - select()-based server\n");
        fprintf(stderr, "\tudp echo [addr] port - echo server\n");
        exit(1);
    }
    return 0;
}

// Things this program doesn't do (for simplicity), but code that wants to be robust should consider:
// * In unconnected mode, many errors such as ECONNRESET, ECONNREFUSED and EHOSTUNREACH
//   should be ignored as they might be related to a response to an earlier datagram.
// * Retry send(), recv() and select() if they fail with EINTR.
// * Set CLOEXEC on created sockets. (using SOCK_CLOEXEC where available)
// Also, internet-accessible UDP servers must prevent being useful in DDoS amplification attacks.
