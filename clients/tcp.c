#include <sys/socket.h> // socket(), struct sockaddr, ...
#include <netinet/in.h> // struct inaddr_in{,6}, ...
#include <arpa/inet.h> // inet_ntop()
#include <netdb.h> // getaddrinfo() and struct addrinfo
#include <sys/un.h> // support unix sockets in sockaddr2str()
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h> // strlen() and strerror()
#include <stdio.h>
#include <stdlib.h> // exit() and strtoul()
#include <unistd.h> // close() and read()
#include <stdarg.h>
#include <stdbool.h>

int checkerr(int ret, char *desc, ...) {
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

#define UNUSED(x) (void)(x)
#define STDIN 0
#define STDOUT 1
#define LISTEN_BACKLOG 0

in_port_t parseport(char *arg) {
    char *end;
    unsigned long num = strtoul(arg, &end, 10);
    if (*arg < '0' || *arg > '9' || *end != '\0' || num > 0xffff) {
        fprintf(stderr, "bad port number %s\n", arg);
        exit(1);
    }
    return (in_port_t)num;
}

// format a socket address, using a global buffer
char* sockaddr2str(struct sockaddr *sa) {
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
            if (ipv6->sin6_scope_id == 0) {
                snprintf(&ipstr[len], sizeof(ipstr)-len, "]:%d", ntohs(ipv6->sin6_port));
            } else {
                snprintf(&ipstr[len], sizeof(ipstr)-len, "%%%d]:%d", ipv6->sin6_scope_id, ntohs(ipv6->sin6_port));
            }
        }
        return ipstr;
    } else if (sa->sa_family == AF_UNIX) {
        struct sockaddr_un *local = (struct sockaddr_un*)sa;
        return local->sun_path;
    } else if (sa->sa_family == AF_UNSPEC) {
        return "{unspecified}";
    } else {
        fprintf(stderr, "Unknown address family (%d)\n", sa->sa_family);
        exit(1);
    }
}

// get the local address of the socket and format it using sockaddr2str()
char* local2str(int socket) {
    struct sockaddr_storage local;
    socklen_t len = sizeof(struct sockaddr_storage);
    checkerr(getsockname(socket, (struct sockaddr*)&local, &len), "get local address of socket %d", socket);
    return sockaddr2str((struct sockaddr*)&local);
}

// resolve an address with getaddrinfo(), calling use() for each option
void resolve(char *addr, char *port, bool(*use)(struct addrinfo*, void*), void *context) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
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
        succeeded = use(ai, context);
        ai = ai->ai_next;
    }
    freeaddrinfo(root);
    if (!succeeded) {
        fprintf(stderr, "All options failed for %s:%s\n", addr, port);
        exit(1);
    }
}

// creates a socket and binds it to ai->ai_addrlen
bool try_bind(struct addrinfo *ai, void *param) {
    int *conn = (int*)param;
    fprintf(stderr, "Trying to bind to %s\n", sockaddr2str(ai->ai_addr));
    *conn = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (*conn == -1) {
        fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
        return false;
    }
    const int yes = 1;
    if (setsockopt(*conn, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        fprintf(stderr, "Cannot set SO_REUSEADDR, bind()ing anyway\n");
    }
    if (bind(*conn, ai->ai_addr, ai->ai_addrlen) == -1) {
        fprintf(stderr, "Cannot bind to %s: %s\n", sockaddr2str(ai->ai_addr), strerror(errno));
        checkerr(close(*conn), "close the failed socket");
        *conn = -1;
        return false;
    }
    fprintf(stderr, "Local address: %s\n", local2str(*conn));
    return true;
}

// create a socket and listen on the address
int listen_on(char *addr, char *port) {
    addr = addr==NULL ? "localhost" : addr;
    port = port==NULL ? "0" : port;
    int sock;
    resolve(addr, port, try_bind, &sock);
    checkerr(listen(sock, LISTEN_BACKLOG), "listen on %s", local2str(sock));
    return sock;
}

// create a socket and listen on any interface at the given port
// much simpler than listen_on()
int listen_any(char *port) {
    struct sockaddr_in6 any;
    memset(&any, 0, sizeof(struct sockaddr_in6));
    any.sin6_family = AF_INET6;
    any.sin6_port = port==NULL ? 0 : htons(parseport(port));
    any.sin6_addr = in6addr_any; // not really necessary - it's already zero
    int sock = checkerr(socket(any.sin6_family, SOCK_STREAM, 0), "create TCP socket");
    checkerr(bind(sock, (struct sockaddr*)&any, sizeof(struct sockaddr_in6)),
        "bind to %s", sockaddr2str((struct sockaddr*)&any)
    );
    // query socket address because it might have changed if port was 0
    checkerr(listen(sock, LISTEN_BACKLOG), "listen on %s", local2str(sock));
    return sock;
}

// connects a socket to ai->ai_addr, creating a socket if it doesn't exists
bool try_connect(struct addrinfo *ai, void *params) {
    int *conn = (int*)params;
    bool new_socket = *conn == -1;
    fprintf(stderr, "Trying to connect to %s\n", sockaddr2str(ai->ai_addr));
    if (new_socket) {
        *conn = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (*conn == -1) {
            fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
            return false;
        }
    }
    if (connect(*conn, ai->ai_addr, ai->ai_addrlen) == -1) {
        fprintf(stderr, "Cannot connect to %s", sockaddr2str(ai->ai_addr));
        // split because socketaddr2str() reuses string buffer
        fprintf(stderr, " (from %s): %s\n", local2str(*conn), strerror(errno));
        if (new_socket) {
            checkerr(close(*conn), "close the failed socket");
            *conn = -1;
        }
        return false;
    }
    return true;
}

// connect to domain:port, and bind to ip:port if one of them are not null
int connect_from_to(char *from_ip, char *from_port, char *to_domain, char *to_port) {
    from_port = from_port==NULL ? "0" : from_port;
    to_port = to_port==NULL ? "23" : to_port;
    int conn;
    resolve(from_ip, from_port, try_bind, &conn);
    resolve(to_domain, to_port, try_connect, &conn);
    return conn;
}

// connect to domain:port, and bind to ip:port if one of them are not null
int connect_to(char *domain, char *port) {
    domain = domain==NULL ? "localhost" : domain;
    port = port==NULL ? "23" : port;
    int conn = -1;
    resolve(domain, port, try_connect, &conn);
    return conn;
}

// much simpler
int connect_to_localhost(char *port) {
    port = port==NULL ? "23" : port;
    struct sockaddr_in localhost;
    bzero(&localhost, sizeof(struct sockaddr_in));
    localhost.sin_family = AF_INET;
    localhost.sin_port = htons(parseport(port));
    localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int conn = checkerr(socket(AF_INET, SOCK_STREAM, 0), "create TCP socket");
    checkerr(connect(conn, (struct sockaddr*)&localhost, sizeof(struct sockaddr_in)),
             "connect to %s", sockaddr2str((struct sockaddr*)&localhost));
    return conn;
}

void accept_loop(int sd, ssize_t(*perform)(int, struct sockaddr_in6*, void*), void* param) {
    struct sockaddr_storage remote;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    while (1) {
        int conn = checkerr(accept(sd, (struct sockaddr*)&remote, &addrlen), "accept connection");
        char *client = sockaddr2str((struct sockaddr*)&remote);
        printf("Accepted connection from %s\n", client);
        int lastret = perform(conn, (struct sockaddr_in6*)&remote, param);
        if (lastret == -1) {
            fprintf(stderr, "Error with %s: %s\n", client, strerror(errno));
        } else {
            printf("Closed by remote\n");
        }
        checkerr(close(conn), "close connection to %s", client);
    }
}

void client(int conn, ssize_t(*perform)(int, struct sockaddr_in6*, void*), void* param) {
    fprintf(stderr, "Connected, from %s\n", local2str(conn));
    ssize_t lastret = perform(conn, NULL, param);
    if (lastret == -1) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
    } else {
        printf("Closed by remote\n");
    }
    checkerr(close(conn), "close connection");
}

ssize_t echo(int conn, struct sockaddr_in6 *_remote, void *_nothing) {
    UNUSED(_remote);
    UNUSED(_nothing);
    char buf[1024];
    while (1) {
        ssize_t received = recv(conn, &buf, sizeof(buf), 0/*flags*/);
        if (received <= 0) {
            return received;
        }
        checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        ssize_t sent = 0;
        while (sent < received) {
            ssize_t this_send = send(conn, &buf[sent], received-sent, 0);
            if (this_send <= 0) {
                return this_send;
            }
            sent += this_send;
        }
    }
}

/// send stdin to socket and socket to stdout, using select() to avoid blocking on either side.
ssize_t talk_rasync(int conn, struct sockaddr_in6 *_remote, void *_nothing) {
    UNUSED(_remote);
    UNUSED(_nothing);
    // set stdin to nonblocking mode unless it's a file
    // (because it would then never make progress on Linux)
    struct stat stdinfo;
    checkerr(fstat(STDIN, &stdinfo), "stat() stdin");
    // not sure about block devices, so treat it as file just in case
    if ((stdinfo.st_mode & S_IFMT) != S_IFREG && (stdinfo.st_mode & S_IFMT) != S_IFBLK) {
        int flags = checkerr(fcntl(STDIN, F_GETFL, 0), "get flags for stdin");
        checkerr(fcntl(STDIN, F_SETFL, flags | O_NONBLOCK), "make stdin nonblocking");
    }
    char buf[1024];
    ssize_t received;
    // main loop; runs until either stdin reaches EOF or remote disconnects
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN, &readfds);
        FD_SET(conn, &readfds);
        fd_set errfds = readfds;
        checkerr(select(conn+1, &readfds, NULL, &errfds, NULL), "select()");
        while ((received = recv(conn, &buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
            checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        }
        if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return received;
        }
        ssize_t to_send;
        while ((to_send = read(STDIN, &buf, sizeof(buf))) > 0) {
            ssize_t sent = 0;
            while (sent < to_send) {
                ssize_t this_send = send(conn, &buf[sent], to_send-sent, 0);
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
    while ((received = recv(conn, &buf, sizeof(buf), 0/*do wait now*/)) > 0) {
        checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
    }
    return received;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "listen")) {
        accept_loop(listen_any(argv[2]), talk_rasync, NULL);
    } else if (argc == 4 && !strcmp(argv[1], "listen")) {
        accept_loop(listen_on(argv[2], argv[3]), talk_rasync, NULL);
    } else if (argc == 3 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_any(argv[2]), echo, NULL);
    } else if (argc == 4 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_on(argv[2], argv[3]), echo, NULL);
    } else if (argc == 2) {
        client(connect_to_localhost(argv[1]), talk_rasync, NULL);
    } else if (argc == 3) {
        client(connect_to(argv[1], argv[2]), talk_rasync, NULL);
    } else if (argc == 5) {
        client(connect_from_to(argv[1], argv[2], argv[3], argv[4]), talk_rasync, NULL);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\ttcp [[source_addr source_port] domain] port - select()-based client\n");
        fprintf(stderr, "\ttcp listen [addr] port - select()-based server\n");
        fprintf(stderr, "\ttcp echo [addr] port - echo server\n");
        exit(1);
    }
    return 0;
}
