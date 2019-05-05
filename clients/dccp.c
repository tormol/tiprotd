// A simple DCCP client or server sporting some async features.

#define _POSIX_C_SOURCE 200809L // 2008.09 needed for SA_RESETHAND and the S_IF* fd types
#include <linux/dccp.h>
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
#define LISTEN_BACKLOG 10 // zero gives clients EUSERS, set high to reduce risk of errors

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
            if (ipv6->sin6_scope_id != 0) {
                len += snprintf(&ipstr[len], sizeof(ipstr)-len, "%%%d", ipv6->sin6_scope_id);
            }
            snprintf(&ipstr[len], sizeof(ipstr)-len, "]:%d", ntohs(ipv6->sin6_port));
        }
        return ipstr;
    } else if (sa->sa_family == AF_UNIX) {
        struct sockaddr_un *local = (struct sockaddr_un*)sa;
        return local->sun_path;
    } else if (sa->sa_family == AF_UNSPEC) {
        return "{unspecified}";
    } else {
        snprintf(ipstr, sizeof(ipstr), "(address of unknown type %d)", sa->sa_family);
        return ipstr;
    }
}

// get the local address of the socket and format it using sockaddr2str()
char* local2str(int socket) {
    struct sockaddr_storage local;
    socklen_t len = sizeof(struct sockaddr_storage);
    checkerr(getsockname(socket, (struct sockaddr*)&local, &len),
        "get local address of socket %d", socket);
    return sockaddr2str((struct sockaddr*)&local);
}

// resolve an address with getaddrinfo(), calling use() for each option
void resolve(char *addr, char *port, bool(*use)(struct addrinfo*, void*), void *context) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; // both IPv4 and IPv6
    hints.ai_socktype = SOCK_DCCP;
    hints.ai_protocol = IPPROTO_DCCP;
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

// callback for resolve() to create a socket and bind it to ai->ai_addr
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
    uint8_t ccids[8];
    socklen_t num_ccids = sizeof(ccids);
    checkerr(getsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_AVAILABLE_CCIDS, ccids, &num_ccids), "get available CCIDs");
    for (socklen_t i=0; i<num_ccids; i++) {
        fprintf(stderr, "OS supports CCID %d\n", (int)ccids[i]);
    }
    checkerr(setsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_CCID, &ccids[0], sizeof(uint8_t)),
        "set send & receive CCID");
    // doesn't work for some reason (neither does using uint8)
    // socklen_t int_size = sizeof(int);
    // int rx_ccid;
    // checkerr(getsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_RX_CCID, &rx_ccid, &int_size), "get receive CCID");
    // int tx_ccid;
    // checkerr(getsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_TX_CCID, &tx_ccid, &int_size), "get send CCID");
    // printf("default receive CCID: %d, default send CCID: %d\n", (int)rx_ccid, (int)tx_ccid);
    int services[DCCP_SERVICE_LIST_MAX_LEN];
    for (int i=0; i<DCCP_SERVICE_LIST_MAX_LEN; i++) {
        services[i] = i;
    }
    checkerr(setsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_SERVICE, services, sizeof(services)),
        "set %d service codes", DCCP_SERVICE_LIST_MAX_LEN);
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
    int sock; // try_bind() always creates a new socket
    resolve(addr, port, try_bind, &sock);
    checkerr(listen(sock, LISTEN_BACKLOG), "listen on %s", local2str(sock));
    return sock;
}

// create a socket and listen on any interface (both IPv6 and IPv4) at the given port
// without the complexity of listen_on()
int listen_any(char *port) {
    struct sockaddr_in6 any;
    memset(&any, 0, sizeof(struct sockaddr_in6));
    any.sin6_family = AF_INET6;
    any.sin6_port = port==NULL ? 0 : htons(parseport(port));
    any.sin6_addr = in6addr_any; // not really necessary; it's already zero
    int sock = checkerr(socket(any.sin6_family, SOCK_DCCP, IPPROTO_DCCP), "create DCCP socket");
    checkerr(bind(sock, (struct sockaddr*)&any, sizeof(struct sockaddr_in6)),
        "bind to %s", sockaddr2str((struct sockaddr*)&any));
    // query socket address because it might have changed if port was 0
    checkerr(listen(sock, LISTEN_BACKLOG), "listen on %s", local2str(sock));
    return sock;
}

// callback for resolve() to connect a socket to ai->ai_addr, creating a socket if it doesn't exists
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
    // int minimal_cscov = 1;
    // checkerr(setsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_RECV_CSCOV, &minimal_cscov, sizeof(int)),
    //     "set receive checksum-coverage filter to %d", minimal_cscov);
    // int service_code = 9;
    // checkerr(setsockopt(*conn, SOL_DCCP, DCCP_SOCKOPT_SERVICE, &service_code, sizeof(int)),
    //    "set service code to %d", service_code);
    if (connect(*conn, ai->ai_addr, ai->ai_addrlen) == -1) {
        fprintf(stderr, "Cannot connect to %s", sockaddr2str(ai->ai_addr));
        // split because sockaddr2str() reuses string buffer
        fprintf(stderr, " (from %s): %s\n", local2str(*conn), strerror(errno));
        if (new_socket) {
            checkerr(close(*conn), "close the failed socket");
            *conn = -1;
        }
        return false;
    }
    return true;
}

// connect to domain:port, and bind to ip:port
int connect_from_to(char *from_ip, char *from_port, char *to_domain, char *to_port) {
    from_port = from_port==NULL ? "0" : from_port;
    to_port = to_port==NULL ? "23" : to_port;
    int conn; // try_bind() always creates a new socket
    resolve(from_ip, from_port, try_bind, &conn);
    resolve(to_domain, to_port, try_connect, &conn);
    return conn;
}

// connect to domain:port without binding
int connect_to(char *domain, char *port) {
    domain = domain==NULL ? "localhost" : domain;
    port = port==NULL ? "23" : port;
    int conn = -1; // tells try_connect() to also create a socket
    resolve(domain, port, try_connect, &conn);
    return conn;
}

// connect to the IPv4 loopback 127.0.0.1,
// without the complexity of connect_to()
int connect_to_localhost(char *port) {
    port = port==NULL ? "23" : port;
    struct sockaddr_in localhost;
    memset(&localhost, 0, sizeof(struct sockaddr_in));
    localhost.sin_family = AF_INET;
    localhost.sin_port = htons(parseport(port));
    localhost.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int conn = checkerr(socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP), "create DCCP socket");
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

// call perform() then close() the socket
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

// send the received data back to the sender
ssize_t echo(int conn, struct sockaddr_in6 *_remote, void *_nothing) {
    UNUSED(_remote);
    UNUSED(_nothing);
    char buf[1024];
    while (1) {
        ssize_t received = recv(conn, &buf, sizeof(buf), MSG_TRUNC);
        if (received <= 0) {
            return received;
        }
        size_t stored = (size_t)received <= sizeof(buf) ? (size_t)received : sizeof(buf);
        checkerr(fwrite(&buf, stored, 1, stdout), "write to stdout");
        ssize_t sent = send(conn, buf, stored, MSG_CONFIRM);
        checkerr((int)sent, "Error sending %d bytes to %s: %s\n", stored, client, strerror(errno));
    }
}

// used to restore nonblocking-ness on exit, see talk_rasync()
int initial_stdin_flags; // is initialized by talk_rasync() before use

void restore_stdin_flags() {
    fcntl(STDIN, F_SETFL, initial_stdin_flags);
    // ignore any error; program is terminating already and printf() isn't signal-safe
}

void handler(int signal) {
    restore_stdin_flags();
    raise(signal); // continue to default handler (this handler was registered as oneshot)
}

// send stdin to socket and socket to stdout, using select() to avoid blocking on either side.
ssize_t talk_rasync(int conn, struct sockaddr_in6 *_remote, void *_param) {
    UNUSED(_remote);
    UNUSED(_param);
    // set stdin to nonblocking mode unless it's a file
    // (because it would then never make progress on Linux)
    struct stat stdinfo;
    checkerr(fstat(STDIN, &stdinfo), "stat() stdin");
    // not sure about block devices, so treat it as file just in case
    if ((stdinfo.st_mode & S_IFMT) != S_IFREG && (stdinfo.st_mode & S_IFMT) != S_IFBLK) {
        initial_stdin_flags = checkerr(fcntl(STDIN, F_GETFL, 0), "get flags for stdin");
        checkerr(fcntl(STDIN, F_SETFL, initial_stdin_flags | O_NONBLOCK), "make stdin nonblocking");
        // restore blockingness on exit, otherwise `git add -p` and other commands stop working
        // afterwards. (The `reset` command doesn't restore this either, but invoking `bash` then
        // exiting fixes it).
        atexit(restore_stdin_flags);
        struct sigaction act;
        sigemptyset(&act.sa_mask);
        act.sa_handler = handler;
        act.sa_flags = SA_RESETHAND; // resume with default handler after restoring
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGTERM, &act, NULL);
    }
    int max_packet_size;
    socklen_t int_size = sizeof(int);
    checkerr(getsockopt(conn, SOL_DCCP, DCCP_SOCKOPT_GET_CUR_MPS, &max_packet_size, &int_size),
        "get max packet size");
    fprintf(stderr, "maximum packet size: %d\n", max_packet_size);
    char buf[4096];
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
        fprintf(stderr, "\tdccp [[source_addr source_port] domain] port - select()-based client\n");
        fprintf(stderr, "\tdccp listen [addr] port - select()-based server\n");
        fprintf(stderr, "\tdccp echo [addr] port - echo server\n");
        exit(1);
    }
    return 0;
}
