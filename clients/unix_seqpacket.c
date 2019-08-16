// A simple AF_UNIX SOCK_SEQPACKET client and server that can transfer FDs and credentials.

#define _POSIX_C_SOURCE 200809L // 2008.09 needed for SA_RESETHAND and the S_IF* fd types
#define _GNU_SOURCE // needed for struct ucred definition
#include <sys/socket.h> // socket(), struct sockaddr, ...
#include <sys/un.h> // support unix sockets in sockaddr2str()
#include <sys/select.h> // to avoid blocking on either stdin or the socket when the other has data
#include <fcntl.h> // for making stdin nonblocking
#include <sys/stat.h> // for checking which kind of file stdin is
#include <signal.h> // for restoring stdin on Ctrl-C
#include <sys/sendfile.h>
#include <errno.h>
#include <string.h> // strlen() and strerror()
#include <stdio.h>
#include <stdlib.h> // exit() and strtoul()
#include <unistd.h> // close() and read()
#include <stdarg.h> // used by checkerr()
#include <stdbool.h>
#include <stddef.h> // offsetof

#define BUFFER_SIZE 4096
#define LISTEN_BACKLOG 0


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

#define MINIMAL_SOCKLEN (offsetof(struct sockaddr_un, sun_path))
#define NAME_CAPACITY (sizeof(struct sockaddr_un)-MINIMAL_SOCKLEN)
// format a socket address, using a global buffer to avoid needing to free()
char* sockaddr2str(const struct sockaddr *sa, socklen_t addr_size) {
    static char with_nul[NAME_CAPACITY+1];
    if (sa->sa_family != AF_UNIX) {
        snprintf(with_nul, sizeof(with_nul), "{address of unexpected type %d}", sa->sa_family);
        return with_nul;
    } else if (addr_size <= MINIMAL_SOCKLEN) {
        return "unnamed";
    }
    socklen_t addr_len = addr_size - MINIMAL_SOCKLEN;
    struct sockaddr_un *local = (struct sockaddr_un*)sa;
    memcpy(with_nul, local->sun_path, addr_len);
    with_nul[addr_len] = '\0';
    if (with_nul[0] == '\0') {// abstract sockets
        with_nul[0] = '@';
    }
    size_t str_len = strnlen(&local->sun_path[1], NAME_CAPACITY-1)+1;
    if (addr_len != str_len) {
        fprintf(stderr, "(NOTE) strlen and socklen disagrees: %d characters vs %d characters.\n",
            (int)addr_len, (int)str_len);
    }
    return with_nul;
}

// get the local address of the socket and format it using sockaddr2str()
char* local2str(int sock) {
    struct sockaddr_storage local;
    socklen_t len = sizeof(struct sockaddr_storage);
    checkerr(getsockname(sock, (struct sockaddr*)&local, &len),
        "get local address of socket %d", sock);
    return sockaddr2str((struct sockaddr*)&local, len);
}

// format a (pid,uid,gid) triple, using a global buffer to avoid needing to free()
char *creds2str(struct ucred creds) {
    static char str[100]; // > 35+3*strlen("4000000000")
    snprintf(str, sizeof(str), "pid %d running as uid %d and gid %d",
        (int)creds.pid, (int)creds.uid, (int)creds.gid);
    return str;
}

/// get pid, uid and gid of this process
struct ucred ourcreds() {
    struct ucred our = {
        .pid = getpid(),
        .uid = getuid(),
        .gid = getgid()
    };
    return our;
}


/* socket-creation functions */

// Copy name into an uninitialized sockaddr_un after checking that the name isn't too long.
// Supports names that leaves no room for terminating NUL byte.
// Creates unnamed address if name is NULL or empty, and abstract sockets if name[0] is '@'.
socklen_t addr_from_name(const char *name, struct sockaddr_un *addr) {
    name = name==NULL ? "" : name;
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
    socklen_t len = strlen(name);
    if (len > NAME_CAPACITY) {
        fprintf(stderr, "%s is too long for a socket name\n", name);
        exit(1);
    }
    memcpy(&addr->sun_path, name, len); // NUL byte already set by memset()
    if (len == 0) {
        return MINIMAL_SOCKLEN; // create unnamed socket
    } else if (addr->sun_path[0] == '@') {// interpret as unnamed socket
        addr->sun_path[0] = '\0';
    } else if (len < NAME_CAPACITY) {
        len++; // include terminating NUL if possible to improve portability
    }
    return MINIMAL_SOCKLEN+len;
}

// bind() to from if not NULL and connect() to to if not NULL
int name_from_to(const char *from, const char *to) {
    int sock = checkerr(socket(AF_UNIX, SOCK_SEQPACKET, 0), "create unix seqpacket socket");
    struct sockaddr_un addr;
    if (from != NULL) {
        socklen_t size = addr_from_name(from, &addr);
        checkerr(bind(sock, (struct sockaddr*)&addr, size), "bind to %s", from);
    }
    if (to != NULL) {
        socklen_t size = addr_from_name(to, &addr);
        checkerr(connect(sock, (struct sockaddr*)&addr, size), "connect to %s", to);
    }
    const int yes = 1;
    checkerr(setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &yes, sizeof(int)),
        "enable receiving credentials");
    return sock;
}

// create a socket and listen on the address
int listen_on(const char *name) {
    name = name==NULL ? "seqpacket.socket" : name;
    int listener = name_from_to(name, NULL);
    // query socket address because I don't know if it can change
    checkerr(listen(listener, LISTEN_BACKLOG), "listen on %s", name);
    return listener;
}


/* functions for sending and receiving */

// print pid, uid and gid of the other end of a connection
void peercreds(int conn) {
    struct ucred peer = {.pid=0};
    socklen_t ucred_size = sizeof(struct ucred);
    if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &peer, &ucred_size) == -1) {
        fprintf(stderr, "Cannot get peer credentials: %s\n", strerror(errno));
    } else {
        fprintf(stderr, "peer is %s\n", creds2str(peer));
    }
}

// Wrapper around sendmsg() for unix sockets.
// Is limited to sending one set of credentials and writing from a single slice.
ssize_t send_ancillary(
        int conn, char *content_buf, size_t content_len,
        const struct ucred *creds, const int *fds
) {
    struct iovec content = {
        .iov_base = content_buf,
        .iov_len = content_len
    };
    struct msghdr msg = {
        .msg_name = NULL, // socket is connected
        .msg_namelen = 0,
        .msg_iov = &content,
        .msg_iovlen = 1,
        .msg_control = NULL, // might not have any
        .msg_controllen = 0,
        .msg_flags = 0 // unused, but just in case
    };
    size_t num_fds = 0;
    while (fds != NULL && fds[num_fds] != -1) {
        num_fds++;
    }
    msg.msg_controllen
        = (fds==NULL ? 0 : CMSG_SPACE(num_fds*sizeof(int)))
        + (creds==NULL ? 0 : CMSG_SPACE(sizeof(struct ucred)));
    if (msg.msg_controllen != 0) {
        msg.msg_control = malloc(msg.msg_controllen);
        if (msg.msg_control == NULL) {
            exit(1);
        }
        struct cmsghdr *control = CMSG_FIRSTHDR(&msg);
        if (creds != NULL) {
            control->cmsg_level = SOL_SOCKET;
            control->cmsg_type = SCM_CREDENTIALS;
            control->cmsg_len = CMSG_LEN(sizeof(struct ucred));
            *(struct ucred*)CMSG_DATA(control) = *creds;
            fprintf(stderr, "sending credentials %s\n",
                creds2str(*(struct ucred*)CMSG_DATA(control)));
            control = CMSG_NXTHDR(&msg, control);
        }
        if (fds != NULL) {
            control->cmsg_level = SOL_SOCKET;
            control->cmsg_type = SCM_RIGHTS;
            control->cmsg_len = CMSG_LEN(num_fds*sizeof(int));
            memcpy((int*)CMSG_DATA(control), fds, num_fds*sizeof(int));
        }
    }
    // MSG_EOR is not used by unix domain SOCK_SEQPACKET
    ssize_t sent = sendmsg(conn, &msg, MSG_NOSIGNAL);
    if (msg.msg_control != NULL) {
        free(msg.msg_control);
    }
    return sent;
}

// Wrapper around recvmsg() for unix sockets.
// Is limited to receiving one set of credentials and writing to a single slice.
// The received file descriptors are stored in a global buffer for ease of use.
ssize_t recv_ancillary(
        int conn, char *content_buf, size_t content_capacity,
        struct ucred *creds, int **fds
) {
    static union {// static because it's used to store the returned fds
        struct cmsghdr align;
        char buf[1024]; // should cover a bit
        int fds[1024/sizeof(int)];
    } control_buf;
    struct iovec content = {
        .iov_base = content_buf,
        .iov_len = content_capacity
    };
    struct msghdr msg = {
        .msg_name = NULL, // connected, so already know the peers address
        .msg_namelen = 0,
        .msg_iov = &content,
        .msg_iovlen = 1,
        .msg_control = &control_buf.buf,
        .msg_controllen = 1024,
        .msg_flags = 0 // unused, but just in case
    };
    ssize_t content_bytes = recvmsg(conn, &msg, MSG_NOSIGNAL | MSG_TRUNC | MSG_CMSG_CLOEXEC);
    int num_creds = 0;
    int num_fds = 0;
    for (struct cmsghdr *control=CMSG_FIRSTHDR(&msg); control != NULL; control = CMSG_NXTHDR(&msg, control)) {
        if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_CREDENTIALS) {
            if (creds != NULL) {
                *creds = *(struct ucred*)CMSG_DATA(control);
            }
            num_creds++;
        } else if (control->cmsg_level == SOL_SOCKET && control->cmsg_type == SCM_RIGHTS) {
            int num_fds_here = (control->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            // can overlap. I assume the headers are returned in sequential order
            memmove(&control_buf.fds[num_fds], CMSG_DATA(control), num_fds_here*sizeof(int));
            num_fds += num_fds_here;
        } else {
            fprintf(stderr, "Received unexpected type of ancillary message: level %d, type %d\n",
                control->cmsg_level, control->cmsg_type);
        }
    }
    if (num_creds > 1) {
        fprintf(stderr, "Note: received %d credentials, only last one was kept.\n", num_creds);
    }
    if (fds == NULL) {
        fprintf(stderr, "Note: received %d file descriptors, which will be closed.\n", num_fds);
        for (int i=0; i<num_fds; i++) {
            close(control_buf.fds[i]);
            // ignore errors because the fds were unwanted
        }
    } else {
        control_buf.fds[num_fds] = -1;
        *fds = control_buf.fds;
    }
    return content_bytes;
}


/* program modes */

// accept a single incoming connection at a time,
// waiting until the client disconnects before accepting another
void accept_loop(int listener, ssize_t(*perform)(int)) {
    struct sockaddr_un client;
    while (true) {
        socklen_t addrlen = sizeof(struct sockaddr_un);
        int conn = checkerr(accept(listener, (struct sockaddr*)&client, &addrlen),
            "accept connection");
        char *client_str = sockaddr2str((struct sockaddr*)&client, addrlen);
        fprintf(stderr, "Accepted connection from %s\n", client_str);
        peercreds(conn);
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
        struct ucred peer_creds = { .pid=0 };
        int *fds;
        ssize_t received = recv_ancillary(conn, buf, sizeof(buf), &peer_creds, &fds);
        if (received <= 0) {
            // receiving zero bytes can both mean an empty message and end of connection,
            // and there doesn't seem to be a way to tell them apart.
            // Treat it as end of connection to avoid an infinite loop.
            return received;
        }
        if (peer_creds.pid != 0) {
            printf("Peer identified itself as %s\n", creds2str(peer_creds));
        }
        for (; *fds != -1; fds++) {
            printf("Received fd %d\n", *fds);
            close(*fds);
        }
        if ((size_t)received > sizeof(buf)) {
            printf("Could only store %zd of %zd bytes of peers message\n",
                sizeof(buf), received);
            received = sizeof(buf);
        }
        checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        ssize_t sent = send(conn, buf, received, MSG_NOSIGNAL);
        if (sent <= 0) {
            return sent;
        }
    }
}

#define STDIN 0
#define STDOUT 1

// Used to restore nonblocking-ness on exit.
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
    checkerr(fstat(STDIN, &stdinfo), "stat() stdin");
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

// send stdin to socket and socket to stdout, using select() to avoid blocking on either side,
// and disconnect when peer has nothing more to send.
ssize_t interactive_async_read(int conn) {
    make_stdin_nonblocking();
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
        // receiving zero bytes can both mean an empty message and end of connection,
        // and there doesn't seem to be a way to tell them apart.
        // Treat it as end of connection to avoid an infinite loop.
        int flags = MSG_NOSIGNAL | MSG_TRUNC | MSG_DONTWAIT;
        while ((received = recv(conn, &buf, sizeof(buf), flags)) > 0) {
            if ((size_t)received > sizeof(buf)) {
                fprintf(stderr, "Could only store %zd of %zd bytes of peer's message\n",
                    sizeof(buf), received);
                received = sizeof(buf);
            }
            checkerr(fwrite(&buf, received, 1, stdout), "write to stdout");
        }
        if (received == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return received;
        }
        ssize_t to_send;
        while ((to_send = read(STDIN, &buf, sizeof(buf))) > 0) {
            ssize_t sent = send(conn, buf, to_send, MSG_NOSIGNAL);
            if (sent <= 0) {
                return sent;
            }
            // fails with EMSGSIZE if message is too big
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

// exchange stdin with the peer and then send contents of the received fd to stdout
ssize_t interactive_fdpassing(int conn) {
    char buf[1] = "";
    int send_fds[2] = {STDIN, -1};
    ssize_t ret = send_ancillary(conn, buf, 1, NULL, send_fds);
    if (ret < 0) {
        return ret;
    }
    int *fd;
    ret = recv_ancillary(conn, buf, 1, NULL, &fd);
    if (ret < 0) {
        return ret;
    }
    if (fd == NULL) {
        fprintf(stderr, "Peer did not send a file descriptor\n");
        return -1;
    }
    do {
        ret = sendfile(*fd, STDOUT, NULL, 0xffff);
    } while (ret != -1);
    if (errno == ENOSYS || errno == EINVAL) {
        // do it manually
        char buf[BUFFER_SIZE];
        while ((ret = read(*fd, buf, sizeof(buf))) > 0) {
            if ((ret = fwrite(buf, ret, 1, stdout)) <= 0) {
               break;
            }
        }
    }
    checkerr(close(*fd), "close received fd %d", *fd);
    checkerr(fclose(stdin), "close stdin");
    return ret;
}


int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "listen")) {
        accept_loop(listen_on(argv[2]), interactive_async_read);
    } else if (argc == 3 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_on(argv[2]), echo);
    } else if (argc == 4 && !strcmp(argv[1], "fdpass")) {
        client(name_from_to(argv[2], argv[3]), interactive_fdpassing);
    } else if (argc == 3 && !strcmp(argv[1], "fdpass")) {
        client(name_from_to(NULL, argv[2]), interactive_fdpassing);
    } else if (argc == 3 && !strcmp(argv[1], "listen_fdpass")) {
        accept_loop(listen_on(argv[2]), interactive_fdpassing);
    } else if (argc == 3) {
        client(name_from_to(argv[1], argv[2]), interactive_async_read);
    } else if (argc == 2) {
        client(name_from_to(NULL, argv[1]), interactive_async_read);
    } else {
        fprintf(stderr, "unix seqpacket socket client and server\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\tunix_seqpacket [source] path - select()-based client\n");
        fprintf(stderr, "\tunix_seqpacket listen path - select()-based server\n");
        fprintf(stderr, "\tunix_seqpacket echo path - echo server\n");
        fprintf(stderr, "\tunix_seqpacket fdpass [source] path - exchange stdins and read from received fd\n");
        fprintf(stderr, "\tunix_seqpacket listen_fdpass path - exchange stdins and read from received fd\n");
        exit(1);
    }
    return 0;
}

// Things this program doesn't do (for simplicity), but code that wants to be robust should consider:
// * Retry reads, writes, connect(), select() and accept() if they fail with EINTR.
// * Avoid using global variables, or at least make them thread-local.
// * Set CLOEXEC on created sockets. (using SOCK_CLOEXEC and accept4() where available)
