// A simple AF_UNIX SOCK_STREAM client or server sporting some async features.

#define _POSIX_C_SOURCE 200809L // 2008.09 needed for SA_RESETHAND and the S_IF* fd types
#include <sys/socket.h> // socket(), struct sockaddr, ...
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
#define LISTEN_BACKLOG 0

// format a socket address, using a global buffer
char* sockaddr2str(struct sockaddr *sa) {
    static char ipstr[100];
    if (sa->sa_family == AF_UNIX) {
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

// create a socket and listen on the address
int listen_on(char *path) {
    path = path==NULL ? "sock_stream" : path;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(struct sockaddr_un)-sizeof(sa_family_t));
    int sock = checkerr(socket(AF_UNIX, SOCK_STREAM, 0), "create unix stream socket");
    checkerr(bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)),
        "bind to %s", sockaddr2str((struct sockaddr*)&addr));
    // query socket address because I don't know if it can change
    checkerr(listen(sock, LISTEN_BACKLOG), "listen on %s", local2str(sock));
    return sock;
}

// connect to path
int connect_to(char *path) {
    path = path==NULL ? "sock_stream" : path;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(struct sockaddr_un)-sizeof(sa_family_t));
    int conn = checkerr(socket(AF_UNIX, SOCK_STREAM, 0), "create unix stream socket");
    checkerr(connect(conn, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)),
        "connect to %s", sockaddr2str((struct sockaddr*)&path));
    return conn;
}

void accept_loop(int sd, ssize_t(*perform)(int, struct sockaddr_un*, void*), void* param) {
    struct sockaddr_storage remote;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    while (1) {
        int conn = checkerr(accept(sd, (struct sockaddr*)&remote, &addrlen), "accept connection");
        char *client = sockaddr2str((struct sockaddr*)&remote);
        printf("Accepted connection from %s\n", client);
        int lastret = perform(conn, (struct sockaddr_un*)&remote, param);
        if (lastret == -1) {
            fprintf(stderr, "Error with %s: %s\n", client, strerror(errno));
        } else {
            printf("Closed by remote\n");
        }
        checkerr(close(conn), "close connection to %s", client);
    }
}

// call perform() then close() the socket
void client(int conn, ssize_t(*perform)(int, struct sockaddr_un*, void*), void* param) {
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
ssize_t echo(int conn, struct sockaddr_un *_remote, void *_nothing) {
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
ssize_t talk_rasync(int conn, struct sockaddr_un *_remote, void *_param) {
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
        accept_loop(listen_on(argv[2]), talk_rasync, NULL);
    } else if (argc == 3 && !strcmp(argv[1], "echo")) {
        accept_loop(listen_on(argv[2]), echo, NULL);
    } else if (argc == 2) {
        client(connect_to(argv[1]), talk_rasync, NULL);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "\tunix_stream path - select()-based client\n");
        fprintf(stderr, "\tunix_stream listen path - select()-based server\n");
        fprintf(stderr, "\tunix_stream echo path - echo server\n");
        exit(1);
    }
    return 0;
}
