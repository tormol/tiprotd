// Wraps the POSIX API as thinly as possible to expose error conditions that a
// Rust wrapper must also handle.
// Compile with `gcc -Wall -Wextra -Wpedantic -std=c11 -g -o mqc mq.c -lrt`

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>
//#define _POSIX_C_SOURCE 200809L // needed for O_CLOEXEC
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void printerr(int err, char* action, char*(*specific)(int), int ex) __attribute__((noreturn));
void printerr(int err, char* action, char*(*specific)(int), int ex) {
    fprintf(stderr, "%s failed with errno %d = %s\n(generic desc: %s)\n",
        action, err, specific(err), strerror(err)
    );
    exit(ex);
}

void usage() __attribute__((noreturn));
void usage() {
    fprintf(stderr, "mqc - work with POSIX message queues\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\tmqc ls : list all existing queues\n\t\t(uses /dev/mqueue/)\n");
    fprintf(stderr, "\tmqc rm /mqname... : mq_unlink() wrapper\n\t\tsupports multiple queues\n");
    fprintf(stderr, "\tmqc stat (/mqname openmode)... : mq_getattr() wrapper\n\t\tsupports multiple queues\n");
    fprintf(stderr, "\tmqc read /mqname openmode : call mq_recv() once\n");
    fprintf(stderr, "\t\tprints priority before message contents\n");
    fprintf(stderr, "\tmqc write /mqname openmode priority message: call mq_send() once\n");
    fprintf(stderr, "openmode format: flags[perms][,capacity,size]\n");
    fprintf(stderr, "\tflags: r=O_RDONLY, w=O_WRONLY, d=O_RDWR, c=O_CREAT, e=O_EXCL\n");
    fprintf(stderr, "\t       n=O_NONBLOCK, s=O_CLOEXEC\n");
    fprintf(stderr, "\tIf there is only a single number it is used for permissions,\n");
    fprintf(stderr, "\tif there are two they are used for capacity and size limit.\n");
    fprintf(stderr, "\tExamples: d wcn8,1024 rce700 rce733,10,200\n");
    exit(1);
}

char* openerrdesc(int err) {
    switch (err) {
        case EACCES: return "EACCES: not permitted to open in this mode, or, more than one '/' in name";
        case EINVAL: return "EINVAL: invalid capacities, or, no slash in name";
        case ENOENT: return "ENOENT: queue doesn't exist, or, name is just '/'";
        case ENAMETOOLONG: return "ENAMETOOLONG - self explanatory";
        case EEXIST: return "EEXIST: queue already exists";
        case EMFILE: return "per-process fd limit reached";
        case ENFILE: return "system-wide fd limit reached";
        case ENOMEM: return "ENOMEM: process out of memory";
        case ENOSPC: return "ENOSPC: system out of memory";
        default: return "undocumented error!";
    }
}

mqd_t parseopts_open(char* qname, char* qopts) {
    int opts = 0;
    while (1) {
        int badopt = 0;
        switch (*qopts) {
            case 'r': opts |= O_RDONLY; break;
            case 'w': opts |= O_WRONLY; break;
            case 'b': opts |= O_RDWR; break;
            case 'c': opts |= O_CREAT; break;
            case 'e': opts |= O_EXCL; break;
            case 'n': opts |= O_NONBLOCK; break;
            case 's': opts |= O_CLOEXEC; break;
            default: badopt = 1; break;
        }
        if (badopt) {
            break;
        }
        qopts++;
    }
    
    char* numstarts[3] = {NULL, NULL, NULL};
    int nums = 0;
    int in_num = 0;
    while (*qopts != '\0') {
        if (*qopts >= '0' && *qopts <= '9') {
            if (!in_num) {
                if (nums == 3) {
                    fprintf(stderr, "Too many numbers in open options\n");
                    exit(1);
                }
                numstarts[nums] = qopts;
                nums++;
                in_num = 1;
            }
        } else if (*qopts == ',') {
            if (!in_num) {
               fprintf(stderr, "Empty number in open options\n");
               exit(1);
            }
            in_num = 0;
        } else if (nums == 0 && !in_num) {
            fprintf(stderr, "Invalid open mode %c\n", *qopts);
            exit(1);
        } else {
            fprintf(stderr, "mode flags must come before other open options\n");
            exit(1);
        }
        qopts++;
    }

    int perms = 0640;
    struct mq_attr caps;
    struct mq_attr* caps_ptr = NULL;
    if (nums%2 != 0) {
        perms = (int)strtoul(numstarts[0], NULL, 8);
    }
    if (nums >= 2) {
        caps.mq_maxmsg = atoi(numstarts[nums-2]);
        caps.mq_msgsize = atoi(numstarts[nums-1]);
        caps_ptr = &caps;
    }

    mqd_t q = mq_open(qname, opts, perms, caps_ptr);
    if (q == -1) {
        printerr(errno, "opening", openerrdesc, 1);
    }
    return q;
}


char* recverrdesc(int err) {
    switch (err) {
        case EAGAIN: return "EAGAIN: queue is empty so the call would have to block";
        case EBADF: return "EBADF: BUG!";
        case EINTR: return "EINTR: interrupted; try again";
        case EMSGSIZE: return "EMSGSIZE: the receive buffer is smaller than the maximum message size";
        case ETIMEDOUT: return "ETIMEDOUT - self explanatory";
        default: return "undocumented error!";
    }
}

char* senderrdesc(int err) {
    switch (err) {
        case EAGAIN: return "EAGAIN: queue is full so the call would have to block";
        case EBADF: return "EBADF: BUG!";
        case EINTR: return "EINTR: interrupted; try again";
        case EMSGSIZE: return "EMSGSIZE: the message is too big for the queue";
        case ETIMEDOUT: return "ETIMEDOUT - self explanatory";
        default: return "undocumented error!";
    }
}

char* unlinkerrdesc(int err) {
    switch (err) {
        case EACCES: return "EACCES: not permitted to delete this queue";
        case ENOENT: return "ENOENT: queue doesn't exist";
        case EINVAL: return "EINVAL: name is empty or does not start with a slash";
        case ENAMETOOLONG: return "ENAMETOOLONG - self explanatory";
        default: return "undocumented error!";
    }
}

int main(int argc, char* const* const argv) {
    if (argc < 2) {
        usage();
    } else if (!strcmp(argv[1], "ls") && argc == 2) {
        DIR *dd = opendir("/dev/mqueue");
        if (dd == NULL) {
            printerr(errno, "oppening /dev/mqueue/", strerror, 1);
        }
        struct dirent *de;
        while ((de = readdir(dd)) != NULL) {
            if (strcmp(de->d_name, "..") && strcmp(de->d_name, ".")) {
                printf("/%s\n", de->d_name);
            }
        }
        closedir(dd);
    } else if (!strcmp(argv[1], "rm") && argc > 2) {
        // if (syscall(SYS_mq_unlink, NULL) == -1) {
        //     printerr(errno, "raw-deleting", unlinkerrdesc, 1);
        // }
        for (int i=2; i<argc; i++) {
            if (mq_unlink(argv[i])) {
                printerr(errno, "deleting", unlinkerrdesc, 1);
            }
        }
    } else if (!strcmp(argv[1], "stat") && argc > 2 && argc%2 == 0) {
        for (int i=2; i<argc; i+=2) {
            mqd_t q = parseopts_open(argv[i], argv[i+1]);
            struct mq_attr attrs;
            if (mq_getattr(q, &attrs)) {
                perror("bug or undocumented error!");
                exit(1);
            }
            printf("maxmsg: %ld\nmsgsize: %ld\ncurmsgs: %ld\nflags: %ld\n",
                attrs.mq_maxmsg, attrs.mq_msgsize, attrs.mq_curmsgs, attrs.mq_flags
            );
            if (mq_close(q)) {
                perror("close queue");
                exit(1);
            }
       }
       // there is no point in exposing mq_setattr(), because the only thing it
       // can change is O_NONBLOCK
    } else if (!strcmp(argv[1], "read") && argc == 4) {
        char buf[1024*1024];
        unsigned int prio;
        mqd_t q = parseopts_open(argv[2], argv[3]);
        ssize_t len = mq_receive(q, buf, 1024*1024, &prio);
        if (len == -1) {
            printerr(errno, "receiving", recverrdesc, 1);
        } else if (mq_close(q)) {
            perror("close queue");
            exit(1);
        }
        printf("%2d ", prio);
        fwrite(&buf, len, 1, stdout);
        putchar('\n');
    } else if (!strcmp(argv[1], "write") && argc == 6) {
        mqd_t q = parseopts_open(argv[2], argv[3]);
        if (mq_send(q, argv[5], strlen(argv[5]), atoi(argv[4]))) {
            printerr(errno, "sending", senderrdesc, 1);
        } else if (mq_close(q)) {
            perror("close queue");
            exit(1);
        }
    } else {
        fprintf(stderr, "unknown operation or wrong number of arguments\n");
        usage();
    }
    // TODO support timeouts for read and write
    // TODO make stat smart and try to show permissions too
    // TODO read from or write to first available (using select or aio or epoll)

    return 0;
}
