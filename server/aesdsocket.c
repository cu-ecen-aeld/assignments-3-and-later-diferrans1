/*
 * aesdsocket.c
 *
 * Build:
 *   gcc -Wall -Wextra -std=gnu11 -o aesdsocket aesdsocket.c
 *
 * Run (needs root for binding some ports; 9000 usually ok as non-root):
 *   ./aesdsocket
 *
 * Behavior:
 *  - Listen on TCP port 9000, accept connections.
 *  - Log "Accepted connection from <ip>" and "Closed connection from <ip>" to syslog.
 *  - Receive stream data; treat a packet as bytes up to and including '\n'.
 *    Each completed packet is appended to /var/tmp/aesdsocketdata.
 *  - After appending a complete packet, read the whole /var/tmp/aesdsocketdata
 *    and send it back to the client.
 *  - Continue accepting new connections until SIGINT or SIGTERM.
 *
 * Requirements from user are implemented here.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>

#define SERVER_PORT "9000"
#define BACKLOG 10
#define RECV_BUF_SZ 1024
#define DATA_FILE "/var/tmp/aesdsocketdata"

/* global signal flag */
static volatile sig_atomic_t do_exit = 0;

static void signal_handler(int signum) {
    (void)signum;
    do_exit = 1;
}

/* send all bytes from buf (len); return 0 on success, -1 on error */
static int send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t nw = send(fd, p, left, 0);
        if (nw < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= (size_t)nw;
        p += nw;
    }
    return 0;
}

/* utility: return peer IP as string (caller-provided buffer) */
static int peername_to_str(int fd, char *out, size_t outlen) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &len) != 0) return -1;

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        if (!inet_ntop(AF_INET, &a->sin_addr, out, outlen)) return -1;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
        if (!inet_ntop(AF_INET6, &a6->sin6_addr, out, outlen)) return -1;
    } else {
        /* unknown family */
        strncpy(out, "unknown", outlen);
        out[outlen-1] = '\0';
    }
    return 0;
}

int main(void) {
    int status;
    struct addrinfo hints = {0}, *res = NULL, *rp;
    int listen_fd = -1;

    /* set up signal handling */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* open syslog */
    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);

    /* prepare addrinfo for IPv4+IPv6 (AI_PASSIVE) */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(NULL, SERVER_PORT, &hints, &res);
    if (status != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(status));
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        closelog();
        return -1;
    }

    /* create/bind socket: try addresses until success */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd == -1) continue;

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

        close(listen_fd);
        listen_fd = -1;
    }

    freeaddrinfo(res);
    if (listen_fd == -1) {
        syslog(LOG_ERR, "Failed to bind to port %s", SERVER_PORT);
        fprintf(stderr, "Failed to bind to port %s\n", SERVER_PORT);
        closelog();
        return -1;
    }

    if (listen(listen_fd, BACKLOG) != 0) {
        syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
        fprintf(stderr, "listen() failed: %s\n", strerror(errno));
        close(listen_fd);
        closelog();
        return -1;
    }

    /* main accept loop */
    while (!do_exit) {
        struct sockaddr_storage cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (conn_fd < 0) {
            if (errno == EINTR && do_exit) break;
            syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
            if (errno == EINTR) continue;
            /* non-fatal: continue accepting */
            continue;
        }

        /* get peer ip string */
        char peer[INET6_ADDRSTRLEN];
        if (cli_addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&cli_addr;
            inet_ntop(AF_INET, &s->sin_addr, peer, sizeof(peer));
        } else if (cli_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&cli_addr;
            inet_ntop(AF_INET6, &s6->sin6_addr, peer, sizeof(peer));
        } else {
            strncpy(peer, "unknown", sizeof(peer));
            peer[sizeof(peer)-1] = '\0';
        }

        syslog(LOG_INFO, "Accepted connection from %s", peer);

        /* per-connection buffer (dynamic) */
        char *acc = NULL;
        size_t acc_len = 0;

        bool conn_done = false;
        while (!conn_done && !do_exit) {
            char rbuf[RECV_BUF_SZ];
            ssize_t nr = recv(conn_fd, rbuf, sizeof(rbuf), 0);
            if (nr < 0) {
                if (errno == EINTR) continue;
                syslog(LOG_ERR, "recv() error from %s: %s", peer, strerror(errno));
                break;
            } else if (nr == 0) {
                /* client closed connection */
                break;
            } else {
                /* append received bytes to acc */
                char *newacc = realloc(acc, acc_len + (size_t)nr);
                if (!newacc) {
                    syslog(LOG_ERR, "malloc/realloc failed: %s", strerror(errno));
                    /* cannot process further - drop connection */
                    free(acc);
                    acc = NULL;
                    acc_len = 0;
                    break;
                }
                acc = newacc;
                memcpy(acc + acc_len, rbuf, (size_t)nr);
                acc_len += (size_t)nr;

                /* process complete packets terminated by '\n' */
                size_t start = 0;
                for (size_t i = 0; i < acc_len; ++i) {
                    if (acc[i] == '\n') {
                        size_t pkt_len = i - start + 1; /* include newline */

                        /* append the packet to DATA_FILE */
                        int fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
                        if (fd < 0) {
                            syslog(LOG_ERR, "open(%s) failed: %s", DATA_FILE, strerror(errno));
                            /* can't append; still attempt to continue */
                        } else {
                            ssize_t wn = write(fd, acc + start, pkt_len);
                            if (wn < 0 || (size_t)wn != pkt_len) {
                                syslog(LOG_ERR, "write(%s) failed: %s", DATA_FILE, strerror(errno));
                                /* continue anyway */
                            }
                            close(fd);
                        }

                        /* After appending, send the full file back to client */
                        /* Open file for reading */
                        FILE *f = fopen(DATA_FILE, "r");
                        if (!f) {
                            syslog(LOG_ERR, "fopen(%s) failed: %s", DATA_FILE, strerror(errno));
                            /* no file to send; continue */
                        } else {
                            if (fseek(f, 0, SEEK_END) == 0) {
                                long fsz = ftell(f);
                                if (fsz < 0) {
                                    syslog(LOG_ERR, "ftell failed: %s", strerror(errno));
                                } else {
                                    if (fseek(f, 0, SEEK_SET) == 0) {
                                        /* allocate buffer for file content -- check size */
                                        size_t to_read = (size_t)fsz;
                                        char *filebuf = NULL;
                                        if (to_read > 0) {
                                            filebuf = malloc(to_read);
                                            if (!filebuf) {
                                                syslog(LOG_ERR, "malloc for file send failed");
                                            } else {
                                                size_t rr = fread(filebuf, 1, to_read, f);
                                                if (rr != to_read) {
                                                    syslog(LOG_ERR, "fread mismatch: wanted %zu got %zu", to_read, rr);
                                                } else {
                                                    if (send_all(conn_fd, filebuf, to_read) != 0) {
                                                        syslog(LOG_ERR, "send_all failed to %s: %s", peer, strerror(errno));
                                                        free(filebuf);
                                                        fclose(f);
                                                        conn_done = true;
                                                        break;
                                                    }
                                                }
                                                free(filebuf);
                                            }
                                        }
                                    } else {
                                        syslog(LOG_ERR, "fseek back failed");
                                    }
                                }
                            } else {
                                syslog(LOG_ERR, "fseek end failed");
                            }
                            fclose(f);
                        }

                        /* move start past this newline for next packet */
                        start = i + 1;
                    }
                } /* end for all bytes */

                /* If there are leftover bytes after last newline, keep them */
                if (start == 0) {
                    /* No newline processed - keep entire acc */
                } else if (start == acc_len) {
                    /* all processed - free acc */
                    free(acc);
                    acc = NULL;
                    acc_len = 0;
                } else {
                    /* some trailing bytes remain: shift them to beginning */
                    size_t newlen = acc_len - start;
                    memmove(acc, acc + start, newlen);
                    char *shrunk = realloc(acc, newlen);
                    if (shrunk || newlen == 0) {
                        acc = shrunk;
                    }
                    acc_len = newlen;
                }
            } /* nr > 0 */
        } /* end per-connection while */

        /* Clean up per-connection */
        if (acc) free(acc);
        /* log closed connection */
        syslog(LOG_INFO, "Closed connection from %s", peer);

        close(conn_fd);
    } /* end main accept loop */

    /* shutdown server */
    close(listen_fd);
    syslog(LOG_INFO, "Server shutting down");
    closelog();
    return 0;
}
