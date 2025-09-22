#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define SERVER_PORT "9000"
#define BACKLOG 10
#define DATAFILE_PATH "/var/tmp/aesdsocketdata"
#define IO_CHUNK 1024

static volatile sig_atomic_t stop_requested = 0;
static int server_fd = -1;

static void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        stop_requested = 1;
        if (server_fd != -1) {
            close(server_fd);
            server_fd = -1;
        }
    }
}

static int install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    if (sigaction(SIGINT, &sa, NULL) < 0) return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    return 0;
}

/* Create server socket. Returns fd or -1 on error. */
static int create_listen_socket(void)
{
    struct addrinfo hints = {0}, *res = NULL, *ai;
    int fd = -1, yes = 1;
    int rv;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rv = getaddrinfo(NULL, SERVER_PORT, &hints, &res);
    if (rv != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1) continue;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            close(fd);
            fd = -1;
            continue;
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
            close(fd);
            fd = -1;
            continue;
        }

        if (listen(fd, BACKLOG) == -1) {
            syslog(LOG_ERR, "listen failed: %s", strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }

        break; // success
    }

    freeaddrinfo(res);

    if (fd == -1) {
        syslog(LOG_ERR, "Failed to bind/listen on port %s", SERVER_PORT);
        return -1;
    }

    return fd;
}


static int append_datafile(const char *buf, size_t len)
{
    int fd = open(DATAFILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;

    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, buf + written, len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        written += (size_t)w;
    }
    close(fd);
    return 0;
}

static int send_datafile_to_client(int client_fd)
{
    int fd = open(DATAFILE_PATH, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    char buf[IO_CHUNK];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t offset = 0;
        while (offset < r) {
            ssize_t s = send(client_fd, buf + offset, (size_t)r - offset, 0);
            if (s <= 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            offset += s;
        }
    }
    close(fd);
    return (r < 0) ? -1 : 0;
}

/* Convert peer sockaddr to printable IP string. */
static void peeraddr_to_ipstr(struct sockaddr *sa, char *out, size_t outlen)
{
    if (!sa) {
        strncpy(out, "unknown", outlen);
        out[outlen - 1] = '\0';
        return;
    }
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &sin->sin_addr, out, outlen);
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, out, outlen);
    } else {
        strncpy(out, "unknown", outlen);
        out[outlen - 1] = '\0';
    }
}

static void handle_connection(int client_fd, struct sockaddr *peer_addr)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    peeraddr_to_ipstr(peer_addr, ipstr, sizeof(ipstr));
    syslog(LOG_INFO, "Accepted connection from %s", ipstr);

    size_t buf_capacity = IO_CHUNK;
    size_t buf_len = 0;
    char *acc = malloc(buf_capacity);
    if (!acc) {
        syslog(LOG_ERR, "malloc failed");
        close(client_fd);
        return;
    }

    char rbuf[IO_CHUNK];

    while (1) {
        ssize_t r = recv(client_fd, rbuf, sizeof(rbuf), 0);
        if (r == 0) break; // client closed
        if (r < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "recv failed: %s", strerror(errno));
            break;
        }

        size_t pos = 0;
        while (pos < (size_t)r) {
            if (buf_len + (r - pos) + 1 > buf_capacity) {
                size_t newcap = buf_capacity * 2;
                while (newcap < buf_len + (r - pos) + 1) newcap *= 2;
                char *tmp = realloc(acc, newcap);
                if (!tmp) {
                    syslog(LOG_ERR, "realloc failed");
                    free(acc);
                    close(client_fd);
                    return;
                }
                acc = tmp;
                buf_capacity = newcap;
            }

            char *newline = memchr(rbuf + pos, '\n', (size_t)r - pos);
            if (newline) {
                size_t chunk_len = (size_t)(newline - (rbuf + pos)) + 1;
                memcpy(acc + buf_len, rbuf + pos, chunk_len);
                buf_len += chunk_len;
                pos += chunk_len;

                if (buf_len > 0) {
                    if (append_datafile(acc, buf_len) != 0) {
                        syslog(LOG_ERR, "append_datafile failed: %s", strerror(errno));
                    } else {
                        if (send_datafile_to_client(client_fd) != 0) {
                            syslog(LOG_ERR, "send_datafile_to_client failed to %s", ipstr);
                        }
                    }
                }
                buf_len = 0; // reset for next packet
            } else {
                size_t chunk_len = (size_t)r - pos;
                memcpy(acc + buf_len, rbuf + pos, chunk_len);
                buf_len += chunk_len;
                pos += chunk_len;
            }
        }
    }

    free(acc);
    syslog(LOG_INFO, "Closed connection from %s", ipstr);
    close(client_fd);
}

int main(int argc, char *argv[])
{
    bool daemonize = false;
    if (argc == 2 && strcmp(argv[1], "-d") == 0) daemonize = true;
    else if (argc > 1) {
        fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
        return EXIT_FAILURE;
    }

    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);

    if (install_signals() < 0) {
        syslog(LOG_ERR, "Failed to install signal handlers: %s", strerror(errno));
        closelog();
        return -1;
    }

    unlink(DATAFILE_PATH);

    server_fd = create_listen_socket();
    if (server_fd < 0) {
        closelog();
        return -1;
    }

    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "fork failed: %s", strerror(errno));
            close(server_fd);
            closelog();
            return -1;
        }
        if (pid > 0) {
            close(server_fd);
            closelog();
            _exit(EXIT_SUCCESS);
        }
        if (setsid() < 0) {
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
    }

    while (!stop_requested) {
        struct sockaddr_storage client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (client_fd < 0) {
            if (stop_requested) break;
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            break;
        }

        handle_connection(client_fd, (struct sockaddr *)&client_addr);
    }

    syslog(LOG_INFO, "Caught signal, exiting");
    if (server_fd != -1) close(server_fd);
    unlink(DATAFILE_PATH);
    closelog();
    return 0;
}
