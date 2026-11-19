#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define DEVICE_FILE "/dev/aesdchar"
#define PORT        "9000"
#define MAX_BUF     1024

static int server_fd;
static pthread_mutex_t dev_mutex = PTHREAD_MUTEX_INITIALIZER;

struct thread_data {
    int rcvfd;
    struct sockaddr_in rcvaddr;
};

static void cleanup(int sig)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    close(server_fd);
    closelog();
    exit(0);
}

/* Read everything from dev_fd at current position and forward to sock_fd */
static void relay_device_to_socket(int sock_fd, int dev_fd)
{
    char buf[MAX_BUF];
    ssize_t n;
    while ((n = read(dev_fd, buf, sizeof(buf))) > 0)
        send(sock_fd, buf, (size_t)n, 0);
}

void *connection_handler(void *arg)
{
    struct thread_data *data = (struct thread_data *)arg;
    char  buf[MAX_BUF];
    char *packet     = NULL;
    size_t packet_len = 0;
    ssize_t bytes_recvd;

    while ((bytes_recvd = recv(data->rcvfd, buf, sizeof(buf), 0)) > 0) {

        packet = realloc(packet, packet_len + (size_t)bytes_recvd + 1);
        if (!packet) break;
        memcpy(packet + packet_len, buf, (size_t)bytes_recvd);
        packet_len += (size_t)bytes_recvd;
        packet[packet_len] = '\0';

        char *newline;
        while ((newline = memchr(packet, '\n', packet_len)) != NULL) {

            size_t line_len = (size_t)(newline - packet) + 1;

            pthread_mutex_lock(&dev_mutex);

            if (strncmp(packet, "AESDCHAR_IOCSEEKTO:", 19) == 0) {
                unsigned int cmd = 0, offset = 0;
                if (sscanf(packet + 19, "%u,%u", &cmd, &offset) == 2) {
                    struct aesd_seekto seekto = {
                        .write_cmd        = cmd,
                        .write_cmd_offset = offset
                    };
                    int dev_fd = open(DEVICE_FILE, O_RDWR);
                    if (dev_fd >= 0) {
                        if (ioctl(dev_fd, AESDCHAR_IOCSEEKTO, &seekto) == 0)
                            relay_device_to_socket(data->rcvfd, dev_fd);
                        close(dev_fd);
                    }
                }
            } else {
                /* Normal write: append line to char device, echo all contents */
                int dev_fd = open(DEVICE_FILE, O_WRONLY);
                if (dev_fd >= 0) {
                    write(dev_fd, packet, line_len);
                    close(dev_fd);
                }
                dev_fd = open(DEVICE_FILE, O_RDONLY);
                if (dev_fd >= 0) {
                    relay_device_to_socket(data->rcvfd, dev_fd);
                    close(dev_fd);
                }
            }

            pthread_mutex_unlock(&dev_mutex);

            /* Discard the processed line */
            size_t remaining = packet_len - line_len;
            memmove(packet, packet + line_len, remaining);
            packet_len = remaining;
        }
    }

    free(packet);
    close(data->rcvfd);
    free(data);
    return NULL;
}

int main(int argc, char *argv[])
{
    openlog("aesdsocket", LOG_PID, LOG_USER);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cleanup;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *res;
    getaddrinfo(NULL, PORT, &hints, &res);

    server_fd = socket(res->ai_family, res->ai_socktype, 0);
    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(server_fd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("bind failed");
        return -1;
    }
    freeaddrinfo(res);

    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        daemon(0, 0);

    listen(server_fd, 10);

    while (1) {
        struct thread_data *tdata = malloc(sizeof(struct thread_data));
        socklen_t len = sizeof(tdata->rcvaddr);
        tdata->rcvfd  = accept(server_fd,
                               (struct sockaddr *)&tdata->rcvaddr, &len);
        if (tdata->rcvfd != -1) {
            pthread_t tid;
            pthread_create(&tid, NULL, connection_handler, tdata);
            pthread_detach(tid);
        } else {
            free(tdata);
        }
    }
    return 0;
}
