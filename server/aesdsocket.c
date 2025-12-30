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
#include <time.h>

#define RCV_FILE "/var/tmp/aesdsocketdata"
#define PORT "9000"
#define MAX_BUF 16384

int server_fd;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
timer_t timerid;

struct thread_data {
    int rcvfd;
    struct sockaddr_in rcvaddr;
};

// Timestamp logic
void write_timestamp() {
    time_t now = time(NULL);
    struct tm *tmp = localtime(&now);
    char buf[128];
    strftime(buf, sizeof(buf), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tmp);

    pthread_mutex_lock(&file_mutex);
    FILE *f = fopen(RCV_FILE, "a");
    if (f) {
        fputs(buf, f);
        fclose(f);
    }
    pthread_mutex_unlock(&file_mutex);
}

static void timer_handler(union sigval sv) { write_timestamp(); }

void cleanup(int sig) {
    syslog(LOG_INFO, "Caught signal, exiting");
    timer_delete(timerid);
    close(server_fd);
    unlink(RCV_FILE);
    closelog();
    exit(0);
}

void *connection_handler(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &data->rcvaddr.sin_addr, addr_str, sizeof(addr_str));
    
    char *buf = malloc(MAX_BUF);
    ssize_t bytes_recvd;
    
    // Receive and Write
    while ((bytes_recvd = recv(data->rcvfd, buf, MAX_BUF, 0)) > 0) {
        pthread_mutex_lock(&file_mutex);
        int f_fd = open(RCV_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        write(f_fd, buf, bytes_recvd);
        close(f_fd);
        
        // If message complete, send file back
        if (memchr(buf, '\n', bytes_recvd)) {
            FILE *f = fopen(RCV_FILE, "r");
            while (fgets(buf, MAX_BUF, f)) {
                send(data->rcvfd, buf, strlen(buf), 0);
            }
            fclose(f);
            pthread_mutex_unlock(&file_mutex);
            break; // Exit loop after sending full file back
        }
        pthread_mutex_unlock(&file_mutex);
    }

    close(data->rcvfd);
    free(buf);
    free(data);
    return NULL;
}

int main(int argc, char *argv[]) {
    openlog("aesdsocket", LOG_PID, LOG_USER);

    // Signal setup
    struct sigaction sa = {.sa_handler = cleanup};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Socket setup
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE};
    struct addrinfo *res;
    getaddrinfo(NULL, PORT, &hints, &res);

    server_fd = socket(res->ai_family, res->ai_socktype, 0);
    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    
    if (bind(server_fd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("Bind failed");
        return -1;
    }
    freeaddrinfo(res);

    if (argc == 2 && strcmp(argv[1], "-d") == 0) daemon(0, 0);

    listen(server_fd, 10);
    unlink(RCV_FILE);

    // Timer setup (10s)
    struct sigevent sev = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = timer_handler};
    timer_create(CLOCK_REALTIME, &sev, &timerid);
    struct itimerspec its = {.it_value.tv_sec = 10, .it_interval.tv_sec = 10};
    timer_settime(timerid, 0, &its, NULL);

    while (1) {
        struct thread_data *data = malloc(sizeof(struct thread_data));
        socklen_t len = sizeof(data->rcvaddr);
        data->rcvfd = accept(server_fd, (struct sockaddr *)&data->rcvaddr, &len);
        
        if (data->rcvfd != -1) {
            pthread_t tid;
            pthread_create(&tid, NULL, connection_handler, data);
            pthread_detach(tid);
        } else {
            free(data);
        }
    }
    return 0;
}