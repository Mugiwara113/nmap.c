#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

typedef struct {
    uint16_t port;
    const char *service;
} ServicePort;

static ServicePort common_services[] = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {5432, "PostgreSQL"},
    {5984, "CouchDB"},
    {6379, "Redis"},
    {8080, "HTTP-Proxy"},
    {8443, "HTTPS-Alt"},
    {27017, "MongoDB"},
    {0, NULL}
};

const char* get_service_name(uint16_t port) {
    for (int i = 0; common_services[i].service != NULL; i++) {
        if (common_services[i].port == port) {
            return common_services[i].service;
        }
    }
    return "Unknown";
}

int check_port(const char *host, uint16_t port, int timeout) {
    struct sockaddr_in addr;
    struct hostent *he;
    int sock;
    int result = PORT_CLOSED;

#ifdef _WIN32
    unsigned long ul = 1;
#endif

    he = gethostbyname(host);
    if (!he) {
        return PORT_FILTERED;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        return PORT_FILTERED;
    }

#ifdef _WIN32
    ioctlsocket(sock, FIONBIO, &ul);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        result = PORT_OPEN;
    } else {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            fd_set write_set;
            struct timeval tv;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            tv.tv_sec = timeout;
            tv.tv_usec = 0;

            if (select(sock + 1, NULL, &write_set, NULL, &tv) > 0) {
                int opt = 0;
                socklen_t len = sizeof(opt);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&opt, &len) == 0 && opt == 0) {
                    result = PORT_OPEN;
                } else {
                    result = PORT_CLOSED;
                }
            } else {
                result = PORT_FILTERED;
            }
        } else {
            result = PORT_CLOSED;
        }
#else
        int err = errno;
        if (err == EINPROGRESS) {
            fd_set write_set;
            struct timeval tv;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            tv.tv_sec = timeout;
            tv.tv_usec = 0;

            if (select(sock + 1, NULL, &write_set, NULL, &tv) > 0) {
                int opt = 0;
                socklen_t len = sizeof(opt);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &opt, &len) == 0 && opt == 0) {
                    result = PORT_OPEN;
                } else {
                    result = PORT_CLOSED;
                }
            } else {
                result = PORT_FILTERED;
            }
        } else {
            result = PORT_CLOSED;
        }
#endif
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return result;
}

#ifdef _WIN32
#include <windows.h>

typedef struct {
    char host[256];
    uint16_t port;
    PortResult *result;
    int timeout;
} ThreadData;

DWORD WINAPI scan_thread(LPVOID arg) {
    ThreadData *data = (ThreadData *)arg;
    int status = check_port(data->host, data->port, data->timeout);
    data->result->port = data->port;
    data->result->status = status;
    strcpy_s(data->result->service, 32, get_service_name(data->port));
    free(data);
    return 0;
}

int scan_host(ScanConfig *config) {
    HANDLE threads[MAX_THREADS];
    int active_threads = 0;
    int current_index = 0;
    int completed_count = 0;

    while (current_index < config->num_results || active_threads > 0) {
        while (active_threads < config->num_threads && current_index < config->num_results) {
            ThreadData *data = malloc(sizeof(ThreadData));
            if (!data) {
                return -1;
            }
            strcpy_s(data->host, 256, config->host);
            data->port = config->ports[current_index];
            data->result = &config->results[current_index];
            data->timeout = config->timeout;

            HANDLE thread = CreateThread(NULL, 0, scan_thread, data, 0, NULL);
            if (thread) {
                threads[active_threads] = thread;
                active_threads++;
            } else {
                free(data);
            }
            current_index++;
        }

        if (active_threads > 0) {
            DWORD result = WaitForMultipleObjects(active_threads, threads, FALSE, 1000);
            if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + active_threads) {
                int completed = result - WAIT_OBJECT_0;
                CloseHandle(threads[completed]);
                threads[completed] = threads[active_threads - 1];
                active_threads--;
                completed_count++;

                if (config->show_progress) {
                    int percent = (completed_count * 100) / config->num_results;
                    fprintf(stderr, "\rProgress: %d/%d ports (%d%%)", completed_count, config->num_results, percent);
                    if (completed_count >= config->num_results) {
                        fprintf(stderr, "\n");
                    }
                }
            }
        }
    }

    return 0;
}

#else
#include <pthread.h>

typedef struct {
    char host[256];
    uint16_t port;
    PortResult *result;
    int timeout;
} ThreadData;

void* scan_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    int status = check_port(data->host, data->port, data->timeout);
    data->result->port = data->port;
    data->result->status = status;
    strcpy(data->result->service, get_service_name(data->port));
    free(data);
    return NULL;
}

int scan_host(ScanConfig *config) {
    pthread_t threads[MAX_THREADS];
    int active_threads = 0;
    int current_index = 0;
    int completed_count = 0;

    while (current_index < config->num_results || active_threads > 0) {
        while (active_threads < config->num_threads && current_index < config->num_results) {
            ThreadData *data = malloc(sizeof(ThreadData));
            if (!data) {
                return -1;
            }
            strcpy(data->host, config->host);
            data->port = config->ports[current_index];
            data->result = &config->results[current_index];
            data->timeout = config->timeout;

            if (pthread_create(&threads[active_threads], NULL, scan_thread, data) == 0) {
                active_threads++;
            } else {
                free(data);
            }
            current_index++;
        }

        if (active_threads > 0) {
            for (int i = 0; i < active_threads; i++) {
                pthread_join(threads[i], NULL);
            }
            completed_count += active_threads;
            active_threads = 0;

            if (config->show_progress) {
                int percent = (completed_count * 100) / config->num_results;
                fprintf(stderr, "\rProgress: %d/%d ports (%d%%)", completed_count, config->num_results, percent);
                if (completed_count >= config->num_results) {
                    fprintf(stderr, "\n");
                }
            }
        }
    }

    return 0;
}
#endif
