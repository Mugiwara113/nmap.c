#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <time.h>

#define MAX_THREADS 256
#define DEFAULT_TIMEOUT 3

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED
} PortStatus;

typedef struct {
    uint16_t port;
    PortStatus status;
    char service[32];
} PortResult;

typedef struct {
    char host[256];
    uint16_t start_port;
    uint16_t end_port;
    int num_threads;
    int timeout;
    PortResult *results;
    uint16_t *ports;
    int num_results;
    int quiet_mode;
    int json_output;
    int show_progress;
    char output_file[256];
} ScanConfig;

typedef struct {
    char host[256];
    uint16_t start_port;
    uint16_t end_port;
    int timeout;
    PortResult *results;
} ThreadArgs;

int scan_host(ScanConfig *config);
int check_port(const char *host, uint16_t port, int timeout);
const char* get_service_name(uint16_t port);

#endif // SCANNER_H
