#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <ctype.h>
#endif

#ifdef _WIN32
#define STRTOK_R(str, delim, saveptr) strtok_s((str), (delim), (saveptr))
#else
#define STRTOK_R(str, delim, saveptr) strtok_r((str), (delim), (saveptr))
#endif

void print_usage(const char *program_name) {
    printf("Usage: %s <target_host> [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -p <start>[-<end>]     Port range or comma-separated ports to scan\n");
    printf("                         (default: 1-1000)\n");
    printf("  -t <threads>           Number of threads (default: 64)\n");
    printf("  -T <timeout>           Connection timeout in seconds (default: 3)\n");
    printf("  -q                     Quiet mode: suppress banner and summary output\n");
    printf("  -v                     Show live progress updates while scanning\n");
    printf("  -o <file>              Write scan results to a file\n");
    printf("  -j                     Output results as JSON\n");
    printf("  -h                     Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s google.com\n", program_name);
    printf("  %s 192.168.1.1 -p 1-65535 -t 128 -T 5\n", program_name);
    printf("  %s localhost -p 80,443,3306,5432\n", program_name);
    printf("  %s localhost -p 80,443,443 -q -o results.txt\n", program_name);
}

static void sort_ports(uint16_t *ports, int count) {
    for (int i = 1; i < count; i++) {
        uint16_t current = ports[i];
        int j = i - 1;
        while (j >= 0 && ports[j] > current) {
            ports[j + 1] = ports[j];
            j--;
        }
        ports[j + 1] = current;
    }
}

static int port_in_list(const uint16_t *ports, int count, uint16_t port) {
    for (int i = 0; i < count; i++) {
        if (ports[i] == port) {
            return 1;
        }
    }
    return 0;
}

int parse_port_spec(const char *spec, uint16_t **ports_out, int *count_out) {
    char buffer[256];
    char *saveptr = NULL;
    char *token;
    uint16_t *ports = NULL;
    int count = 0;
    int capacity = 8;

    if (!spec || !ports_out || !count_out) {
        return -1;
    }

    strncpy(buffer, spec, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    ports = malloc((size_t)capacity * sizeof(uint16_t));
    if (!ports) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    for (token = STRTOK_R(buffer, ",", &saveptr); token != NULL; token = STRTOK_R(NULL, ",", &saveptr)) {
        char *dash = strchr(token, '-');
        char *endptr = NULL;
        long start_val;
        long end_val;
        uint16_t start_port;
        uint16_t end_port;

        while (*token == ' ' || *token == '\t') {
            token++;
        }

        if (*token == '\0') {
            continue;
        }

        if (dash) {
            *dash = '\0';
            start_val = strtol(token, &endptr, 10);
            if (*token == '\0' || *endptr != '\0') {
                fprintf(stderr, "Error: Invalid port range '%s'\n", token);
                free(ports);
                return -1;
            }

            end_val = strtol(dash + 1, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "Error: Invalid port range '%s'\n", token);
                free(ports);
                return -1;
            }

            start_port = (uint16_t)start_val;
            end_port = (uint16_t)end_val;

            if (start_port < 1 || end_port > 65535 || start_port > end_port) {
                fprintf(stderr, "Error: Invalid port range '%s'\n", token);
                free(ports);
                return -1;
            }

            for (uint16_t port = start_port; port <= end_port; port++) {
                if (count >= capacity) {
                    int new_capacity = capacity * 2;
                    uint16_t *resized = realloc(ports, (size_t)new_capacity * sizeof(uint16_t));
                    if (!resized) {
                        fprintf(stderr, "Error: Memory allocation failed\n");
                        free(ports);
                        return -1;
                    }
                    ports = resized;
                    capacity = new_capacity;
                }
                if (!port_in_list(ports, count, port)) {
                    ports[count++] = port;
                }
            }
        } else {
            start_val = strtol(token, &endptr, 10);
            if (*token == '\0' || *endptr != '\0') {
                fprintf(stderr, "Error: Invalid port '%s'\n", token);
                free(ports);
                return -1;
            }

            start_port = (uint16_t)start_val;
            if (start_port < 1 || start_port > 65535) {
                fprintf(stderr, "Error: Invalid port '%s'\n", token);
                free(ports);
                return -1;
            }

            if (count >= capacity) {
                int new_capacity = capacity * 2;
                uint16_t *resized = realloc(ports, (size_t)new_capacity * sizeof(uint16_t));
                if (!resized) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    free(ports);
                    return -1;
                }
                ports = resized;
                capacity = new_capacity;
            }
            if (!port_in_list(ports, count, start_port)) {
                ports[count++] = start_port;
            }
        }
    }

    if (count == 0) {
        free(ports);
        fprintf(stderr, "Error: No valid ports found in '%s'\n", spec);
        return -1;
    }

    sort_ports(ports, count);
    *ports_out = ports;
    *count_out = count;
    return 0;
}

static void print_text_results(FILE *stream, const ScanConfig *config, int open_count, int closed_count, int filtered_count, time_t duration) {
    fprintf(stream, "\n============ SCAN RESULTS ============\n");
    fprintf(stream, "Port    Status     Service\n");
    fprintf(stream, "--------------------------------\n");

    for (int i = 0; i < config->num_results; i++) {
        PortResult *result = &config->results[i];
        const char *status_str = "UNKNOWN";

        switch (result->status) {
            case PORT_OPEN:
                status_str = "OPEN";
                break;
            case PORT_CLOSED:
                status_str = "CLOSED";
                break;
            case PORT_FILTERED:
                status_str = "FILTERED";
                break;
            default:
                break;
        }

        if (result->status == PORT_OPEN) {
            fprintf(stream, "%-7u %-10s %s\n", result->port, status_str, result->service);
        }
    }

    fprintf(stream, "\n============ SUMMARY ============\n");
    fprintf(stream, "Scan completed in %ld seconds\n", duration);
    fprintf(stream, "Open ports:     %d\n", open_count);
    fprintf(stream, "Closed ports:   %d\n", closed_count);
    fprintf(stream, "Filtered ports: %d\n", filtered_count);
    fprintf(stream, "Total scanned:  %d\n", config->num_results);
}

static void print_json_results(FILE *stream, const ScanConfig *config, int open_count, int closed_count, int filtered_count, time_t duration) {
    fprintf(stream, "{\n");
    fprintf(stream, "  \"host\": \"%s\",\n", config->host);
    fprintf(stream, "  \"duration_seconds\": %ld,\n", duration);
    fprintf(stream, "  \"open_ports\": %d,\n", open_count);
    fprintf(stream, "  \"closed_ports\": %d,\n", closed_count);
    fprintf(stream, "  \"filtered_ports\": %d,\n", filtered_count);
    fprintf(stream, "  \"total_scanned\": %d,\n", config->num_results);
    fprintf(stream, "  \"results\": [\n");

    for (int i = 0; i < config->num_results; i++) {
        const PortResult *result = &config->results[i];
        const char *status = "UNKNOWN";

        switch (result->status) {
            case PORT_OPEN:
                status = "OPEN";
                break;
            case PORT_CLOSED:
                status = "CLOSED";
                break;
            case PORT_FILTERED:
                status = "FILTERED";
                break;
            default:
                break;
        }

        fprintf(stream, "    {\"port\": %u, \"status\": \"%s\", \"service\": \"%s\"}",
                result->port, status, result->service);
        if (i + 1 < config->num_results) {
            fprintf(stream, ",");
        }
        fprintf(stream, "\n");
    }

    fprintf(stream, "  ]\n}");
}

int main(int argc, char *argv[]) {
    ScanConfig config = {0};
    uint16_t *requested_ports = NULL;
    int requested_count = 0;
    uint16_t start_port = 1;
    uint16_t end_port = 1000;
    int num_threads = 64;
    int timeout = DEFAULT_TIMEOUT;
    time_t start_time, end_time;
    int open_count = 0, closed_count = 0, filtered_count = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    strncpy(config.host, argv[1], 255);
    config.host[255] = '\0';

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            if (parse_port_spec(argv[++i], &requested_ports, &requested_count) < 0) {
                free(requested_ports);
                return 1;
            }
            start_port = requested_ports[0];
            end_port = requested_ports[requested_count - 1];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[++i]);
            if (num_threads < 1 || num_threads > MAX_THREADS) {
                fprintf(stderr, "Error: Thread count must be between 1 and %d\n", MAX_THREADS);
                free(requested_ports);
                return 1;
            }
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
            if (timeout < 1) {
                fprintf(stderr, "Error: Timeout must be at least 1 second\n");
                free(requested_ports);
                return 1;
            }
        } else if (strcmp(argv[i], "-q") == 0) {
            config.quiet_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            config.show_progress = 1;
        } else if (strcmp(argv[i], "-j") == 0) {
            config.json_output = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(config.output_file, argv[++i], sizeof(config.output_file) - 1);
            config.output_file[sizeof(config.output_file) - 1] = '\0';
        }
    }

    if (!requested_ports) {
        if (parse_port_spec("1-1000", &requested_ports, &requested_count) < 0) {
            return 1;
        }
    }

    config.start_port = start_port;
    config.end_port = end_port;
    config.num_threads = num_threads;
    config.timeout = timeout;
    config.ports = requested_ports;
    config.num_results = requested_count;
    config.results = calloc((size_t)requested_count, sizeof(PortResult));

    if (!config.results) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(requested_ports);
        return 1;
    }

    if (!config.quiet_mode) {
        printf("Starting scan of %s\n", config.host);
        printf("Scanning ports %u-%u with %d threads (timeout: %ds)\n\n",
               start_port, end_port, num_threads, timeout);
    }

    start_time = time(NULL);
    scan_host(&config);
    end_time = time(NULL);

    for (int i = 0; i < config.num_results; i++) {
        PortResult *result = &config.results[i];

        switch (result->status) {
            case PORT_OPEN:
                open_count++;
                break;
            case PORT_CLOSED:
                closed_count++;
                break;
            case PORT_FILTERED:
                filtered_count++;
                break;
            default:
                break;
        }
    }

    FILE *output = stdout;
    if (config.output_file[0] != '\0') {
        output = fopen(config.output_file, "w");
        if (!output) {
            fprintf(stderr, "Error: Unable to open output file '%s'\n", config.output_file);
            free(config.results);
            free(config.ports);
            return 1;
        }
    }

    if (config.output_file[0] != '\0' || !config.quiet_mode) {
        if (config.json_output) {
            print_json_results(output, &config, open_count, closed_count, filtered_count, end_time - start_time);
            fprintf(output, "\n");
        } else {
            print_text_results(output, &config, open_count, closed_count, filtered_count, end_time - start_time);
        }
    }

    if (output != stdout) {
        fclose(output);
    }

    free(config.results);
    free(config.ports);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
