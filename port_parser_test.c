#define main nmap_main
#include "main.c"
#undef main

#include <assert.h>

int main(void) {
    uint16_t *ports = NULL;
    int count = 0;

    assert(parse_port_spec("80", &ports, &count) == 0);
    assert(count == 1 && ports[0] == 80);
    free(ports);

    assert(parse_port_spec("22-80", &ports, &count) == 0);
    assert(count == 59 && ports[0] == 22 && ports[count - 1] == 80);
    free(ports);

    assert(parse_port_spec("22,80,443,3306", &ports, &count) == 0);
    assert(count == 4 && ports[0] == 22 && ports[count - 1] == 3306);
    free(ports);

    assert(parse_port_spec("443,22", &ports, &count) == 0);
    assert(count == 2 && ports[0] == 22 && ports[count - 1] == 443);
    free(ports);

    assert(parse_port_spec("80,22,80,22-25", &ports, &count) == 0);
    assert(count == 5 && ports[0] == 22 && ports[count - 1] == 80);
    free(ports);

    assert(parse_port_spec("0-10", &ports, &count) == -1);

    puts("port parser checks passed");
    return 0;
}
