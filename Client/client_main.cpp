#include "framing.h"
#include "tcp_util.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECV_BUF_CAP 4096

int main(int argc, char** argv)
{
    const char* host = SAHC_DEFAULT_HOST;
    int         port = SAHC_DEFAULT_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    int fd = tcp_connect(host, port);
    if (fd < 0) return 1;
    printf("Client: connected to %s:%d\n", host, port);

    const char* greeting = "hello from sahc client";
    uint32_t glen = (uint32_t)strlen(greeting);
    if (frame_send(fd, MSG_HELLO, (const uint8_t*)greeting, glen) != 0) {
        close(fd);
        return 1;
    }
    printf("Client: sent HELLO (%u bytes)\n", glen);

    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;
    int r = frame_recv(fd, &type, buf, sizeof(buf), &len);
    if (r != 0) {
        fprintf(stderr, "Client: frame_recv failed (r=%d)\n", r);
        close(fd);
        return 1;
    }

    if (type == MSG_HELLO_ACK) {
        printf("Client: HELLO_ACK received (%u bytes): \"%.*s\"\n",
               len, (int)len, (const char*)buf);
    } else if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: server ERROR code=%u\n", code);
    } else {
        fprintf(stderr, "Client: unexpected msg type 0x%02x\n", type);
    }

    close(fd);
    return 0;
}
