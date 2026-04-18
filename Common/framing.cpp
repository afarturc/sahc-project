#include "framing.h"

#include "tcp_util.h"
#include "protocol.h"

#include <stdio.h>

static inline void write_u32_be(uint8_t* out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xFF);
    out[1] = (uint8_t)((v >> 16) & 0xFF);
    out[2] = (uint8_t)((v >>  8) & 0xFF);
    out[3] = (uint8_t)( v        & 0xFF);
}

static inline uint32_t read_u32_be(const uint8_t* in)
{
    return ((uint32_t)in[0] << 24)
         | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] <<  8)
         |  (uint32_t)in[3];
}

int frame_send(int fd, uint8_t type, const uint8_t* payload, uint32_t len)
{
    uint8_t header[FRAME_HEADER_SIZE];
    header[0] = type;
    write_u32_be(header + 1, len);

    if (tcp_send_all(fd, header, FRAME_HEADER_SIZE) != 0) return -1;
    if (len > 0 && tcp_send_all(fd, payload, len) != 0) return -1;
    return 0;
}

int frame_recv(int fd,
               uint8_t* type_out,
               uint8_t* buf, uint32_t buf_cap,
               uint32_t* len_out)
{
    uint8_t header[FRAME_HEADER_SIZE];
    int r = tcp_recv_all(fd, header, FRAME_HEADER_SIZE);
    if (r != 0) return r;

    uint8_t  type = header[0];
    uint32_t len  = read_u32_be(header + 1);

    if (len > FRAME_MAX_PAYLOAD) {
        fprintf(stderr, "frame_recv: oversize payload %u\n", len);
        return -1;
    }
    if (len > buf_cap) {
        fprintf(stderr, "frame_recv: payload %u exceeds buf_cap %u\n", len, buf_cap);
        return -1;
    }

    if (len > 0) {
        if (tcp_recv_all(fd, buf, len) != 0) return -1;
    }
    *type_out = type;
    *len_out  = len;
    return 0;
}
