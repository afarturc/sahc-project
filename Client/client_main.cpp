#include "framing.h"
#include "tcp_util.h"
#include "protocol.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECV_BUF_CAP 4096

static int read_random(uint8_t* out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); return -1; }
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

static void print_hex(const char* label, const uint8_t* data, size_t n)
{
    printf("  %s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", data[i]);
    printf("\n");
}

static inline uint16_t get_u16_le(const uint8_t* p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

int main(int argc, char** argv)
{
    const char* host     = SAHC_DEFAULT_HOST;
    int         port     = SAHC_DEFAULT_PORT;
    const char* party_id = "hosp-santa-maria";
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);
    if (argc >= 4) party_id = argv[3];

    size_t id_len = strlen(party_id);
    if (id_len == 0 || id_len > 63) {
        fprintf(stderr, "Client: invalid party_id (len %zu)\n", id_len);
        return 1;
    }

    int fd = tcp_connect(host, port);
    if (fd < 0) return 1;
    printf("Client: connected to %s:%d (party=%s)\n", host, port, party_id);

    uint8_t nonce[PROTO_NONCE_SIZE];
    if (read_random(nonce, sizeof(nonce)) != 0) { close(fd); return 1; }

    uint8_t req[1 + 63 + PROTO_NONCE_SIZE
                + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE];
    uint32_t req_len = (uint32_t)(1 + id_len + PROTO_NONCE_SIZE
                                  + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE);
    uint8_t* p = req;
    *p++ = (uint8_t)id_len;
    memcpy(p, party_id, id_len);       p += id_len;
    memcpy(p, nonce, PROTO_NONCE_SIZE); p += PROTO_NONCE_SIZE;
    memset(p, 0, PROTO_ECDH_PUB_SIZE);  p += PROTO_ECDH_PUB_SIZE;
    memset(p, 0, PROTO_SIG_SIZE);

    if (frame_send(fd, MSG_ATTEST_REQ, req, req_len) != 0) {
        close(fd); return 1;
    }
    printf("Client: sent ATTEST_REQ (%u bytes)\n", req_len);
    print_hex("nonce (sent)", nonce, PROTO_NONCE_SIZE);

    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;
    int r = frame_recv(fd, &type, buf, sizeof(buf), &len);
    if (r != 0) { close(fd); return 1; }

    if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: server ERROR code=%u\n", code);
        close(fd); return 1;
    }
    if (type != MSG_ATTEST_RESP) {
        fprintf(stderr, "Client: unexpected msg type 0x%02x\n", type);
        close(fd); return 1;
    }
    if (len != PROTO_ATTEST_RESP_SIZE) {
        fprintf(stderr, "Client: bad ATTEST_RESP size %u (expected %u)\n",
                len, PROTO_ATTEST_RESP_SIZE);
        close(fd); return 1;
    }

    const uint8_t* q = buf;
    const uint8_t* mrenclave   = q;                           // 32
    const uint8_t* mrsigner    = mrenclave + 32;              // 32
    uint16_t isv_prod_id = get_u16_le(mrsigner + 32);
    uint16_t isv_svn     = get_u16_le(mrsigner + 32 + 2);
    const uint8_t* user_data   = mrsigner + 32 + 4;           // 32
    const uint8_t* quote_sig   = user_data + 32;              // 64
    const uint8_t* qe_identity = quote_sig + 64;              // 32
    const uint8_t* enclave_pub = qe_identity + 32;            // 64
    (void)enclave_pub;

    printf("Client: ATTEST_RESP received (%u bytes)\n", len);
    print_hex("mrenclave", mrenclave, 32);
    print_hex("mrsigner",  mrsigner, 32);
    printf("  isv_prod_id: %u  isv_svn: %u\n", isv_prod_id, isv_svn);
    print_hex("user_data", user_data, 32);
    print_hex("quote_sig", quote_sig, 64);
    print_hex("qe_ident",  qe_identity, 32);

    if (memcmp(user_data, nonce, PROTO_NONCE_SIZE) == 0) {
        printf("Client: nonce match OK\n");
    } else {
        fprintf(stderr, "Client: NONCE MISMATCH (replay?)\n");
        close(fd); return 1;
    }

    frame_send(fd, MSG_SESSION_CLOSE, NULL, 0);
    close(fd);
    return 0;
}
