#include "Enclave_u.h"
#include "sgx_urts.h"

#include "framing.h"
#include "tcp_util.h"
#include "protocol.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENCLAVE_FILE "enclave.signed.so"
#define RECV_BUF_CAP 4096

void ocall_print_string(const char* str) { printf("%s", str); }

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int) { g_stop = 1; }

static int init_enclave(sgx_enclave_id_t* eid_out)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
                                          &token, &updated, eid_out, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave failed: 0x%x\n", ret);
        return -1;
    }
    printf("Server: enclave loaded (eid=%lu)\n", *eid_out);
    return 0;
}

static void handle_client(int conn_fd)
{
    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;

    int r = frame_recv(conn_fd, &type, buf, sizeof(buf), &len);
    if (r != 0) {
        fprintf(stderr, "Server: frame_recv failed (r=%d)\n", r);
        return;
    }

    if (type == MSG_HELLO) {
        printf("Server: HELLO from client (%u bytes): \"%.*s\"\n",
               len, (int)len, (const char*)buf);

        const char* reply = "hello from sahc server";
        uint32_t rlen = (uint32_t)strlen(reply);
        if (frame_send(conn_fd, MSG_HELLO_ACK, (const uint8_t*)reply, rlen) != 0) {
            fprintf(stderr, "Server: failed to send HELLO_ACK\n");
        } else {
            printf("Server: sent HELLO_ACK\n");
        }
    } else {
        fprintf(stderr, "Server: unexpected msg type 0x%02x\n", type);
        uint16_t code = E_INVALID_STATE;
        uint8_t  err[2] = { (uint8_t)(code >> 8), (uint8_t)code };
        frame_send(conn_fd, MSG_ERROR, err, sizeof(err));
    }
}

int main(int argc, char** argv)
{
    const char* host = SAHC_DEFAULT_HOST;
    int         port = SAHC_DEFAULT_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigint);

    sgx_enclave_id_t eid = 0;
    if (init_enclave(&eid) != 0) return 1;

    int listen_fd = tcp_listen(host, port, 8);
    if (listen_fd < 0) {
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Server: listening on %s:%d\n", host, port);

    while (!g_stop) {
        int conn_fd = tcp_accept(listen_fd);
        if (conn_fd < 0) {
            if (g_stop) break;
            continue;
        }
        handle_client(conn_fd);
        close(conn_fd);
    }

    close(listen_fd);
    sgx_destroy_enclave(eid);
    printf("Server: shutdown\n");
    return 0;
}
