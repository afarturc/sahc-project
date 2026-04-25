#include "Enclave_u.h"
#include "sgx_urts.h"

#include "framing.h"
#include "parties_loader.h"
#include "tcp_util.h"
#include "protocol.h"
#include "types.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENCLAVE_FILE "enclave.signed.so"
#define PARTIES_FILE "authorized_parties.json"
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

static void send_error(int fd, uint16_t code)
{
    uint8_t err[2] = { (uint8_t)(code >> 8), (uint8_t)code };
    frame_send(fd, MSG_ERROR, err, sizeof(err));
}

static inline void put_u16_le(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static int handle_hello(int fd, const uint8_t* payload, uint32_t len)
{
    printf("Server: HELLO (%u bytes): \"%.*s\"\n",
           len, (int)len, (const char*)payload);
    const char* reply = "hello from sahc server";
    return frame_send(fd, MSG_HELLO_ACK, (const uint8_t*)reply,
                      (uint32_t)strlen(reply));
}

static int handle_attest_req(sgx_enclave_id_t eid, int fd,
                             const uint8_t* payload, uint32_t len,
                             uint32_t* session_handle)
{
    if (len < 1) { send_error(fd, E_INVALID_STATE); return -1; }
    uint8_t id_len = payload[0];
    uint32_t expected = 1u + id_len + PROTO_NONCE_SIZE
                      + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE;
    if (id_len == 0 || id_len > 63 || len != expected) {
        fprintf(stderr, "Server: ATTEST_REQ malformed (len=%u, id_len=%u)\n",
                len, id_len);
        send_error(fd, E_INVALID_STATE);
        return -1;
    }

    if (*session_handle != 0) {
        fprintf(stderr, "Server: duplicate ATTEST_REQ on handle %u\n",
                *session_handle);
        send_error(fd, E_INVALID_STATE);
        return -1;
    }

    const uint8_t* party_id         = payload + 1;
    const uint8_t* nonce            = party_id + id_len;
    const uint8_t* client_ecdh_pub  = nonce + PROTO_NONCE_SIZE;
    (void)client_ecdh_pub;  // signature verified at Passo 4b
    (void)(nonce + PROTO_NONCE_SIZE + PROTO_ECDH_PUB_SIZE);  // signature

    printf("Server: ATTEST_REQ party=\"%.*s\"\n", (int)id_len, party_id);

    int open_rc = 0;
    sgx_status_t so = ecall_open_session(eid, &open_rc,
                                         (uint8_t*)party_id, (size_t)id_len,
                                         session_handle);
    if (so != SGX_SUCCESS || open_rc != 0 || *session_handle == 0) {
        fprintf(stderr, "Server: ecall_open_session failed (s=0x%x rc=%d)\n",
                so, open_rc);
        send_error(fd, E_INTERNAL);
        return -1;
    }
    printf("Server: session handle=%u\n", *session_handle);

    uint8_t  mrenclave[32];
    uint8_t  mrsigner[32];
    uint16_t isv_prod_id = 0;
    uint16_t isv_svn     = 0;
    uint8_t  user_data[USER_DATA_SIZE];
    uint8_t  signature[QUOTE_SIGNATURE_SIZE];
    uint8_t  qe_identity[32];

    int ret_status = 0;
    sgx_status_t s = ecall_generate_report(eid, &ret_status,
                                           *session_handle,
                                           (uint8_t*)nonce,
                                           mrenclave, mrsigner,
                                           &isv_prod_id, &isv_svn,
                                           user_data,
                                           signature, qe_identity);
    if (s != SGX_SUCCESS || ret_status != 0) {
        fprintf(stderr, "Server: ecall_generate_report failed (s=0x%x rc=%d)\n",
                s, ret_status);
        send_error(fd, E_INTERNAL);
        return -1;
    }

    uint8_t resp[PROTO_ATTEST_RESP_SIZE];
    uint8_t* p = resp;
    memcpy(p, mrenclave,    32); p += 32;
    memcpy(p, mrsigner,     32); p += 32;
    put_u16_le(p, isv_prod_id);  p += 2;
    put_u16_le(p, isv_svn);      p += 2;
    memcpy(p, user_data,    32); p += 32;
    memcpy(p, signature,    64); p += 64;
    memcpy(p, qe_identity,  32); p += 32;
    // enclave_ecdh_pub placeholder — real key kicks in at Passo 4b.
    memset(p, 0, PROTO_ECDH_PUB_SIZE);

    printf("Server: sending ATTEST_RESP (%u bytes)\n", PROTO_ATTEST_RESP_SIZE);
    return frame_send(fd, MSG_ATTEST_RESP, resp, PROTO_ATTEST_RESP_SIZE);
}

static void close_session_if_open(sgx_enclave_id_t eid, uint32_t* handle)
{
    if (*handle == 0) return;
    int rc = 0;
    sgx_status_t s = ecall_close_session(eid, &rc, *handle);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "Server: ecall_close_session(%u) failed (s=0x%x rc=%d)\n",
                *handle, s, rc);
    } else {
        printf("Server: session handle=%u closed\n", *handle);
    }
    *handle = 0;
}

static void serve_connection(sgx_enclave_id_t eid, int conn_fd)
{
    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;
    uint32_t session_handle = 0;

    while (!g_stop) {
        int r = frame_recv(conn_fd, &type, buf, sizeof(buf), &len);
        if (r == 1) {
            printf("Server: peer closed\n");
            break;
        }
        if (r != 0) {
            fprintf(stderr, "Server: frame_recv failed\n");
            break;
        }

        int rc = 0;
        switch (type) {
        case MSG_HELLO:
            rc = handle_hello(conn_fd, buf, len);
            break;
        case MSG_ATTEST_REQ:
            rc = handle_attest_req(eid, conn_fd, buf, len, &session_handle);
            break;
        case MSG_SESSION_CLOSE:
            printf("Server: SESSION_CLOSE received\n");
            close_session_if_open(eid, &session_handle);
            return;
        default:
            fprintf(stderr, "Server: unexpected msg type 0x%02x\n", type);
            send_error(conn_fd, E_INVALID_STATE);
            close_session_if_open(eid, &session_handle);
            return;
        }

        if (rc != 0) break;
    }

    close_session_if_open(eid, &session_handle);
}

int main(int argc, char** argv)
{
    const char* host = SAHC_DEFAULT_HOST;
    int         port = SAHC_DEFAULT_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);

    // sigaction (not signal()) so SIGINT does NOT carry SA_RESTART —
    // otherwise accept() is auto-restarted on Ctrl+C and g_stop is never
    // re-checked.
    struct sigaction sa_int = {};
    sa_int.sa_handler = on_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    sgx_enclave_id_t eid = 0;
    if (init_enclave(&eid) != 0) return 1;

    uint32_t n_hosp = 0, n_res = 0, n_rej = 0;
    int pl = parties_load_into_enclave(eid, PARTIES_FILE,
                                       &n_hosp, &n_res, &n_rej);
    if (pl == -1) {
        fprintf(stderr, "Server: %s not found — run scripts/gen_identity.py "
                        "and scripts/build_authorized_parties.py first\n",
                PARTIES_FILE);
    } else if (pl != 0) {
        fprintf(stderr, "Server: parties load failed (rc=%d)\n", pl);
        sgx_destroy_enclave(eid);
        return 1;
    } else {
        printf("Server: parties loaded — %u hospitals, %u researchers, "
               "%u rejected\n", n_hosp, n_res, n_rej);
    }

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
        serve_connection(eid, conn_fd);
        close(conn_fd);
    }

    close(listen_fd);
    sgx_destroy_enclave(eid);
    printf("Server: shutdown\n");
    return 0;
}
