/* Gramine variant of the SAHC server.
 *
 * Same wire protocol and dispatcher shape as Server/server_main.cpp, but
 * the trusted core is the EnclaveLogic library compiled with the OpenSSL
 * + Gramine backends instead of the SGX-SDK enclave. There is no eid
 * and no ECALL boundary — sahc_* functions are called directly.
 *
 * Run under the LibOS:
 *   gramine-direct gramine_server          # dev / smoke
 *   gramine-sgx    gramine_server          # production / HW
 */

#include "enclave_logic.h"

#include "framing.h"
#include "parties_loader.h"
#include "tcp_util.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SAHC_HW
#define SAHC_HW 0
#endif

#if SAHC_HW
/* Read a real Intel DCAP quote from Gramine's pseudo-files.
 *
 *   /dev/attestation/user_report_data : write-only, 64 B raw
 *   /dev/attestation/quote            : read-only, returns sgx_quote3_t
 *
 * The first 32 B of user_report_data carry our SHA256(nonce ||
 * enclave_ecdh_pub) binding; the remaining 32 B are zero-padding.
 * After the write, the next read on /dev/attestation/quote returns a
 * fresh DCAP quote that embeds those report_data bytes inside
 * sgx_report_body_t. Only meaningful under gramine-sgx — under
 * gramine-direct the pseudo-files are absent and this returns -1. */
static int read_dcap_quote(const uint8_t user_data32[32],
                           uint8_t* out, size_t out_cap, size_t* out_len)
{
    int wfd = open("/dev/attestation/user_report_data", O_WRONLY);
    if (wfd < 0) {
        fprintf(stderr, "DCAP: open user_report_data failed: %s\n",
                strerror(errno));
        return -1;
    }
    uint8_t urd[64];
    memcpy(urd, user_data32, 32);
    memset(urd + 32, 0, 32);
    ssize_t w = write(wfd, urd, sizeof(urd));
    close(wfd);
    if (w != (ssize_t)sizeof(urd)) {
        fprintf(stderr, "DCAP: write user_report_data short (%zd)\n", w);
        return -1;
    }

    int rfd = open("/dev/attestation/quote", O_RDONLY);
    if (rfd < 0) {
        fprintf(stderr, "DCAP: open quote failed: %s\n", strerror(errno));
        return -1;
    }
    size_t total = 0;
    while (total < out_cap) {
        ssize_t n = read(rfd, out + total, out_cap - total);
        if (n < 0) {
            fprintf(stderr, "DCAP: read quote failed: %s\n", strerror(errno));
            close(rfd); return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(rfd);
    if (total == 0) { fprintf(stderr, "DCAP: empty quote\n"); return -1; }
    *out_len = total;
    fprintf(stderr, "DCAP: quote read OK (%zu bytes)\n", total);
    return 0;
}
#endif /* SAHC_HW */

#define PARTIES_FILE "authorized_parties.json"
#define SEALED_DIR   "data/sealed"
#define SEALED_FILE  "data/sealed/state.bin"
#define SEALED_TMP   "data/sealed/state.bin.tmp"
#define SEAL_BUF_CAP (64 * 1024)
#define RECV_BUF_CAP (32 * 1024)

static void log_to_stderr(const char* s) { fputs(s, stderr); }

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int) { g_stop = 1; }

static pthread_mutex_t state_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  active_cv    = PTHREAD_COND_INITIALIZER;
static int             active_conns = 0;

/* ---------- Sealed state I/O (identical structure to Server, but the
 * "ECALL" calls are direct sahc_* invocations) ---------- */

static int read_file(const char* path, uint8_t* buf, size_t cap, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) return (errno == ENOENT) ? 1 : -1;
    size_t n = fread(buf, 1, cap, f);
    int eof = feof(f), err = ferror(f);
    fclose(f);
    if (err || !eof) return -1;
    *out_len = n;
    return 0;
}

static int write_file_atomic(const char* path, const char* tmp,
                             const uint8_t* buf, size_t len)
{
    mkdir(SEALED_DIR, 0700);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); return -1;
        }
        off += (size_t)n;
    }
    if (fsync(fd) < 0) { close(fd); unlink(tmp); return -1; }
    close(fd);
    if (rename(tmp, path) < 0) { unlink(tmp); return -1; }
    return 0;
}

static int persist_state(void)
{
    pthread_mutex_lock(&state_mutex);
    uint8_t blob[SEAL_BUF_CAP];
    size_t  blob_len = 0;
    int rc = sahc_seal_state(blob, sizeof(blob), &blob_len);
    if (rc != 0) {
        fprintf(stderr, "Server: sahc_seal_state failed (rc=%d)\n", rc);
        pthread_mutex_unlock(&state_mutex);
        return -1;
    }
    if (write_file_atomic(SEALED_FILE, SEALED_TMP, blob, blob_len) != 0) {
        fprintf(stderr, "Server: failed to write %s (%s)\n",
                SEALED_FILE, strerror(errno));
        pthread_mutex_unlock(&state_mutex);
        return -1;
    }
    pthread_mutex_unlock(&state_mutex);
    printf("Server: state persisted (%zu bytes)\n", blob_len);
    return 0;
}

static int try_load_sealed(void)
{
    uint8_t blob[SEAL_BUF_CAP];
    size_t  blob_len = 0;
    int rf = read_file(SEALED_FILE, blob, sizeof(blob), &blob_len);
    if (rf == 1) return 1;
    if (rf != 0) {
        fprintf(stderr, "Server: read %s failed (%s)\n",
                SEALED_FILE, strerror(errno));
        return -1;
    }
    int rc = sahc_unseal_state(blob, blob_len);
    if (rc != 0) {
        fprintf(stderr, "Server: sahc_unseal_state failed (rc=%d)\n", rc);
        return -1;
    }
    printf("Server: state restored from %s (%zu bytes)\n", SEALED_FILE, blob_len);
    return 0;
}

/* ---------- Dispatcher ---------- */

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
    const char* reply = "hello from sahc gramine server";
    return frame_send(fd, MSG_HELLO_ACK, (const uint8_t*)reply,
                      (uint32_t)strlen(reply));
}

static int handle_attest_req(int fd, const uint8_t* payload, uint32_t len,
                             uint32_t* session_handle)
{
    if (len < 1) { send_error(fd, E_INVALID_STATE); return -1; }
    uint8_t id_len = payload[0];
    uint32_t expected = 1u + id_len + PROTO_NONCE_SIZE
                      + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE;
    if (id_len == 0 || id_len > 63 || len != expected) {
        send_error(fd, E_INVALID_STATE);
        return -1;
    }
    if (*session_handle != 0) { send_error(fd, E_INVALID_STATE); return -1; }

    const uint8_t* party_id        = payload + 1;
    const uint8_t* nonce           = party_id + id_len;
    const uint8_t* client_ecdh_pub = nonce + PROTO_NONCE_SIZE;
    const uint8_t* signature       = client_ecdh_pub + PROTO_ECDH_PUB_SIZE;

    printf("Server: ATTEST_REQ party=\"%.*s\"\n", (int)id_len, party_id);

    uint8_t  enclave_ecdh_pub[PROTO_ECDH_PUB_SIZE];
    uint8_t  mrenclave[32], mrsigner[32];
    uint8_t  user_data[PROTO_QUOTE_USER_DATA_SIZE];
    uint8_t  quote_sig[PROTO_QUOTE_SIG_SIZE];
    uint8_t  qe_identity[32];
    uint16_t isv_prod_id = 0, isv_svn = 0;

    int rc = sahc_attest_begin((uint8_t*)party_id, id_len,
        (uint8_t*)nonce, (uint8_t*)client_ecdh_pub, (uint8_t*)signature,
        session_handle, enclave_ecdh_pub,
        mrenclave, mrsigner, &isv_prod_id, &isv_svn,
        user_data, quote_sig, qe_identity);
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -1) wire = E_INVALID_STATE;
        else if (rc == -2) wire = E_UNKNOWN_PARTY;
        else if (rc == -3) wire = E_BAD_SIGNATURE;
        send_error(fd, wire);
        return -1;
    }

#if SAHC_HW
    /* DCAP path: ignore the artesanal mrenclave/mrsigner/quote_sig/
     * qe_identity outputs (we read the real values from
     * /dev/attestation/quote) and emit format=DCAP. user_data32 was
     * computed as SHA256(nonce || enclave_ecdh_pub) by sahc_attest_begin
     * — that's the binding we want in the quote's report_data. */
    uint8_t  quote_buf[PROTO_DCAP_QUOTE_MAX];
    size_t   quote_len = 0;
    if (read_dcap_quote(user_data, quote_buf, sizeof(quote_buf), &quote_len) != 0) {
        send_error(fd, E_INTERNAL);
        return -1;
    }
    size_t resp_len = PROTO_ATTEST_RESP_DCAP_HEADER_SIZE + quote_len;
    uint8_t* resp = (uint8_t*)malloc(resp_len);
    if (!resp) { send_error(fd, E_INTERNAL); return -1; }
    uint8_t* p = resp;
    *p++ = PROTO_QUOTE_FORMAT_DCAP;
    memcpy(p, enclave_ecdh_pub, PROTO_ECDH_PUB_SIZE); p += PROTO_ECDH_PUB_SIZE;
    p[0] = (uint8_t)(quote_len >> 24);
    p[1] = (uint8_t)(quote_len >> 16);
    p[2] = (uint8_t)(quote_len >>  8);
    p[3] = (uint8_t)(quote_len);
    p += 4;
    memcpy(p, quote_buf, quote_len);
    int rc_send = frame_send(fd, MSG_ATTEST_RESP, resp, resp_len);
    free(resp);
    return rc_send;
#else
    uint8_t resp[PROTO_ATTEST_RESP_SAHC_SIZE];
    uint8_t* p = resp;
    *p++ = PROTO_QUOTE_FORMAT_SAHC;
    memcpy(p, mrenclave,        32); p += 32;
    memcpy(p, mrsigner,         32); p += 32;
    put_u16_le(p, isv_prod_id);      p += 2;
    put_u16_le(p, isv_svn);          p += 2;
    memcpy(p, user_data,        32); p += 32;
    memcpy(p, quote_sig,        64); p += 64;
    memcpy(p, qe_identity,      32); p += 32;
    memcpy(p, enclave_ecdh_pub, PROTO_ECDH_PUB_SIZE);
    return frame_send(fd, MSG_ATTEST_RESP, resp, PROTO_ATTEST_RESP_SAHC_SIZE);
#endif
}

static int handle_key_confirm(int fd, const uint8_t* payload, uint32_t len,
                              uint32_t* session_handle)
{
    if (*session_handle == 0 || len != PROTO_KEY_CONFIRM_SIZE) {
        send_error(fd, E_INVALID_STATE); return -1;
    }
    uint8_t role = 0;
    int rc = sahc_key_confirm(*session_handle, (uint8_t*)payload, &role);
    if (rc != 0) {
        uint16_t wire = (rc == -3) ? E_BAD_SIGNATURE : E_INVALID_STATE;
        send_error(fd, wire);
        *session_handle = 0;  /* enclave wiped the slot */
        return -1;
    }
    uint8_t ack[PROTO_KEY_ACK_SIZE] = { 0, role };
    return frame_send(fd, MSG_KEY_ACK, ack, PROTO_KEY_ACK_SIZE);
}

static int handle_upload(int fd, const uint8_t* req, uint32_t req_len,
                         uint32_t* session_handle)
{
    if (*session_handle == 0) { send_error(fd, E_INVALID_STATE); return -1; }
    uint8_t resp[64];
    size_t  resp_len = 0;
    int rc = sahc_upload_records(*session_handle,
                                 (uint8_t*)req, req_len,
                                 resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -2) wire = E_INVALID_STATE;
        else if (rc == -7) wire = E_DECRYPT_FAIL;
        else if (rc == -8) wire = E_UNAUTHORIZED;
        else if (rc == -9) wire = E_INVALID_STATE;
        send_error(fd, wire);
        return (wire == E_DECRYPT_FAIL) ? -1 : 0;
    }
    if (persist_state() != 0) { send_error(fd, E_INTERNAL); return -1; }
    return frame_send(fd, MSG_UPLOAD_ACK, resp, (uint32_t)resp_len);
}

static int handle_query(int fd, const uint8_t* req, uint32_t req_len,
                        uint32_t* session_handle)
{
    if (*session_handle == 0) { send_error(fd, E_INVALID_STATE); return -1; }
    uint8_t resp[64];
    size_t  resp_len = 0;
    int rc = sahc_query(*session_handle, (uint8_t*)req, req_len,
                        resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -2)  wire = E_INVALID_STATE;
        else if (rc == -7)  wire = E_DECRYPT_FAIL;
        else if (rc == -9)  wire = E_INVALID_STATE;
        else if (rc == -10) wire = E_INSUFFICIENT_RECORDS;
        send_error(fd, wire);
        return (wire == E_DECRYPT_FAIL) ? -1 : 0;
    }
    return frame_send(fd, MSG_QUERY_RESP, resp, (uint32_t)resp_len);
}

static void close_session_if_open(uint32_t* handle)
{
    if (*handle == 0) return;
    sahc_close_session(*handle);
    *handle = 0;
}

typedef struct { int fd; } ConnArgs;

static void serve_connection(int conn_fd)
{
    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;
    uint32_t session_handle = 0;

    while (!g_stop) {
        int r = frame_recv(conn_fd, &type, buf, sizeof(buf), &len);
        if (r == 1) { printf("Server: peer closed\n"); break; }
        if (r != 0) { fprintf(stderr, "Server: frame_recv failed\n"); break; }

        int rc = 0;
        switch (type) {
        case MSG_HELLO:        rc = handle_hello(conn_fd, buf, len); break;
        case MSG_ATTEST_REQ:   rc = handle_attest_req(conn_fd, buf, len, &session_handle); break;
        case MSG_KEY_CONFIRM:  rc = handle_key_confirm(conn_fd, buf, len, &session_handle); break;
        case MSG_UPLOAD:       rc = handle_upload(conn_fd, buf, len, &session_handle); break;
        case MSG_QUERY_REQ:    rc = handle_query(conn_fd, buf, len, &session_handle); break;
        case MSG_SESSION_CLOSE:
            close_session_if_open(&session_handle);
            return;
        default:
            send_error(conn_fd, E_INVALID_STATE);
            close_session_if_open(&session_handle);
            return;
        }
        if (rc != 0) break;
    }
    close_session_if_open(&session_handle);
}

static void* conn_thread(void* arg)
{
    ConnArgs* a = (ConnArgs*)arg;
    serve_connection(a->fd);
    close(a->fd);
    free(a);
    pthread_mutex_lock(&active_mutex);
    active_conns--;
    pthread_cond_broadcast(&active_cv);
    pthread_mutex_unlock(&active_mutex);
    return NULL;
}

/* ---------- Direct sahc_* sink for parties_load_json ---------- */

static int sink_begin(void*, uint32_t q) {
    return sahc_parties_begin(q) == 0 ? 0 : -1;
}
static int sink_add_h(void*, uint8_t* id, size_t id_len, uint8_t* pub) {
    return sahc_parties_add_hospital(id, id_len, pub) == 0 ? 0 : -1;
}
static int sink_add_r(void*, uint8_t* id, size_t id_len, uint8_t* pub,
                      uint8_t* blob, size_t blob_len, uint32_t* accepted) {
    return sahc_parties_add_researcher(id, id_len, pub,
                                       blob, blob_len, accepted) == 0 ? 0 : -1;
}
static int sink_end(void*, uint32_t* h, uint32_t* r, uint32_t* rej) {
    return sahc_parties_end(h, r, rej) == 0 ? 0 : -1;
}

int main(int argc, char** argv)
{
    sahc_log_install(log_to_stderr);

    if (argc >= 2 && strcmp(argv[1], "--print-mrenclave") == 0) {
        uint8_t mre[32];
        if (sahc_get_mrenclave(mre) != 0) {
            fprintf(stderr, "gramine_server: sahc_get_mrenclave failed\n");
            return 1;
        }
        for (int i = 0; i < 32; i++) printf("%02x", mre[i]);
        printf("\n");
        return 0;
    }

    const char* host = SAHC_DEFAULT_HOST;
    int         port = SAHC_DEFAULT_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa_int = {};
    sa_int.sa_handler = on_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    int sealed_rc = try_load_sealed();
    if (sealed_rc != 0) {
        if (sealed_rc < 0) {
            fprintf(stderr, "gramine_server: sealed blob present but unusable — "
                            "remove %s to fall back to %s\n",
                    SEALED_FILE, PARTIES_FILE);
            return 1;
        }
        PartiesSink sink = { NULL, sink_begin, sink_add_h, sink_add_r, sink_end };
        uint32_t n_hosp = 0, n_res = 0, n_rej = 0;
        int pl = parties_load_json(PARTIES_FILE, &sink, &n_hosp, &n_res, &n_rej);
        if (pl == -1) {
            fprintf(stderr, "gramine_server: %s not found — run scripts/gen_identity.py "
                            "and scripts/build_authorized_parties.py first\n",
                    PARTIES_FILE);
            return 1;
        } else if (pl != 0) {
            fprintf(stderr, "gramine_server: parties load failed (rc=%d)\n", pl);
            return 1;
        }
        printf("gramine_server: parties loaded — %u hospitals, %u researchers, "
               "%u rejected\n", n_hosp, n_res, n_rej);
        if (persist_state() != 0) {
            fprintf(stderr, "gramine_server: initial seal failed — aborting\n");
            return 1;
        }
    }

    int listen_fd = tcp_listen(host, port, 8);
    if (listen_fd < 0) return 1;
    printf("gramine_server: listening on %s:%d\n", host, port);

    while (!g_stop) {
        int conn_fd = tcp_accept(listen_fd);
        if (conn_fd < 0) { if (g_stop) break; continue; }
        tcp_set_timeout(conn_fd, 30, 30);

        ConnArgs* args = (ConnArgs*)malloc(sizeof(*args));
        if (!args) { close(conn_fd); continue; }
        args->fd = conn_fd;

        pthread_mutex_lock(&active_mutex);
        active_conns++;
        pthread_mutex_unlock(&active_mutex);

        pthread_t tid;
        if (pthread_create(&tid, NULL, conn_thread, args) != 0) {
            pthread_mutex_lock(&active_mutex);
            active_conns--;
            pthread_cond_broadcast(&active_cv);
            pthread_mutex_unlock(&active_mutex);
            close(conn_fd); free(args);
            continue;
        }
        pthread_detach(tid);
    }

    close(listen_fd);
    pthread_mutex_lock(&active_mutex);
    while (active_conns > 0) pthread_cond_wait(&active_cv, &active_mutex);
    pthread_mutex_unlock(&active_mutex);
    printf("gramine_server: shutdown\n");
    return 0;
}
