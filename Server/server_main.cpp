#include "Enclave_u.h"
#include "sgx_urts.h"

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

#define ENCLAVE_FILE "enclave.signed.so"
#define PARTIES_FILE "authorized_parties.json"
#define SEALED_DIR   "data/sealed"
#define SEALED_FILE  "data/sealed/state.bin"
#define SEALED_TMP   "data/sealed/state.bin.tmp"
/* Seal blob caps out at sealed_size(sizeof(SealedStatePT)) — that struct
 * is ~22.8 KB plaintext, so 64 KB leaves comfortable headroom. */
#define SEAL_BUF_CAP (64 * 1024)
/* 32 KB is comfortably above the largest UPLOAD frame the enclave will
 * accept (1024 records * 20 B = 20 KB plaintext + 36 B envelope). */
#define RECV_BUF_CAP (32 * 1024)

void ocall_print_string(const char* str) { printf("%s", str); }

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int) { g_stop = 1; }

/* Concurrency primitives for one-thread-per-connection serving.
 *
 *  - state_mutex serialises seal+write so two concurrent UPLOADs can
 *    never reorder the on-disk blob vs the in-enclave state. The
 *    enclave already serialises mutations internally via its own
 *    sessions_mutex; this lock only exists to keep the host-side
 *    "ecall_seal_state → write_file_atomic" pair atomic.
 *  - active_mutex/active_cv let the main thread wait for in-flight
 *    connections to drain before tearing down the enclave on shutdown. */
static pthread_mutex_t state_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  active_cv    = PTHREAD_COND_INITIALIZER;
static int             active_conns = 0;

/* ---------- Sealed state I/O ----------
 *
 * The enclave is the single source of truth; this layer only moves an
 * opaque blob between the enclave and disk. persist_state() is called
 * after every state mutation (initial parties load + each successful
 * upload). load_state() runs once at startup and falls back to the
 * JSON parties loader if the blob is missing or stale. */

static int read_file(const char* path, uint8_t* buf, size_t cap, size_t* out_len)
{
    FILE* f = fopen(path, "rb");
    if (!f) return (errno == ENOENT) ? 1 : -1;
    size_t n = fread(buf, 1, cap, f);
    int    eof = feof(f);
    int    err = ferror(f);
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

static int persist_state(sgx_enclave_id_t eid)
{
    /* Lock spans the seal ECALL and the file write so concurrent
     * persists from two upload threads serialise as whole pairs —
     * otherwise the on-disk blob could end up reflecting an older
     * snapshot than the one the most recent UPLOAD_ACK promised. */
    pthread_mutex_lock(&state_mutex);

    uint8_t blob[SEAL_BUF_CAP];
    size_t  blob_len = 0;
    int     rc = 0;
    sgx_status_t s = ecall_seal_state(eid, &rc, blob, sizeof(blob), &blob_len);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "Server: ecall_seal_state failed (s=0x%x rc=%d)\n", s, rc);
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

/* rc:  0=unsealed OK   1=no blob on disk   -1=blob present but unseal failed */
static int try_load_sealed(sgx_enclave_id_t eid)
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
    int rc = 0;
    sgx_status_t s = ecall_unseal_state(eid, &rc, blob, blob_len);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "Server: ecall_unseal_state failed (s=0x%x rc=%d)\n", s, rc);
        return -1;
    }
    printf("Server: state restored from %s (%zu bytes)\n", SEALED_FILE, blob_len);
    return 0;
}

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

    int rc = 0;
    sgx_status_t s = ecall_attest_begin(eid, &rc,
        (uint8_t*)party_id, (size_t)id_len,
        (uint8_t*)nonce, (uint8_t*)client_ecdh_pub, (uint8_t*)signature,
        session_handle, enclave_ecdh_pub,
        mrenclave, mrsigner, &isv_prod_id, &isv_svn,
        user_data, quote_sig, qe_identity);
    if (s != SGX_SUCCESS) {
        fprintf(stderr, "Server: ecall_attest_begin SGX failure 0x%x\n", s);
        send_error(fd, E_INTERNAL);
        return -1;
    }
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -1) wire = E_INVALID_STATE;
        else if (rc == -2) wire = E_UNKNOWN_PARTY;
        else if (rc == -3) wire = E_BAD_SIGNATURE;
        fprintf(stderr, "Server: attest_begin failed rc=%d (wire=%u)\n",
                rc, wire);
        send_error(fd, wire);
        return -1;
    }
    printf("Server: session handle=%u (KEX done)\n", *session_handle);

    uint8_t resp[PROTO_ATTEST_RESP_SIZE];
    uint8_t* p = resp;
    memcpy(p, mrenclave,        32); p += 32;
    memcpy(p, mrsigner,         32); p += 32;
    put_u16_le(p, isv_prod_id);      p += 2;
    put_u16_le(p, isv_svn);          p += 2;
    memcpy(p, user_data,        32); p += 32;
    memcpy(p, quote_sig,        64); p += 64;
    memcpy(p, qe_identity,      32); p += 32;
    memcpy(p, enclave_ecdh_pub, PROTO_ECDH_PUB_SIZE);

    printf("Server: sending ATTEST_RESP (%u bytes)\n", PROTO_ATTEST_RESP_SIZE);
    return frame_send(fd, MSG_ATTEST_RESP, resp, PROTO_ATTEST_RESP_SIZE);
}

static int handle_key_confirm(sgx_enclave_id_t eid, int fd,
                              const uint8_t* payload, uint32_t len,
                              uint32_t* session_handle)
{
    if (*session_handle == 0) {
        fprintf(stderr, "Server: KEY_CONFIRM with no open session\n");
        send_error(fd, E_INVALID_STATE);
        return -1;
    }
    if (len != PROTO_KEY_CONFIRM_SIZE) {
        fprintf(stderr, "Server: KEY_CONFIRM bad size %u\n", len);
        send_error(fd, E_INVALID_STATE);
        return -1;
    }

    uint8_t role = 0;
    int rc = 0;
    sgx_status_t s = ecall_key_confirm(eid, &rc, *session_handle,
                                       (uint8_t*)payload, &role);
    if (s != SGX_SUCCESS) {
        fprintf(stderr, "Server: ecall_key_confirm SGX failure 0x%x\n", s);
        send_error(fd, E_INTERNAL);
        return -1;
    }
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -1) wire = E_INVALID_STATE;
        else if (rc == -2) wire = E_INVALID_STATE;
        else if (rc == -3) wire = E_BAD_SIGNATURE;
        fprintf(stderr, "Server: key_confirm rejected rc=%d (wire=%u)\n",
                rc, wire);
        send_error(fd, wire);
        /* Enclave already wiped the slot on -2/-3/-5; reflect that. */
        *session_handle = 0;
        return -1;
    }

    printf("Server: session handle=%u READY (role=%u)\n",
           *session_handle, role);

    uint8_t ack[PROTO_KEY_ACK_SIZE];
    ack[0] = 0;     /* status: OK */
    ack[1] = role;  /* assigned role echoed back */
    return frame_send(fd, MSG_KEY_ACK, ack, PROTO_KEY_ACK_SIZE);
}

static int handle_upload(sgx_enclave_id_t eid, int fd,
                         const uint8_t* req, uint32_t req_len,
                         uint32_t* session_handle)
{
    if (*session_handle == 0) {
        fprintf(stderr, "Server: UPLOAD with no open session\n");
        send_error(fd, E_INVALID_STATE);
        return -1;
    }

    /* UPLOAD_ACK is tiny (4 B plaintext + 36 B envelope). */
    uint8_t resp[64];
    size_t  resp_len = 0;
    int     rc       = 0;
    sgx_status_t s = ecall_upload_records(eid, &rc, *session_handle,
                                          (uint8_t*)req, req_len,
                                          resp, sizeof(resp), &resp_len);
    if (s != SGX_SUCCESS) {
        fprintf(stderr, "Server: ecall_upload_records SGX failure 0x%x\n", s);
        send_error(fd, E_INTERNAL);
        return -1;
    }
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -2) wire = E_INVALID_STATE;
        else if (rc == -7) wire = E_DECRYPT_FAIL;
        else if (rc == -8) wire = E_UNAUTHORIZED;
        else if (rc == -9) wire = E_INVALID_STATE;
        fprintf(stderr, "Server: upload rejected rc=%d (wire=%u)\n", rc, wire);
        send_error(fd, wire);
        /* Decrypt failure means the channel is tainted; everything else
         * is a user-side error — keep the session alive for REPL retries. */
        return (wire == E_DECRYPT_FAIL) ? -1 : 0;
    }
    /* Records committed inside the enclave — persist before acknowledging
     * so a crash between ECALL and reply can never claim accepted records
     * the disk doesn't reflect. Failure to persist tears down the
     * connection (the client should retry against a clean snapshot). */
    if (persist_state(eid) != 0) {
        send_error(fd, E_INTERNAL);
        return -1;
    }
    return frame_send(fd, MSG_UPLOAD_ACK, resp, (uint32_t)resp_len);
}

static int handle_query(sgx_enclave_id_t eid, int fd,
                        const uint8_t* req, uint32_t req_len,
                        uint32_t* session_handle)
{
    if (*session_handle == 0) {
        fprintf(stderr, "Server: QUERY with no open session\n");
        send_error(fd, E_INVALID_STATE);
        return -1;
    }

    /* QUERY_RESP is 9 B plaintext + 36 B envelope = 45 B. */
    uint8_t resp[64];
    size_t  resp_len = 0;
    int     rc       = 0;
    sgx_status_t s = ecall_query(eid, &rc, *session_handle,
                                 (uint8_t*)req, req_len,
                                 resp, sizeof(resp), &resp_len);
    if (s != SGX_SUCCESS) {
        fprintf(stderr, "Server: ecall_query SGX failure 0x%x\n", s);
        send_error(fd, E_INTERNAL);
        return -1;
    }
    if (rc != 0) {
        uint16_t wire = E_INTERNAL;
        if      (rc == -2)  wire = E_INVALID_STATE;
        else if (rc == -7)  wire = E_DECRYPT_FAIL;
        else if (rc == -9)  wire = E_INVALID_STATE;
        else if (rc == -10) wire = E_INSUFFICIENT_RECORDS;
        fprintf(stderr, "Server: query rejected rc=%d (wire=%u)\n", rc, wire);
        send_error(fd, wire);
        return (wire == E_DECRYPT_FAIL) ? -1 : 0;
    }
    return frame_send(fd, MSG_QUERY_RESP, resp, (uint32_t)resp_len);
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

typedef struct {
    sgx_enclave_id_t eid;
    int              fd;
} ConnArgs;

static void serve_connection(sgx_enclave_id_t eid, int conn_fd);

static void* conn_thread(void* arg)
{
    ConnArgs* a = (ConnArgs*)arg;
    serve_connection(a->eid, a->fd);
    close(a->fd);
    free(a);

    pthread_mutex_lock(&active_mutex);
    active_conns--;
    pthread_cond_broadcast(&active_cv);
    pthread_mutex_unlock(&active_mutex);
    return NULL;
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
        case MSG_KEY_CONFIRM:
            rc = handle_key_confirm(eid, conn_fd, buf, len, &session_handle);
            break;
        case MSG_UPLOAD:
            rc = handle_upload(eid, conn_fd, buf, len, &session_handle);
            break;
        case MSG_QUERY_REQ:
            rc = handle_query(eid, conn_fd, buf, len, &session_handle);
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
    /* --print-mrenclave: load the enclave, print its MRENCLAVE in hex,
     * exit. Used by scripts/extract_mrenclave.sh to populate the pinned
     * value the client compares against. */
    if (argc >= 2 && strcmp(argv[1], "--print-mrenclave") == 0) {
        sgx_enclave_id_t eid = 0;
        if (init_enclave(&eid) != 0) return 1;
        uint8_t mre[32];
        int rc = 0;
        sgx_status_t s = ecall_get_mrenclave(eid, &rc, mre);
        sgx_destroy_enclave(eid);
        if (s != SGX_SUCCESS || rc != 0) {
            fprintf(stderr, "Server: ecall_get_mrenclave failed (s=0x%x rc=%d)\n",
                    s, rc);
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

    int sealed_rc = try_load_sealed(eid);
    if (sealed_rc != 0) {
        if (sealed_rc < 0) {
            fprintf(stderr, "Server: sealed blob present but unusable — "
                            "remove %s to fall back to %s\n",
                    SEALED_FILE, PARTIES_FILE);
            sgx_destroy_enclave(eid);
            return 1;
        }
        /* Adapt the new callback-sink loader to the SDK ECALL surface.
         * Each callback wraps the matching ecall_* with the boilerplate
         * that translates sgx_status_t/rc into the sink's int convention. */
        struct SgxSinkCtx { sgx_enclave_id_t eid; };
        SgxSinkCtx sink_ctx = { eid };
        PartiesSink sink = { &sink_ctx,
            [](void* c, uint32_t q) -> int {
                auto* s = (SgxSinkCtx*)c; int rc = 0;
                sgx_status_t st = ecall_parties_begin(s->eid, &rc, q);
                return (st != SGX_SUCCESS || rc != 0) ? -1 : 0;
            },
            [](void* c, uint8_t* id, size_t id_len, uint8_t* pub) -> int {
                auto* s = (SgxSinkCtx*)c; int rc = 0;
                sgx_status_t st = ecall_parties_add_hospital(s->eid, &rc,
                                                             id, id_len, pub);
                return (st != SGX_SUCCESS || rc != 0) ? -1 : 0;
            },
            [](void* c, uint8_t* id, size_t id_len, uint8_t* pub,
               uint8_t* blob, size_t blob_len, uint32_t* accepted) -> int {
                auto* s = (SgxSinkCtx*)c; int rc = 0;
                sgx_status_t st = ecall_parties_add_researcher(s->eid, &rc,
                                                               id, id_len, pub,
                                                               blob, blob_len,
                                                               accepted);
                return (st != SGX_SUCCESS || rc != 0) ? -1 : 0;
            },
            [](void* c, uint32_t* h, uint32_t* r, uint32_t* rej) -> int {
                auto* s = (SgxSinkCtx*)c; int rc = 0;
                sgx_status_t st = ecall_parties_end(s->eid, &rc, h, r, rej);
                return (st != SGX_SUCCESS || rc != 0) ? -1 : 0;
            }
        };
        uint32_t n_hosp = 0, n_res = 0, n_rej = 0;
        int pl = parties_load_json(PARTIES_FILE, &sink,
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
            if (persist_state(eid) != 0) {
                fprintf(stderr, "Server: initial seal failed — aborting\n");
                sgx_destroy_enclave(eid);
                return 1;
            }
        }
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
        /* 30 s idle on either direction kills the connection — protects
         * the server from a client that handshakes and never speaks
         * again, and bounds how long a stuck send blocks a worker. */
        tcp_set_timeout(conn_fd, 30, 30);

        ConnArgs* args = (ConnArgs*)malloc(sizeof(*args));
        if (!args) {
            fprintf(stderr, "Server: malloc(ConnArgs) failed — dropping conn\n");
            close(conn_fd);
            continue;
        }
        args->eid = eid;
        args->fd  = conn_fd;

        pthread_mutex_lock(&active_mutex);
        active_conns++;
        pthread_mutex_unlock(&active_mutex);

        pthread_t tid;
        int prc = pthread_create(&tid, NULL, conn_thread, args);
        if (prc != 0) {
            fprintf(stderr, "Server: pthread_create failed (rc=%d)\n", prc);
            pthread_mutex_lock(&active_mutex);
            active_conns--;
            pthread_cond_broadcast(&active_cv);
            pthread_mutex_unlock(&active_mutex);
            close(conn_fd);
            free(args);
            continue;
        }
        pthread_detach(tid);
    }

    close(listen_fd);

    /* Drain in-flight connections before destroying the enclave —
     * sgx_destroy_enclave with active TCS would crash the workers. */
    pthread_mutex_lock(&active_mutex);
    if (active_conns > 0) {
        printf("Server: waiting for %d in-flight connection(s) to drain\n",
               active_conns);
    }
    while (active_conns > 0) {
        pthread_cond_wait(&active_cv, &active_mutex);
    }
    pthread_mutex_unlock(&active_mutex);

    sgx_destroy_enclave(eid);
    printf("Server: shutdown\n");
    return 0;
}
