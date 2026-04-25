#include "session.h"

#include "csv_loader.h"
#include "framing.h"
#include "identity.h"
#include "patient.h"
#include "secure_frame.h"
#include "tcp_util.h"
#include "protocol.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECV_BUF_CAP       (32 * 1024)
#define MAX_CLIENT_RECORDS 1024

/* MRENCLAVE the client is willing to talk to. Mirrors SIMULATED_MRENCLAVE
 * in Enclave.cpp; on Fase 4 (DCAP real) this gets replaced by the value
 * sgx_sign emits for the signed enclave binary. */
static const uint8_t EXPECTED_MRENCLAVE[32] = {
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89
};

static const uint8_t ATTEST_PREFIX[] = "SAHC-attest-v1";
#define ATTEST_PREFIX_LEN (sizeof(ATTEST_PREFIX) - 1)
static const uint8_t HKDF_SALT[] = "SAHC-v1";
#define HKDF_SALT_LEN (sizeof(HKDF_SALT) - 1)

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

static void write_u32_le(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v        & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t read_u32_le(const uint8_t* p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

#define VLOG(verbose, ...) do { if (verbose) printf(__VA_ARGS__); } while (0)

int client_session_open(const char* host, int port, const char* party_id,
                        ClientSession* out, int verbose)
{
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    size_t id_len = strlen(party_id);
    if (id_len == 0 || id_len > 63) {
        fprintf(stderr, "Client: invalid party_id (len %zu)\n", id_len);
        return -1;
    }

    char key_path[128];
    snprintf(key_path, sizeof(key_path), "parties/%s.key", party_id);
    EVP_PKEY* lt_key = identity_load_pem(key_path);
    if (!lt_key) {
        fprintf(stderr, "Client: failed to load %s\n", key_path);
        return -1;
    }
    VLOG(verbose, "Client: identity loaded from %s\n", key_path);

    EVP_PKEY* eph_priv = NULL;
    uint8_t   client_ecdh_pub[ID_PUB_SIZE];
    if (ecdh_keygen(&eph_priv, client_ecdh_pub) != 0) {
        fprintf(stderr, "Client: ECDH keygen failed\n");
        identity_free(lt_key);
        return -1;
    }
    if (verbose) print_hex("client_ecdh_pub", client_ecdh_pub, 16);

    int fd = tcp_connect(host, port);
    if (fd < 0) { identity_free(eph_priv); identity_free(lt_key); return -1; }
    tcp_set_timeout(fd, 30, 30);
    VLOG(verbose, "Client: connected to %s:%d (party=%s)\n", host, port, party_id);

    uint8_t nonce[PROTO_NONCE_SIZE];
    if (read_random(nonce, sizeof(nonce)) != 0) goto fail;

    uint8_t to_sign[ATTEST_PREFIX_LEN + PROTO_NONCE_SIZE + PROTO_ECDH_PUB_SIZE];
    {
        size_t off = 0;
        memcpy(to_sign + off, ATTEST_PREFIX, ATTEST_PREFIX_LEN); off += ATTEST_PREFIX_LEN;
        memcpy(to_sign + off, nonce, PROTO_NONCE_SIZE);          off += PROTO_NONCE_SIZE;
        memcpy(to_sign + off, client_ecdh_pub, PROTO_ECDH_PUB_SIZE);
    }
    uint8_t signature[PROTO_SIG_SIZE];
    if (identity_sign(lt_key, to_sign, sizeof(to_sign), signature) != 0) {
        fprintf(stderr, "Client: identity_sign failed\n");
        goto fail;
    }

    {
        uint8_t req[1 + 63 + PROTO_NONCE_SIZE
                    + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE];
        uint32_t req_len = (uint32_t)(1 + id_len + PROTO_NONCE_SIZE
                                      + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE);
        uint8_t* p = req;
        *p++ = (uint8_t)id_len;
        memcpy(p, party_id, id_len);                    p += id_len;
        memcpy(p, nonce, PROTO_NONCE_SIZE);             p += PROTO_NONCE_SIZE;
        memcpy(p, client_ecdh_pub, PROTO_ECDH_PUB_SIZE); p += PROTO_ECDH_PUB_SIZE;
        memcpy(p, signature, PROTO_SIG_SIZE);

        if (frame_send(fd, MSG_ATTEST_REQ, req, req_len) != 0) goto fail;
        VLOG(verbose, "Client: sent ATTEST_REQ (%u bytes)\n", req_len);
    }

    /* All declarations after the first `goto fail` must be uninitialized
     * — C++ rejects gotos that skip past initializers. frame_recv writes
     * type/len before we read them. */
    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type;
    uint32_t len;
    if (frame_recv(fd, &type, buf, sizeof(buf), &len) != 0) goto fail;
    if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: server ERROR code=%u\n", code);
        goto fail;
    }
    if (type != MSG_ATTEST_RESP || len != PROTO_ATTEST_RESP_SIZE) {
        fprintf(stderr, "Client: bad ATTEST_RESP (type=0x%02x len=%u)\n", type, len);
        goto fail;
    }

    {
        const uint8_t* q = buf;
        const uint8_t* mrenclave   = q;
        const uint8_t* mrsigner    = mrenclave + 32;
        uint16_t isv_prod_id = get_u16_le(mrsigner + 32);
        uint16_t isv_svn     = get_u16_le(mrsigner + 32 + 2);
        const uint8_t* user_data   = mrsigner + 32 + 4;
        const uint8_t* enclave_pub = user_data + 32 + 64 + 32;
        (void)isv_prod_id; (void)isv_svn;

        VLOG(verbose, "Client: ATTEST_RESP received (%u bytes)\n", len);
        if (verbose) {
            print_hex("mrenclave",   mrenclave, 32);
            printf("  isv_prod_id: %u  isv_svn: %u\n", isv_prod_id, isv_svn);
            print_hex("enclave_pub", enclave_pub, 16);
        }

        if (memcmp(mrenclave, EXPECTED_MRENCLAVE, 32) != 0) {
            fprintf(stderr, "Client: MRENCLAVE MISMATCH (wrong enclave)\n");
            goto fail;
        }
        VLOG(verbose, "Client: MRENCLAVE pin OK\n");

        uint8_t to_hash[PROTO_NONCE_SIZE + PROTO_ECDH_PUB_SIZE];
        memcpy(to_hash, nonce, PROTO_NONCE_SIZE);
        memcpy(to_hash + PROTO_NONCE_SIZE, enclave_pub, PROTO_ECDH_PUB_SIZE);
        uint8_t expected[ID_HASH_SIZE];
        if (crypto_sha256(to_hash, sizeof(to_hash), expected) != 0 ||
            memcmp(user_data, expected, ID_HASH_SIZE) != 0) {
            fprintf(stderr, "Client: user_data mismatch (replay or tampered)\n");
            goto fail;
        }
        VLOG(verbose, "Client: user_data binding OK\n");

        uint8_t shared[ID_SHARED_SIZE];
        if (ecdh_compute_shared(eph_priv, enclave_pub, shared) != 0) {
            fprintf(stderr, "Client: ECDH derive failed\n");
            goto fail;
        }
        uint8_t prk[32];
        if (crypto_hmac_sha256(HKDF_SALT, HKDF_SALT_LEN,
                               shared, ID_SHARED_SIZE, prk) != 0) {
            fprintf(stderr, "Client: HKDF-extract failed\n");
            memset(shared, 0, sizeof(shared));
            goto fail;
        }
        memset(shared, 0, sizeof(shared));

        if (crypto_hkdf_expand(prk, 32, "session-aes128",
                               out->session_key, 16) != 0 ||
            crypto_hkdf_expand(prk, 32, "iv-prefix",
                               out->iv_prefix, 4) != 0) {
            fprintf(stderr, "Client: HKDF-expand failed\n");
            memset(prk, 0, sizeof(prk));
            goto fail;
        }
        memset(prk, 0, sizeof(prk));

        if (verbose) {
            uint8_t kh[32];
            crypto_sha256(out->session_key, 16, kh);
            printf("Client: session_key derived (sha256(key)[0..7]):");
            for (int i = 0; i < 8; i++) printf(" %02x", kh[i]);
            printf("\n");
        }
    }

    {
        uint8_t mac[PROTO_KEY_CONFIRM_SIZE];
        if (crypto_hmac_sha256(out->session_key, 16,
                               (const uint8_t*)"confirm", 7, mac) != 0) {
            fprintf(stderr, "Client: HMAC for KEY_CONFIRM failed\n");
            goto fail;
        }
        if (frame_send(fd, MSG_KEY_CONFIRM, mac, PROTO_KEY_CONFIRM_SIZE) != 0)
            goto fail;
    }

    if (frame_recv(fd, &type, buf, sizeof(buf), &len) != 0) goto fail;
    if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: KEY_CONFIRM rejected, server ERROR code=%u\n", code);
        goto fail;
    }
    if (type != MSG_KEY_ACK || len != PROTO_KEY_ACK_SIZE) {
        fprintf(stderr, "Client: bad KEY_ACK (type=0x%02x len=%u)\n", type, len);
        goto fail;
    }
    if (buf[0] != 0) {
        fprintf(stderr, "Client: KEY_ACK status=%u (rejected)\n", buf[0]);
        goto fail;
    }
    out->role = buf[1];
    if (verbose) {
        const char* role_str =
            (out->role == PROTO_ROLE_HOSPITAL)   ? "HOSPITAL" :
            (out->role == PROTO_ROLE_RESEARCHER) ? "RESEARCHER" : "?";
        printf("Client: KEY_ACK status=0 role=%s — session READY\n", role_str);
    }

    out->fd       = fd;
    out->seq_send = 0;
    out->seq_recv = 0;
    identity_free(eph_priv);
    identity_free(lt_key);
    return 0;

fail:
    memset(out->session_key, 0, sizeof(out->session_key));
    memset(out->iv_prefix,   0, sizeof(out->iv_prefix));
    if (eph_priv) identity_free(eph_priv);
    if (lt_key)   identity_free(lt_key);
    if (fd >= 0)  close(fd);
    out->fd = -1;
    return -1;
}

void client_session_close(ClientSession* s)
{
    if (s == NULL || s->fd < 0) return;
    frame_send(s->fd, MSG_SESSION_CLOSE, NULL, 0);
    close(s->fd);
    s->fd = -1;
    memset(s->session_key, 0, sizeof(s->session_key));
    memset(s->iv_prefix,   0, sizeof(s->iv_prefix));
}

int client_session_upload_csv(ClientSession* s, const char* csv_path,
                              uint32_t* out_accepted, int verbose)
{
    if (s == NULL || s->fd < 0) return -1;

    PatientRecord recs[MAX_CLIENT_RECORDS];
    int n = csv_load(csv_path, recs, MAX_CLIENT_RECORDS);
    if (n <= 0) {
        fprintf(stderr, "upload: cannot load %s\n", csv_path);
        return 0;
    }

    VLOG(verbose, "upload: sending %d records from %s\n", n, csv_path);
    if (sf_send(s->fd, MSG_UPLOAD, &s->seq_send, s->session_key, s->iv_prefix,
                (const uint8_t*)recs,
                (uint32_t)(n * (int)sizeof(PatientRecord))) != 0) {
        fprintf(stderr, "upload: sf_send failed\n");
        return -1;
    }

    uint8_t  ack[64];
    uint32_t ack_len  = 0;
    uint8_t  ack_type = 0;
    if (sf_recv(s->fd, &s->seq_recv, s->session_key, s->iv_prefix, &ack_type,
                ack, sizeof(ack), &ack_len) != 0) {
        fprintf(stderr, "upload: sf_recv failed\n");
        return -1;
    }
    if (ack_type == MSG_ERROR && ack_len >= 2) {
        uint16_t code = ((uint16_t)ack[0] << 8) | ack[1];
        if (code == E_UNAUTHORIZED) {
            fprintf(stderr, "upload: refused — role not authorised\n");
        } else if (code == E_DECRYPT_FAIL) {
            fprintf(stderr, "upload: decrypt fail (channel tainted)\n");
            return -1;
        } else {
            fprintf(stderr, "upload: server ERROR code=%u\n", code);
        }
        return 0;
    }
    if (ack_type != MSG_UPLOAD_ACK || ack_len != 4) {
        fprintf(stderr, "upload: bad ACK (type=0x%02x len=%u)\n", ack_type, ack_len);
        return -1;
    }
    uint32_t accepted = read_u32_le(ack);
    if (out_accepted) *out_accepted = accepted;
    VLOG(verbose, "upload: records_accepted=%u\n", accepted);
    return 0;
}

int client_session_query(ClientSession* s, int field, int op, int diag,
                         float* out_result, uint32_t* out_matched,
                         int verbose)
{
    if (s == NULL || s->fd < 0) return -1;

    uint8_t qreq[PROTO_QUERY_REQ_SIZE];
    write_u32_le(qreq + 0, (uint32_t)field);
    write_u32_le(qreq + 4, (uint32_t)op);
    write_u32_le(qreq + 8, (uint32_t)diag);

    if (sf_send(s->fd, MSG_QUERY_REQ, &s->seq_send, s->session_key, s->iv_prefix,
                qreq, sizeof(qreq)) != 0) {
        fprintf(stderr, "query: sf_send failed\n");
        return -1;
    }

    uint8_t  resp[64];
    uint32_t resp_len  = 0;
    uint8_t  resp_type = 0;
    if (sf_recv(s->fd, &s->seq_recv, s->session_key, s->iv_prefix, &resp_type,
                resp, sizeof(resp), &resp_len) != 0) {
        fprintf(stderr, "query: sf_recv failed\n");
        return -1;
    }
    if (resp_type == MSG_ERROR && resp_len >= 2) {
        uint16_t code = ((uint16_t)resp[0] << 8) | resp[1];
        if (code == E_INSUFFICIENT_RECORDS) {
            VLOG(verbose, "query: refused — below k-anonymity threshold\n");
        } else if (code == E_DECRYPT_FAIL) {
            fprintf(stderr, "query: decrypt fail (channel tainted)\n");
            return -1;
        } else {
            fprintf(stderr, "query: server ERROR code=%u\n", code);
        }
        return 0;
    }
    if (resp_type != MSG_QUERY_RESP || resp_len != PROTO_QUERY_RESP_SIZE) {
        fprintf(stderr, "query: bad RESP (type=0x%02x len=%u)\n", resp_type, resp_len);
        return -1;
    }
    float    result;
    uint32_t matched;
    memcpy(&result, resp, sizeof(float));
    matched = read_u32_le(resp + 4);
    if (out_result)  *out_result  = result;
    if (out_matched) *out_matched = matched;
    VLOG(verbose, "query: result=%.3f matched=%u applied_k=%u\n",
         result, matched, resp[8]);
    return 0;
}
