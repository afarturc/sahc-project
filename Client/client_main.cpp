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

/* Sized to comfortably hold the largest UPLOAD/UPLOAD_ACK frame. */
#define RECV_BUF_CAP (32 * 1024)
#define MAX_CLIENT_RECORDS 1024

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

static int parse_field(const char* s)
{
    if (!s) return -1;
    if (!strcmp(s, "age"))                                  return FIELD_AGE;
    if (!strcmp(s, "temperature") || !strcmp(s, "temp"))    return FIELD_TEMPERATURE;
    if (!strcmp(s, "blood_sugar") || !strcmp(s, "sugar"))   return FIELD_BLOOD_SUGAR;
    return -1;
}

static int parse_op(const char* s)
{
    if (!s) return -1;
    if (!strcmp(s, "avg"))   return QUERY_AVG;
    if (!strcmp(s, "min"))   return QUERY_MIN;
    if (!strcmp(s, "max"))   return QUERY_MAX;
    if (!strcmp(s, "count")) return QUERY_COUNT;
    return -1;
}

static int parse_diag(const char* s)
{
    if (!s || !strcmp(s, "any"))                                     return -1;
    if (!strcmp(s, "healthy"))                                       return DIAG_HEALTHY;
    if (!strcmp(s, "diabetes"))                                      return DIAG_DIABETES;
    if (!strcmp(s, "hypertension") || !strcmp(s, "htn"))             return DIAG_HYPERTENSION;
    if (!strcmp(s, "infection"))                                     return DIAG_INFECTION;
    return -2;  /* signal "invalid" (since -1 already means "any") */
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

/* Reusable command primitives.
 *
 * Return value:
 *    0 = command completed (OK or soft-rejected — REPL keeps going);
 *   -1 = transport/AEAD error — the channel is unusable, caller must
 *        tear down the session.
 *
 * Soft rejections (E_UNAUTHORIZED, E_INSUFFICIENT_RECORDS, malformed
 * client input) are reported to stdout/stderr but the session stays
 * alive; the server matches this contract by not closing on those. */

static int do_upload(int fd, uint64_t* seq_send, uint64_t* seq_recv,
                     const uint8_t key[16], const uint8_t iv_prefix[4],
                     const char* csv_path)
{
    PatientRecord recs[MAX_CLIENT_RECORDS];
    int n = csv_load(csv_path, recs, MAX_CLIENT_RECORDS);
    if (n <= 0) {
        fprintf(stderr, "upload: cannot load %s\n", csv_path);
        return 0;  /* user error — keep session */
    }

    printf("upload: sending %d records from %s\n", n, csv_path);
    if (sf_send(fd, MSG_UPLOAD, seq_send, key, iv_prefix,
                (const uint8_t*)recs,
                (uint32_t)(n * (int)sizeof(PatientRecord))) != 0) {
        fprintf(stderr, "upload: sf_send failed\n");
        return -1;
    }

    uint8_t  ack[64];
    uint32_t ack_len = 0;
    uint8_t  ack_type = 0;
    if (sf_recv(fd, seq_recv, key, iv_prefix, &ack_type,
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
        fprintf(stderr, "upload: bad ACK (type=0x%02x len=%u)\n",
                ack_type, ack_len);
        return -1;
    }
    uint32_t accepted = (uint32_t)ack[0]
                      | ((uint32_t)ack[1] << 8)
                      | ((uint32_t)ack[2] << 16)
                      | ((uint32_t)ack[3] << 24);
    printf("upload: records_accepted=%u\n", accepted);
    return 0;
}

static int do_query(int fd, uint64_t* seq_send, uint64_t* seq_recv,
                    const uint8_t key[16], const uint8_t iv_prefix[4],
                    int field, int op, int diag,
                    const char* field_label, const char* op_label,
                    const char* diag_label)
{
    uint8_t qreq[PROTO_QUERY_REQ_SIZE];
    write_u32_le(qreq + 0, (uint32_t)field);
    write_u32_le(qreq + 4, (uint32_t)op);
    write_u32_le(qreq + 8, (uint32_t)diag);

    printf("query: %s(%s) where diag=%s\n",
           op_label, field_label, diag_label ? diag_label : "any");

    if (sf_send(fd, MSG_QUERY_REQ, seq_send, key, iv_prefix,
                qreq, sizeof(qreq)) != 0) {
        fprintf(stderr, "query: sf_send failed\n");
        return -1;
    }

    uint8_t  resp[64];
    uint32_t resp_len = 0;
    uint8_t  resp_type = 0;
    if (sf_recv(fd, seq_recv, key, iv_prefix, &resp_type,
                resp, sizeof(resp), &resp_len) != 0) {
        fprintf(stderr, "query: sf_recv failed\n");
        return -1;
    }
    if (resp_type == MSG_ERROR && resp_len >= 2) {
        uint16_t code = ((uint16_t)resp[0] << 8) | resp[1];
        if (code == E_INSUFFICIENT_RECORDS) {
            printf("query: refused — below k-anonymity threshold\n");
        } else if (code == E_DECRYPT_FAIL) {
            fprintf(stderr, "query: decrypt fail (channel tainted)\n");
            return -1;
        } else {
            fprintf(stderr, "query: server ERROR code=%u\n", code);
        }
        return 0;
    }
    if (resp_type != MSG_QUERY_RESP || resp_len != PROTO_QUERY_RESP_SIZE) {
        fprintf(stderr, "query: bad RESP (type=0x%02x len=%u)\n",
                resp_type, resp_len);
        return -1;
    }
    float    result;
    uint32_t matched;
    uint8_t  applied_k;
    memcpy(&result, resp, sizeof(float));
    matched   = read_u32_le(resp + 4);
    applied_k = resp[8];
    printf("query: result=%.3f matched=%u applied_k=%u\n",
           result, matched, applied_k);
    return 0;
}

static void print_repl_help(void)
{
    printf(
        "commands:\n"
        "  upload <csv_path>             — push records (HOSPITAL only)\n"
        "  query <field> <op> [diag]     — aggregate (any role)\n"
        "      field: age | temperature | blood_sugar\n"
        "      op:    avg | min | max | count\n"
        "      diag:  any | healthy | diabetes | hypertension | infection\n"
        "  help                          — this message\n"
        "  quit                          — close the session and exit\n");
}

/* Returns 0 on clean exit (quit / EOF), -1 if the session died mid-command. */
static int repl_loop(int fd, uint64_t* seq_send, uint64_t* seq_recv,
                     const uint8_t key[16], const uint8_t iv_prefix[4])
{
    char line[256];
    int  is_tty = isatty(fileno(stdin));

    if (is_tty) {
        printf("Entering REPL. 'help' for commands, 'quit' to exit.\n");
    }

    for (;;) {
        if (is_tty) { printf("sahc> "); fflush(stdout); }
        if (!fgets(line, sizeof(line), stdin)) break;  /* EOF */

        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r' ||
                         line[l-1] == ' '  || line[l-1] == '\t')) {
            line[--l] = 0;
        }
        if (l == 0) continue;

        char* tokens[8] = {0};
        int   n_tok = 0;
        char* tok = strtok(line, " \t");
        while (tok && n_tok < 8) { tokens[n_tok++] = tok; tok = strtok(NULL, " \t"); }
        if (n_tok == 0) continue;

        if (!strcmp(tokens[0], "quit") || !strcmp(tokens[0], "exit") ||
            !strcmp(tokens[0], "q")) {
            return 0;
        }
        if (!strcmp(tokens[0], "help") || !strcmp(tokens[0], "h") ||
            !strcmp(tokens[0], "?")) {
            print_repl_help();
            continue;
        }
        if (!strcmp(tokens[0], "upload")) {
            if (n_tok < 2) { fprintf(stderr, "usage: upload <csv_path>\n"); continue; }
            int rc = do_upload(fd, seq_send, seq_recv, key, iv_prefix, tokens[1]);
            if (rc < 0) return -1;
            continue;
        }
        if (!strcmp(tokens[0], "query")) {
            if (n_tok < 3) {
                fprintf(stderr, "usage: query <field> <op> [diag]\n");
                continue;
            }
            int f = parse_field(tokens[1]);
            int o = parse_op(tokens[2]);
            int d = (n_tok >= 4) ? parse_diag(tokens[3]) : -1;
            if (f < 0 || o < 0 || d == -2) {
                fprintf(stderr, "query: bad args (try 'help')\n");
                continue;
            }
            int rc = do_query(fd, seq_send, seq_recv, key, iv_prefix,
                              f, o, d,
                              tokens[1], tokens[2],
                              (n_tok >= 4) ? tokens[3] : NULL);
            if (rc < 0) return -1;
            continue;
        }
        fprintf(stderr, "unknown: %s (try 'help')\n", tokens[0]);
    }
    return 0;  /* EOF */
}

int main(int argc, char** argv)
{
    const char* host     = SAHC_DEFAULT_HOST;
    int         port     = SAHC_DEFAULT_PORT;
    const char* party_id = "hosp-santa-maria";
    const char* csv_path = NULL;   /* argv[4]; "-" or NULL = skip UPLOAD */
    const char* q_field  = NULL;   /* argv[5]; if set, send a QUERY */
    const char* q_op     = NULL;   /* argv[6] */
    const char* q_diag   = NULL;   /* argv[7]; default "any" */
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);
    if (argc >= 4) party_id = argv[3];
    if (argc >= 5 && strcmp(argv[4], "-") != 0) csv_path = argv[4];
    if (argc >= 6) q_field = argv[5];
    if (argc >= 7) q_op    = argv[6];
    if (argc >= 8) q_diag  = argv[7];

    int q_field_id = -1, q_op_id = -1, q_diag_id = -1;
    if (q_field != NULL) {
        q_field_id = parse_field(q_field);
        q_op_id    = parse_op(q_op);
        q_diag_id  = parse_diag(q_diag);
        if (q_field_id < 0 || q_op_id < 0 || q_diag_id == -2) {
            fprintf(stderr,
                "Client: bad query args. Usage: <field> <op> [diag]\n"
                "  field: age | temperature | blood_sugar\n"
                "  op:    avg | min | max | count\n"
                "  diag:  any | healthy | diabetes | hypertension | infection\n");
            return 2;
        }
    }

    size_t id_len = strlen(party_id);
    if (id_len == 0 || id_len > 63) {
        fprintf(stderr, "Client: invalid party_id (len %zu)\n", id_len);
        return 1;
    }

    /* Load long-term identity. */
    char key_path[128];
    snprintf(key_path, sizeof(key_path), "parties/%s.key", party_id);
    EVP_PKEY* lt_key = identity_load_pem(key_path);
    if (!lt_key) {
        fprintf(stderr, "Client: failed to load %s\n", key_path);
        return 1;
    }
    printf("Client: identity loaded from %s\n", key_path);

    /* Ephemeral ECDH keypair. */
    EVP_PKEY* eph_priv = NULL;
    uint8_t   client_ecdh_pub[ID_PUB_SIZE];
    if (ecdh_keygen(&eph_priv, client_ecdh_pub) != 0) {
        fprintf(stderr, "Client: ECDH keygen failed\n");
        identity_free(lt_key);
        return 1;
    }
    print_hex("client_ecdh_pub", client_ecdh_pub, 16);  /* first 16B */

    /* Connect. */
    int fd = tcp_connect(host, port);
    if (fd < 0) { identity_free(eph_priv); identity_free(lt_key); return 1; }
    /* Match server-side 30 s; if the enclave hangs we'd rather error out
     * than block the REPL forever. */
    tcp_set_timeout(fd, 30, 30);
    printf("Client: connected to %s:%d (party=%s)\n", host, port, party_id);

    /* Build ATTEST_REQ:
     *   id_len(1) | party_id | nonce(16) | client_ecdh_pub(64) | sig(64)
     * Signature covers "SAHC-attest-v1" || nonce || client_ecdh_pub. */
    uint8_t nonce[PROTO_NONCE_SIZE];
    if (read_random(nonce, sizeof(nonce)) != 0) {
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }

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
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }

    uint8_t req[1 + 63 + PROTO_NONCE_SIZE
                + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE];
    uint32_t req_len = (uint32_t)(1 + id_len + PROTO_NONCE_SIZE
                                  + PROTO_ECDH_PUB_SIZE + PROTO_SIG_SIZE);
    {
        uint8_t* p = req;
        *p++ = (uint8_t)id_len;
        memcpy(p, party_id, id_len);                    p += id_len;
        memcpy(p, nonce, PROTO_NONCE_SIZE);             p += PROTO_NONCE_SIZE;
        memcpy(p, client_ecdh_pub, PROTO_ECDH_PUB_SIZE); p += PROTO_ECDH_PUB_SIZE;
        memcpy(p, signature, PROTO_SIG_SIZE);
    }

    if (frame_send(fd, MSG_ATTEST_REQ, req, req_len) != 0) {
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    printf("Client: sent ATTEST_REQ (%u bytes)\n", req_len);

    /* Receive ATTEST_RESP. */
    uint8_t  buf[RECV_BUF_CAP];
    uint8_t  type = 0;
    uint32_t len  = 0;
    int r = frame_recv(fd, &type, buf, sizeof(buf), &len);
    if (r != 0) {
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: server ERROR code=%u\n", code);
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    if (type != MSG_ATTEST_RESP || len != PROTO_ATTEST_RESP_SIZE) {
        fprintf(stderr, "Client: bad ATTEST_RESP (type=0x%02x len=%u)\n",
                type, len);
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }

    const uint8_t* q = buf;
    const uint8_t* mrenclave   = q;                            /* 32 */
    const uint8_t* mrsigner    = mrenclave + 32;               /* 32 */
    uint16_t isv_prod_id = get_u16_le(mrsigner + 32);
    uint16_t isv_svn     = get_u16_le(mrsigner + 32 + 2);
    const uint8_t* user_data   = mrsigner + 32 + 4;            /* 32 */
    const uint8_t* quote_sig   = user_data + 32;               /* 64 */
    const uint8_t* qe_identity = quote_sig + 64;               /* 32 */
    const uint8_t* enclave_pub = qe_identity + 32;             /* 64 */
    (void)quote_sig; (void)qe_identity;  /* QE signature path verified in Fase 4 */

    printf("Client: ATTEST_RESP received (%u bytes)\n", len);
    print_hex("mrenclave",   mrenclave, 32);
    printf("  isv_prod_id: %u  isv_svn: %u\n", isv_prod_id, isv_svn);
    print_hex("enclave_pub", enclave_pub, 16);  /* first 16B */

    if (memcmp(mrenclave, EXPECTED_MRENCLAVE, 32) != 0) {
        fprintf(stderr, "Client: MRENCLAVE MISMATCH (wrong enclave)\n");
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    printf("Client: MRENCLAVE pin OK\n");

    /* user_data must equal SHA256(nonce || enclave_pub) — binds the ECDH
     * pubkey to the attested enclave. */
    {
        uint8_t to_hash[PROTO_NONCE_SIZE + PROTO_ECDH_PUB_SIZE];
        memcpy(to_hash, nonce, PROTO_NONCE_SIZE);
        memcpy(to_hash + PROTO_NONCE_SIZE, enclave_pub, PROTO_ECDH_PUB_SIZE);
        uint8_t expected[ID_HASH_SIZE];
        if (crypto_sha256(to_hash, sizeof(to_hash), expected) != 0 ||
            memcmp(user_data, expected, ID_HASH_SIZE) != 0) {
            fprintf(stderr, "Client: user_data mismatch (replay or tampered)\n");
            identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
        }
    }
    printf("Client: user_data binding OK\n");

    /* ECDH + HKDF. session_key proves possession via KEY_CONFIRM below;
     * iv_prefix is parked for the AEAD frames in Passo 5. */
    uint8_t shared[ID_SHARED_SIZE];
    if (ecdh_compute_shared(eph_priv, enclave_pub, shared) != 0) {
        fprintf(stderr, "Client: ECDH derive failed\n");
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }

    uint8_t prk[32];
    if (crypto_hmac_sha256(HKDF_SALT, HKDF_SALT_LEN,
                           shared, ID_SHARED_SIZE, prk) != 0) {
        fprintf(stderr, "Client: HKDF-extract failed\n");
        memset(shared, 0, sizeof(shared));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    memset(shared, 0, sizeof(shared));

    uint8_t session_key[16];   /* AES-128-GCM */
    uint8_t iv_prefix[4];
    if (crypto_hkdf_expand(prk, 32, "session-aes128", session_key, 16) != 0 ||
        crypto_hkdf_expand(prk, 32, "iv-prefix",      iv_prefix,    4) != 0) {
        fprintf(stderr, "Client: HKDF-expand failed\n");
        memset(prk, 0, sizeof(prk));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    memset(prk, 0, sizeof(prk));
    printf("Client: session_key derived (sha256(key)[0..7]):");
    {
        uint8_t kh[32];
        crypto_sha256(session_key, 16, kh);
        for (int i = 0; i < 8; i++) printf(" %02x", kh[i]);
        printf("\n");
    }

    /* KEY_CONFIRM: prove possession of session_key via HMAC over "confirm".
     * Server replies KEY_ACK with [status(1) | role(1)]. */
    uint8_t mac[PROTO_KEY_CONFIRM_SIZE];
    if (crypto_hmac_sha256(session_key, 16,
                           (const uint8_t*)"confirm", 7, mac) != 0) {
        fprintf(stderr, "Client: HMAC for KEY_CONFIRM failed\n");
        memset(session_key, 0, sizeof(session_key));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    if (frame_send(fd, MSG_KEY_CONFIRM, mac, PROTO_KEY_CONFIRM_SIZE) != 0) {
        memset(session_key, 0, sizeof(session_key));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }

    r = frame_recv(fd, &type, buf, sizeof(buf), &len);
    if (r != 0) {
        memset(session_key, 0, sizeof(session_key));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    if (type == MSG_ERROR && len >= 2) {
        uint16_t code = ((uint16_t)buf[0] << 8) | buf[1];
        fprintf(stderr, "Client: KEY_CONFIRM rejected, server ERROR code=%u\n",
                code);
        memset(session_key, 0, sizeof(session_key));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    if (type != MSG_KEY_ACK || len != PROTO_KEY_ACK_SIZE) {
        fprintf(stderr, "Client: bad KEY_ACK (type=0x%02x len=%u)\n",
                type, len);
        memset(session_key, 0, sizeof(session_key));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    uint8_t assigned_role = 0;
    {
        uint8_t status = buf[0];
        assigned_role  = buf[1];
        const char* role_str =
            (assigned_role == PROTO_ROLE_HOSPITAL)   ? "HOSPITAL" :
            (assigned_role == PROTO_ROLE_RESEARCHER) ? "RESEARCHER" : "?";
        if (status != 0) {
            fprintf(stderr, "Client: KEY_ACK status=%u (rejected)\n", status);
            memset(session_key, 0, sizeof(session_key));
            identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
        }
        printf("Client: KEY_ACK status=0 role=%s — session READY\n", role_str);
    }

    /* Per-session AEAD counters (start at 0; sf_send/sf_recv pre-increment). */
    uint64_t seq_send = 0, seq_recv = 0;

    /* Single-shot mode: argv[4]=csv_path or argv[5..7]=query. If neither
     * is given, drop into the REPL after the handshake so the researcher
     * (or anyone) can issue several commands on the same session. */
    int single_shot = (csv_path != NULL) || (q_field != NULL);

    if (csv_path != NULL) {
        if (do_upload(fd, &seq_send, &seq_recv, session_key, iv_prefix,
                      csv_path) < 0) {
            memset(session_key, 0, sizeof(session_key));
            identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
        }
    }

    if (q_field != NULL) {
        if (do_query(fd, &seq_send, &seq_recv, session_key, iv_prefix,
                     q_field_id, q_op_id, q_diag_id,
                     q_field, q_op, q_diag) < 0) {
            memset(session_key, 0, sizeof(session_key));
            identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
        }
    }

    if (!single_shot) {
        if (repl_loop(fd, &seq_send, &seq_recv, session_key, iv_prefix) < 0) {
            fprintf(stderr, "Client: session torn down by AEAD failure\n");
        }
    }

    memset(session_key, 0, sizeof(session_key));
    memset(iv_prefix,   0, sizeof(iv_prefix));

    frame_send(fd, MSG_SESSION_CLOSE, NULL, 0);
    identity_free(eph_priv);
    identity_free(lt_key);
    close(fd);
    return 0;
}
