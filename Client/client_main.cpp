#include "framing.h"
#include "identity.h"
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

    /* ECDH + HKDF. session_key/iv_prefix are derived but only used by
     * KEY_CONFIRM and the AEAD frames in C3 of Passo 4b. */
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

    uint8_t session_key[32];
    uint8_t iv_prefix[4];
    if (crypto_hkdf_expand(prk, 32, "session-aes256", session_key, 32) != 0 ||
        crypto_hkdf_expand(prk, 32, "iv-prefix",      iv_prefix,    4) != 0) {
        fprintf(stderr, "Client: HKDF-expand failed\n");
        memset(prk, 0, sizeof(prk));
        identity_free(eph_priv); identity_free(lt_key); close(fd); return 1;
    }
    memset(prk, 0, sizeof(prk));
    printf("Client: session_key derived (sha256(key)[0..7]):");
    {
        uint8_t kh[32];
        crypto_sha256(session_key, 32, kh);
        for (int i = 0; i < 8; i++) printf(" %02x", kh[i]);
        printf("\n");
    }

    /* Wipe and clean up. KEY_CONFIRM/KEY_ACK arrive in C3. */
    memset(session_key, 0, sizeof(session_key));
    memset(iv_prefix,   0, sizeof(iv_prefix));

    frame_send(fd, MSG_SESSION_CLOSE, NULL, 0);
    identity_free(eph_priv);
    identity_free(lt_key);
    close(fd);
    return 0;
}
