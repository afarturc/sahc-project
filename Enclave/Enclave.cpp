#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_thread.h"
#include "sgx_trts.h"
#include <string.h>

/* ========== ENCLAVE IDENTITY (SIMULATED) ========== */

static const uint8_t SIMULATED_MRENCLAVE[32] = {
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89
};
static const uint8_t SIMULATED_MRSIGNER[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};
static const uint8_t QE_IDENTITY[32] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11
};

static sgx_ec256_private_t qe_sign_key;
static sgx_ec256_public_t  qe_verify_key;
static int qe_keys_ready = 0;

static int init_qe_keys()
{
    if (qe_keys_ready) return 0;
    sgx_ecc_state_handle_t handle;
    if (sgx_ecc256_open_context(&handle) != SGX_SUCCESS) return -1;
    sgx_status_t s = sgx_ecc256_create_key_pair(&qe_sign_key, &qe_verify_key, handle);
    sgx_ecc256_close_context(handle);
    if (s != SGX_SUCCESS) return -2;
    qe_keys_ready = 1;
    ocall_print_string("Enclave: Quoting Enclave keys initialised\n");
    return 0;
}

/* ========== AUTHORIZED PARTIES ========== */

#define MAX_PARTIES      16
#define PARTY_ID_MAX     63
#define PUBKEY_SIZE      64
#define SIGNATURE_SIZE   64

typedef enum { ROLE_NONE = 0, ROLE_HOSPITAL = 1, ROLE_RESEARCHER = 2 } PartyRole;

typedef struct {
    PartyRole role;
    size_t    id_len;
    uint8_t   id[PARTY_ID_MAX + 1];
    uint8_t   pubkey[PUBKEY_SIZE];
} AuthorizedParty;

static AuthorizedParty parties[MAX_PARTIES];
static uint32_t        parties_count    = 0;
static uint32_t        parties_quorum_m = 0;
static uint32_t        parties_rejected = 0;
static int             parties_loading  = 0;

static const uint8_t APPROVAL_PREFIX[] = "SAHC-approve-v1";
#define APPROVAL_PREFIX_LEN (sizeof(APPROVAL_PREFIX) - 1)

static const uint8_t ATTEST_PREFIX[] = "SAHC-attest-v1";
#define ATTEST_PREFIX_LEN (sizeof(ATTEST_PREFIX) - 1)

static int find_hospital(const uint8_t* id, size_t id_len)
{
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].role == ROLE_HOSPITAL &&
            parties[i].id_len == id_len &&
            memcmp(parties[i].id, id, id_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int find_party_any(const uint8_t* id, size_t id_len)
{
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].id_len == id_len &&
            memcmp(parties[i].id, id, id_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int verify_approval(const uint8_t* hospital_pub,
                           const uint8_t* researcher_id, size_t rid_len,
                           const uint8_t* researcher_pub,
                           const uint8_t* signature)
{
    uint8_t msg[APPROVAL_PREFIX_LEN + PARTY_ID_MAX + PUBKEY_SIZE];
    size_t off = 0;
    memcpy(msg + off, APPROVAL_PREFIX, APPROVAL_PREFIX_LEN); off += APPROVAL_PREFIX_LEN;
    memcpy(msg + off, researcher_id, rid_len);               off += rid_len;
    memcpy(msg + off, researcher_pub, PUBKEY_SIZE);          off += PUBKEY_SIZE;

    sgx_ec256_public_t pub;
    memcpy(pub.gx, hospital_pub,      32);
    memcpy(pub.gy, hospital_pub + 32, 32);

    sgx_ec256_signature_t sig;
    memcpy(sig.x, signature,      32);
    memcpy(sig.y, signature + 32, 32);

    sgx_ecc_state_handle_t ctx;
    if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) return 0;

    uint8_t result = 0;
    sgx_status_t s = sgx_ecdsa_verify(msg, (uint32_t)off, &pub, &sig, &result, ctx);
    sgx_ecc256_close_context(ctx);
    return (s == SGX_SUCCESS && result == SGX_EC_VALID) ? 1 : 0;
}

int ecall_parties_begin(uint32_t quorum_m)
{
    if (quorum_m == 0) return -1;
    memset(parties, 0, sizeof(parties));
    parties_count    = 0;
    parties_quorum_m = quorum_m;
    parties_rejected = 0;
    parties_loading  = 1;
    ocall_print_string("Enclave: parties begin\n");
    return 0;
}

int ecall_parties_add_hospital(uint8_t* id, size_t id_len, uint8_t* pubkey)
{
    if (!parties_loading) return -1;
    if (id == NULL || pubkey == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX) return -1;
    if (parties_count >= MAX_PARTIES) return -2;
    if (find_party_any(id, id_len) >= 0) return -3;

    AuthorizedParty* p = &parties[parties_count++];
    p->role = ROLE_HOSPITAL;
    p->id_len = id_len;
    memcpy(p->id, id, id_len);
    p->id[id_len] = 0;
    memcpy(p->pubkey, pubkey, PUBKEY_SIZE);
    return 0;
}

int ecall_parties_add_researcher(uint8_t* id, size_t id_len,
                                 uint8_t* pubkey,
                                 uint8_t* approvals_blob, size_t approvals_len,
                                 uint32_t* accepted)
{
    *accepted = 0;
    if (!parties_loading) return -1;
    if (id == NULL || pubkey == NULL || approvals_blob == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX) return -1;
    if (parties_count >= MAX_PARTIES) return -2;
    if (find_party_any(id, id_len) >= 0) return -3;

    int signers[MAX_PARTIES];
    int n_signers = 0;
    size_t off = 0;

    while (off < approvals_len) {
        if (off + 1 > approvals_len) return -4;
        uint8_t hid_len = approvals_blob[off++];
        if (hid_len == 0 || hid_len > PARTY_ID_MAX) return -4;
        if (off + hid_len + SIGNATURE_SIZE > approvals_len) return -4;
        const uint8_t* hid = approvals_blob + off;  off += hid_len;
        const uint8_t* sig = approvals_blob + off;  off += SIGNATURE_SIZE;

        int h_idx = find_hospital(hid, hid_len);
        if (h_idx < 0) continue;

        int already_counted = 0;
        for (int i = 0; i < n_signers; i++) {
            if (signers[i] == h_idx) { already_counted = 1; break; }
        }
        if (already_counted) continue;

        if (verify_approval(parties[h_idx].pubkey, id, id_len, pubkey, sig)) {
            signers[n_signers++] = h_idx;
        }
    }

    if ((uint32_t)n_signers < parties_quorum_m) {
        parties_rejected++;
        return 0;
    }

    AuthorizedParty* p = &parties[parties_count++];
    p->role = ROLE_RESEARCHER;
    p->id_len = id_len;
    memcpy(p->id, id, id_len);
    p->id[id_len] = 0;
    memcpy(p->pubkey, pubkey, PUBKEY_SIZE);
    *accepted = 1;
    return 0;
}

int ecall_parties_end(uint32_t* hospitals_count,
                      uint32_t* researchers_count,
                      uint32_t* rejected_count)
{
    if (!parties_loading) return -1;
    uint32_t h = 0, r = 0;
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].role == ROLE_HOSPITAL)   h++;
        else if (parties[i].role == ROLE_RESEARCHER) r++;
    }
    *hospitals_count   = h;
    *researchers_count = r;
    *rejected_count    = parties_rejected;
    parties_loading    = 0;
    ocall_print_string("Enclave: parties end\n");
    return 0;
}

/* ========== HKDF-SHA256 (single-block expand) ==========
 *   PRK         = HMAC-SHA256(salt="SAHC-v1", ikm=ecdh_shared)
 *   session_key = HMAC-SHA256(PRK, "session-aes256" || 0x01)[0:32]
 *   iv_prefix   = HMAC-SHA256(PRK, "iv-prefix"      || 0x01)[0:4]
 */

static const uint8_t HKDF_SALT[] = "SAHC-v1";
#define HKDF_SALT_LEN (sizeof(HKDF_SALT) - 1)

static int hkdf_expand_block(const uint8_t* prk, size_t prk_len,
                             const char* info, size_t info_len,
                             uint8_t* out, size_t out_len)
{
    if (out_len > 32) return -1;
    uint8_t buf[64];
    if (info_len + 1 > sizeof(buf)) return -1;
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;

    uint8_t t1[32];
    sgx_status_t s = sgx_hmac_sha256_msg(buf, (int)(info_len + 1),
                                         prk, (int)prk_len,
                                         t1, 32);
    if (s != SGX_SUCCESS) return -1;
    memcpy(out, t1, out_len);
    memset(t1, 0, sizeof(t1));
    return 0;
}

/* ========== SESSION TABLE ========== */

#define MAX_SESSIONS  8
#define SESSION_KEY_SIZE 32
#define IV_PREFIX_SIZE   4

typedef enum {
    S_FREE     = 0,
    S_PENDING  = 1,  // slot reserved while KEX is in flight
    S_KEX_DONE = 2,  // ECDH complete, awaiting KEY_CONFIRM
    S_READY    = 3,  // KEY_CONFIRM verified
} SessionState;

typedef struct {
    SessionState state;
    PartyRole    role;
    size_t       id_len;
    uint8_t      party_id[PARTY_ID_MAX + 1];
    uint8_t      session_key[SESSION_KEY_SIZE];
    uint8_t      iv_prefix[IV_PREFIX_SIZE];
    uint64_t     seq_send;
    uint64_t     seq_recv;
} SessionContext;

static SessionContext sessions[MAX_SESSIONS];
static sgx_thread_mutex_t sessions_mutex = SGX_THREAD_MUTEX_INITIALIZER;

static int session_reserve_locked(void)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].state == S_FREE) {
            sessions[i].state = S_PENDING;
            return i;
        }
    }
    return -1;
}

static void session_clear_locked(int idx)
{
    memset(&sessions[idx], 0, sizeof(sessions[idx]));  // state -> S_FREE
}

int ecall_close_session(uint32_t handle)
{
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    uint32_t idx = handle - 1;

    sgx_thread_mutex_lock(&sessions_mutex);
    if (sessions[idx].state == S_FREE) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        return -2;
    }
    session_clear_locked(idx);
    sgx_thread_mutex_unlock(&sessions_mutex);

    ocall_print_string("Enclave: session closed\n");
    return 0;
}

/* Crypto core for ecall_attest_begin: ephemeral ECDH, HKDF, user_data
 * binding, QE-signed quote. Pulled out of the ECALL because g++ rejects
 * goto across initialisations in C++ (and the cleanup pattern needed a
 * lot of them). On error returns -5 (ECC) or -7 (HKDF/SHA) and writes
 * no outputs the caller would persist. */
static int kex_and_quote(uint8_t* nonce,
                         const uint8_t* client_ecdh_pub,
                         uint8_t* enclave_ecdh_pub_out,
                         uint8_t* mrenclave_out,
                         uint8_t* mrsigner_out,
                         uint16_t* isv_prod_id_out,
                         uint16_t* isv_svn_out,
                         uint8_t* user_data_out,
                         uint8_t* quote_sig_out,
                         uint8_t* qe_identity_out,
                         uint8_t  session_key_out[SESSION_KEY_SIZE],
                         uint8_t  iv_prefix_out[IV_PREFIX_SIZE])
{
    sgx_ecc_state_handle_t ecc_ctx;
    if (sgx_ecc256_open_context(&ecc_ctx) != SGX_SUCCESS) return -5;

    sgx_ec256_private_t e_priv;
    sgx_ec256_public_t  e_pub;
    if (sgx_ecc256_create_key_pair(&e_priv, &e_pub, ecc_ctx) != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecc_ctx);
        return -5;
    }

    sgx_ec256_public_t c_pub;
    memcpy(c_pub.gx, client_ecdh_pub,      32);
    memcpy(c_pub.gy, client_ecdh_pub + 32, 32);

    sgx_ec256_dh_shared_t shared;
    sgx_status_t s = sgx_ecc256_compute_shared_dhkey(&e_priv, &c_pub,
                                                     &shared, ecc_ctx);
    sgx_ecc256_close_context(ecc_ctx);
    memset(&e_priv, 0, sizeof(e_priv));
    if (s != SGX_SUCCESS) {
        memset(&shared, 0, sizeof(shared));
        return -5;
    }

    uint8_t prk[32];
    s = sgx_hmac_sha256_msg(shared.s, 32, HKDF_SALT, HKDF_SALT_LEN, prk, 32);
    memset(&shared, 0, sizeof(shared));
    if (s != SGX_SUCCESS) { memset(prk, 0, sizeof(prk)); return -7; }

    if (hkdf_expand_block(prk, 32, "session-aes256", 14,
                          session_key_out, SESSION_KEY_SIZE) != 0 ||
        hkdf_expand_block(prk, 32, "iv-prefix", 9,
                          iv_prefix_out, IV_PREFIX_SIZE) != 0) {
        memset(prk, 0, sizeof(prk));
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -7;
    }
    memset(prk, 0, sizeof(prk));

    /* user_data = SHA256(nonce || enclave_pub) */
    uint8_t to_hash[16 + 64];
    memcpy(to_hash,      nonce, 16);
    memcpy(to_hash + 16, &e_pub, 64);

    sgx_sha256_hash_t hash;
    s = sgx_sha256_msg(to_hash, sizeof(to_hash), &hash);
    if (s != SGX_SUCCESS) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -7;
    }
    memcpy(user_data_out, &hash, 32);

    /* Build + sign quote */
    memcpy(mrenclave_out, SIMULATED_MRENCLAVE, 32);
    memcpy(mrsigner_out,  SIMULATED_MRSIGNER,  32);
    *isv_prod_id_out = 1;
    *isv_svn_out     = 1;

    uint8_t to_sign[96];
    memcpy(to_sign,      mrenclave_out, 32);
    memcpy(to_sign + 32, mrsigner_out,  32);
    memcpy(to_sign + 64, user_data_out, 32);

    if (sgx_ecc256_open_context(&ecc_ctx) != SGX_SUCCESS) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -5;
    }
    sgx_ec256_signature_t qsig;
    s = sgx_ecdsa_sign(to_sign, 96, &qe_sign_key, &qsig, ecc_ctx);
    sgx_ecc256_close_context(ecc_ctx);
    if (s != SGX_SUCCESS) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -5;
    }
    memcpy(quote_sig_out,        &qsig,       64);
    memcpy(qe_identity_out,      QE_IDENTITY, 32);
    memcpy(enclave_ecdh_pub_out, &e_pub,      64);
    return 0;
}

/* ========== ATTESTATION + KEY EXCHANGE ==========
 *
 * Replaces ecall_open_session + ecall_generate_report from M1.
 *
 * Flow:
 *   1. Look up party_id in parties[] (rejects -2 = unknown party).
 *   2. ECDSA-verify signature over "SAHC-attest-v1" || nonce || client_pub
 *      with party.pubkey (rejects -3 = bad signature).
 *   3. Reserve session slot (state = S_PENDING).
 *   4. Generate ephemeral P-256 keypair, compute ECDH shared secret with
 *      client_ecdh_pub.
 *   5. HKDF-SHA256 → session_key[32] || iv_prefix[4].
 *   6. user_data = SHA256(nonce || enclave_ecdh_pub).
 *   7. QE signs (mrenclave || mrsigner || user_data) — quote binds the
 *      ECDH pubkey to the attested enclave.
 *   8. Persist session (state -> S_KEX_DONE, role/key/iv/seq populated).
 *
 * Any failure after step 3 wipes the slot back to S_FREE.
 *
 * rc:   0=OK  -1=invalid args  -2=unknown party  -3=bad signature
 *      -4=session pool exhausted  -5=ECC failure  -6=QE init failure
 *      -7=HKDF/SHA failure
 */
int ecall_attest_begin(uint8_t* party_id, size_t id_len,
                       uint8_t* nonce,
                       uint8_t* client_ecdh_pub,
                       uint8_t* signature,
                       uint32_t* handle_out,
                       uint8_t* enclave_ecdh_pub_out,
                       uint8_t* mrenclave_out,
                       uint8_t* mrsigner_out,
                       uint16_t* isv_prod_id_out,
                       uint16_t* isv_svn_out,
                       uint8_t* user_data_out,
                       uint8_t* quote_sig_out,
                       uint8_t* qe_identity_out)
{
    *handle_out = 0;
    if (party_id == NULL || nonce == NULL ||
        client_ecdh_pub == NULL || signature == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX) return -1;

    /* 1. Lookup party */
    int p_idx = find_party_any(party_id, id_len);
    if (p_idx < 0) {
        ocall_print_string("Enclave: attest_begin - unknown party\n");
        return -2;
    }
    PartyRole role = parties[p_idx].role;

    /* 2. Verify ECDSA signature over "SAHC-attest-v1"||nonce||client_pub */
    {
        uint8_t to_verify[ATTEST_PREFIX_LEN + 16 + 64];
        size_t off = 0;
        memcpy(to_verify + off, ATTEST_PREFIX, ATTEST_PREFIX_LEN); off += ATTEST_PREFIX_LEN;
        memcpy(to_verify + off, nonce, 16);                        off += 16;
        memcpy(to_verify + off, client_ecdh_pub, 64);              off += 64;

        sgx_ec256_public_t party_pub;
        memcpy(party_pub.gx, parties[p_idx].pubkey,      32);
        memcpy(party_pub.gy, parties[p_idx].pubkey + 32, 32);

        sgx_ec256_signature_t sig;
        memcpy(sig.x, signature,      32);
        memcpy(sig.y, signature + 32, 32);

        sgx_ecc_state_handle_t ctx;
        if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) return -5;
        uint8_t result = 0;
        sgx_status_t s = sgx_ecdsa_verify(to_verify, (uint32_t)off,
                                          &party_pub, &sig, &result, ctx);
        sgx_ecc256_close_context(ctx);
        if (s != SGX_SUCCESS || result != SGX_EC_VALID) {
            ocall_print_string("Enclave: attest_begin - bad signature\n");
            return -3;
        }
    }

    /* 3. Lazy QE init */
    if (init_qe_keys() != 0) return -6;

    /* 4. Reserve session slot */
    sgx_thread_mutex_lock(&sessions_mutex);
    int s_idx = session_reserve_locked();
    sgx_thread_mutex_unlock(&sessions_mutex);
    if (s_idx < 0) {
        ocall_print_string("Enclave: session pool exhausted\n");
        return -4;
    }

    /* 5. ECDH + HKDF + quote — do all the crypto first; if anything
     * fails the slot is rolled back to S_FREE. */
    uint8_t session_key[SESSION_KEY_SIZE];
    uint8_t iv_prefix[IV_PREFIX_SIZE];
    int rc = kex_and_quote(nonce, client_ecdh_pub,
                           enclave_ecdh_pub_out,
                           mrenclave_out, mrsigner_out,
                           isv_prod_id_out, isv_svn_out,
                           user_data_out, quote_sig_out, qe_identity_out,
                           session_key, iv_prefix);
    if (rc != 0) {
        sgx_thread_mutex_lock(&sessions_mutex);
        session_clear_locked(s_idx);
        sgx_thread_mutex_unlock(&sessions_mutex);
        return rc;
    }

    /* 6. Persist session */
    sgx_thread_mutex_lock(&sessions_mutex);
    sessions[s_idx].state = S_KEX_DONE;
    sessions[s_idx].role  = role;
    sessions[s_idx].id_len = id_len;
    memcpy(sessions[s_idx].party_id, party_id, id_len);
    sessions[s_idx].party_id[id_len] = 0;
    memcpy(sessions[s_idx].session_key, session_key, SESSION_KEY_SIZE);
    memcpy(sessions[s_idx].iv_prefix,   iv_prefix,   IV_PREFIX_SIZE);
    sessions[s_idx].seq_send = 0;
    sessions[s_idx].seq_recv = 0;
    sgx_thread_mutex_unlock(&sessions_mutex);
    memset(session_key, 0, sizeof(session_key));

    *handle_out = (uint32_t)(s_idx + 1);
    ocall_print_string("Enclave: KEX complete\n");
    return 0;
}
