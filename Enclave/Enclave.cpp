#include "Enclave_t.h"
#include "patient.h"
#include "protocol.h"
#include "secure_frame.h"
#include "sgx_tcrypto.h"
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include <stdlib.h>
#include <string.h>

/* ========== ENCLAVE IDENTITY ==========
 *
 * MRENCLAVE/MRSIGNER are read from a self-targeted REPORT via
 * sgx_create_report — works in both SIM and HW. In SIM the SDK
 * returns the measurements baked into the SIGSTRUCT by sgx_sign,
 * which are the same values `sgx_sign dump` exposes; on HW the
 * CPU returns the real ones. The host extracts the expected
 * MRENCLAVE from the .signed.so at build time so the client can
 * pin against the same value the enclave reports.
 *
 * QE_IDENTITY stays a placeholder — the real Quoting Enclave
 * identity only enters the picture once we move to DCAP. */
static const uint8_t QE_IDENTITY[32] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11
};

/* Reads the calling enclave's measurement via sgx_create_report against
 * its own target_info. Cheap (~µs) so we just call it on every quote
 * build; no caching needed. */
static int self_measurement(uint8_t mrenclave_out[32], uint8_t mrsigner_out[32])
{
    sgx_target_info_t ti;
    memset(&ti, 0, sizeof(ti));
    sgx_status_t s = sgx_self_target(&ti);
    if (s != SGX_SUCCESS) return -1;

    sgx_report_data_t rd;
    memset(&rd, 0, sizeof(rd));
    sgx_report_t report;
    s = sgx_create_report(&ti, &rd, &report);
    if (s != SGX_SUCCESS) return -1;

    memcpy(mrenclave_out, &report.body.mr_enclave, 32);
    memcpy(mrsigner_out,  &report.body.mr_signer,  32);
    return 0;
}

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
#define SESSION_KEY_SIZE 16   /* AES-128-GCM via sgx_rijndael128GCM_* */
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

    if (hkdf_expand_block(prk, 32, "session-aes128", 14,
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
    if (self_measurement(mrenclave_out, mrsigner_out) != 0) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -5;
    }
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

/* Constant-time equality. memcmp leaks the position of the first
 * differing byte via timing — fine for parsing, not for MAC compare. */
static int consttime_memeq(const uint8_t* a, const uint8_t* b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static const uint8_t KEY_CONFIRM_MSG[] = "confirm";
#define KEY_CONFIRM_MSG_LEN (sizeof(KEY_CONFIRM_MSG) - 1)

/* Verifies the client's HMAC over "confirm" using session_key. On match
 * the session moves to S_READY and the role granted to the peer is
 * returned (caller propagates it to the wire as KEY_ACK).
 *
 * On any failure the slot is wiped — repeated bad MACs cannot be used
 * to brute-force the key, since each attempt costs a fresh handshake.
 *
 * rc:  0=OK  -1=invalid args/handle  -2=invalid state  -3=MAC mismatch
 *     -5=HMAC compute failure
 */
int ecall_key_confirm(uint32_t handle,
                      uint8_t* client_mac,
                      uint8_t* assigned_role)
{
    *assigned_role = 0;
    if (client_mac == NULL) return -1;
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    uint32_t idx = handle - 1;

    /* Snapshot the bits we need under lock; keep the lock held while
     * computing the MAC so a concurrent close cannot wipe the key
     * mid-HMAC. (sgx_hmac_sha256_msg is in-enclave and bounded.) */
    sgx_thread_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_KEX_DONE) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        ocall_print_string("Enclave: key_confirm - invalid state\n");
        return -2;
    }

    uint8_t expected[32];
    sgx_status_t s = sgx_hmac_sha256_msg(KEY_CONFIRM_MSG, KEY_CONFIRM_MSG_LEN,
                                         sessions[idx].session_key,
                                         SESSION_KEY_SIZE,
                                         expected, 32);
    if (s != SGX_SUCCESS) {
        session_clear_locked(idx);
        sgx_thread_mutex_unlock(&sessions_mutex);
        memset(expected, 0, sizeof(expected));
        ocall_print_string("Enclave: key_confirm - HMAC failed\n");
        return -5;
    }

    if (!consttime_memeq(expected, client_mac, 32)) {
        session_clear_locked(idx);
        sgx_thread_mutex_unlock(&sessions_mutex);
        memset(expected, 0, sizeof(expected));
        ocall_print_string("Enclave: key_confirm - MAC mismatch\n");
        return -3;
    }
    memset(expected, 0, sizeof(expected));

    sessions[idx].state = S_READY;
    *assigned_role = (uint8_t)sessions[idx].role;
    sgx_thread_mutex_unlock(&sessions_mutex);

    ocall_print_string("Enclave: KEY_CONFIRM OK, session ready\n");
    return 0;
}

/* ========== PATIENT RECORDS STORE ========== */

#define MAX_RECORDS_TOTAL 1024

static PatientRecord all_records[MAX_RECORDS_TOTAL];
static size_t        total_records = 0;
static sgx_thread_mutex_t records_mutex = SGX_THREAD_MUTEX_INITIALIZER;

/* ========== AEAD HELPERS (per-session) ==========
 *
 * The session_key never leaves the enclave; the server is pure
 * transport. session_decrypt_envelope parses an inbound envelope
 * (seq||iv||ct||tag) for handle, validates seq monotonicity and IV
 * binding, and decrypts to pt_out. session_encrypt_envelope produces an
 * outbound envelope ready for the server to wrap with frame_send.
 *
 * Both helpers reach into SessionContext.seq_send / seq_recv. With the
 * single-threaded server we'd be safe under any locking discipline;
 * locks here are forward-looking for when threading lands. */

static uint64_t read_u64_be_(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

static void write_u64_be_(uint8_t* p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

/* rc:  0=OK  -1=invalid args  -2=invalid state  -7=decrypt fail/replay */
static int session_decrypt_envelope(uint32_t handle,
                                    uint8_t expected_type,
                                    const uint8_t* env, size_t env_len,
                                    uint8_t* pt_out, size_t pt_cap,
                                    size_t* pt_len_out,
                                    PartyRole* role_out)
{
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    if (env == NULL || env_len < SF_PAYLOAD_OVERHEAD) return -1;

    uint32_t idx = handle - 1;
    sgx_thread_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_READY) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        return -2;
    }

    uint8_t  key[SESSION_KEY_SIZE];
    uint8_t  ivp[IV_PREFIX_SIZE];
    uint64_t last_seq = sessions[idx].seq_recv;
    PartyRole role    = sessions[idx].role;
    memcpy(key, sessions[idx].session_key, SESSION_KEY_SIZE);
    memcpy(ivp, sessions[idx].iv_prefix,   IV_PREFIX_SIZE);
    sgx_thread_mutex_unlock(&sessions_mutex);

    uint64_t seq = read_u64_be_(env);
    if (seq <= last_seq) { memset(key, 0, sizeof(key)); return -7; }

    uint8_t expected_iv[SF_IV_SIZE];
    sf_build_iv(ivp, seq, expected_iv);
    if (memcmp(env + SF_SEQ_SIZE, expected_iv, SF_IV_SIZE) != 0) {
        memset(key, 0, sizeof(key));
        return -7;
    }

    size_t ct_len = env_len - SF_PAYLOAD_OVERHEAD;
    if (ct_len > pt_cap) { memset(key, 0, sizeof(key)); return -1; }

    const uint8_t* ct  = env + SF_SEQ_SIZE + SF_IV_SIZE;
    const uint8_t* tag = ct + ct_len;

    uint8_t aad[SF_AAD_SIZE];
    sf_build_aad(expected_type, seq, aad);

    sgx_status_t s = sgx_rijndael128GCM_decrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        ct, (uint32_t)ct_len, pt_out,
        expected_iv, SF_IV_SIZE,
        aad, SF_AAD_SIZE,
        (const sgx_aes_gcm_128bit_tag_t*)tag);
    memset(key, 0, sizeof(key));
    if (s != SGX_SUCCESS) return -7;

    sgx_thread_mutex_lock(&sessions_mutex);
    if (sessions[idx].state == S_READY) sessions[idx].seq_recv = seq;
    sgx_thread_mutex_unlock(&sessions_mutex);

    *pt_len_out = ct_len;
    *role_out   = role;
    return 0;
}

/* rc:  0=OK  -1=invalid args  -2=invalid state  -5=AEAD failure */
static int session_encrypt_envelope(uint32_t handle,
                                    uint8_t resp_type,
                                    const uint8_t* pt, size_t pt_len,
                                    uint8_t* env_out, size_t env_cap,
                                    size_t* env_len_out)
{
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    if (env_cap < SF_PAYLOAD_OVERHEAD + pt_len) return -1;

    uint32_t idx = handle - 1;
    sgx_thread_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_READY) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        return -2;
    }
    uint64_t seq = sessions[idx].seq_send + 1;
    sessions[idx].seq_send = seq;  /* commit early; if encrypt fails the
                                    * burned seq is harmless — next send
                                    * just uses seq+1. */
    uint8_t key[SESSION_KEY_SIZE];
    uint8_t ivp[IV_PREFIX_SIZE];
    memcpy(key, sessions[idx].session_key, SESSION_KEY_SIZE);
    memcpy(ivp, sessions[idx].iv_prefix,   IV_PREFIX_SIZE);
    sgx_thread_mutex_unlock(&sessions_mutex);

    write_u64_be_(env_out, seq);

    uint8_t iv[SF_IV_SIZE];
    sf_build_iv(ivp, seq, iv);
    memcpy(env_out + SF_SEQ_SIZE, iv, SF_IV_SIZE);

    uint8_t* ct  = env_out + SF_SEQ_SIZE + SF_IV_SIZE;
    uint8_t* tag = ct + pt_len;

    uint8_t aad[SF_AAD_SIZE];
    sf_build_aad(resp_type, seq, aad);

    sgx_status_t s = sgx_rijndael128GCM_encrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        pt, (uint32_t)pt_len, ct,
        iv, SF_IV_SIZE,
        aad, SF_AAD_SIZE,
        (sgx_aes_gcm_128bit_tag_t*)tag);
    memset(key, 0, sizeof(key));
    if (s != SGX_SUCCESS) return -5;

    *env_len_out = SF_PAYLOAD_OVERHEAD + pt_len;
    return 0;
}

/* ========== UPLOAD ==========
 *
 * Plaintext format (HOSPITAL → enclave): packed PatientRecord[N], so
 * pt_len must be a multiple of sizeof(PatientRecord).
 *
 * Plaintext response (enclave → HOSPITAL): u32 LE records_accepted.
 *
 * rc:  0=OK  -1=invalid args  -2=invalid state  -5=AEAD failure
 *     -7=decrypt fail/replay  -8=role unauthorised  -9=malformed payload
 */
int ecall_upload_records(uint32_t handle,
                         uint8_t* req, size_t req_len,
                         uint8_t* resp, size_t resp_cap,
                         size_t* resp_len_out)
{
    *resp_len_out = 0;

    /* 20 KB worst-case plaintext (1024 records * 20 B). Stack is fine —
     * enclave Stack is 256 KB per Enclave.config.xml. */
    uint8_t pt_buf[MAX_RECORDS_TOTAL * sizeof(PatientRecord)];
    size_t  pt_len = 0;
    PartyRole role;

    int rc = session_decrypt_envelope(handle, MSG_UPLOAD,
                                      req, req_len,
                                      pt_buf, sizeof(pt_buf), &pt_len,
                                      &role);
    if (rc != 0) return rc;

    if (role != ROLE_HOSPITAL) {
        memset(pt_buf, 0, pt_len);
        ocall_print_string("Enclave: UPLOAD denied (role != HOSPITAL)\n");
        return -8;
    }
    if (pt_len == 0 || (pt_len % sizeof(PatientRecord)) != 0) {
        memset(pt_buf, 0, pt_len);
        return -9;
    }

    size_t n = pt_len / sizeof(PatientRecord);
    PatientRecord* recs = (PatientRecord*)pt_buf;

    sgx_thread_mutex_lock(&records_mutex);
    size_t available = (total_records < MAX_RECORDS_TOTAL)
                     ? (MAX_RECORDS_TOTAL - total_records) : 0;
    size_t accepted = (n <= available) ? n : available;
    for (size_t i = 0; i < accepted; i++)
        all_records[total_records + i] = recs[i];
    total_records += accepted;
    sgx_thread_mutex_unlock(&records_mutex);

    memset(pt_buf, 0, pt_len);

    uint8_t resp_pt[4];
    uint32_t a = (uint32_t)accepted;
    resp_pt[0] = (uint8_t)(a       & 0xFF);
    resp_pt[1] = (uint8_t)((a >> 8) & 0xFF);
    resp_pt[2] = (uint8_t)((a >> 16) & 0xFF);
    resp_pt[3] = (uint8_t)((a >> 24) & 0xFF);

    int erc = session_encrypt_envelope(handle, MSG_UPLOAD_ACK,
                                       resp_pt, sizeof(resp_pt),
                                       resp, resp_cap, resp_len_out);
    if (erc != 0) return erc;

    ocall_print_string("Enclave: UPLOAD persisted\n");
    return 0;
}

/* ========== QUERY ==========
 *
 * Plaintext request : u32 field | u32 query_type | i32 filter_diag (LE).
 * Plaintext response: float result | u32 matched | u8 applied_k    (LE).
 *
 * Any authenticated role may query. Aggregates whose match count is
 * below K_ANON_THRESHOLD are rejected before any number reaches the
 * wire (rc=-10 -> E_INSUFFICIENT_RECORDS), so the enclave never leaks
 * facts about small subgroups.
 *
 * rc:  0=OK  -1=invalid args  -2=invalid state  -5=AEAD failure
 *     -7=decrypt fail/replay  -9=malformed payload  -10=below k-anon
 */
static uint32_t read_u32_le_(const uint8_t* p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void write_u32_le_(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v        & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

int ecall_query(uint32_t handle,
                uint8_t* req, size_t req_len,
                uint8_t* resp, size_t resp_cap,
                size_t* resp_len_out)
{
    *resp_len_out = 0;

    uint8_t   pt[PROTO_QUERY_REQ_SIZE];
    size_t    pt_len = 0;
    PartyRole role;
    int rc = session_decrypt_envelope(handle, MSG_QUERY_REQ,
                                      req, req_len,
                                      pt, sizeof(pt), &pt_len, &role);
    if (rc != 0) return rc;
    if (pt_len != PROTO_QUERY_REQ_SIZE) return -9;

    uint32_t field      = read_u32_le_(pt);
    uint32_t query_type = read_u32_le_(pt + 4);
    int32_t  filter     = (int32_t)read_u32_le_(pt + 8);

    if (field > FIELD_BLOOD_SUGAR || query_type > QUERY_COUNT) return -9;

    float    sum = 0.0f, mn = 1e30f, mx = -1e30f;
    uint32_t matched = 0;

    sgx_thread_mutex_lock(&records_mutex);
    for (size_t i = 0; i < total_records; i++) {
        if (filter >= 0 &&
            all_records[i].diagnosis != (uint32_t)filter) continue;
        float v = 0.0f;
        switch (field) {
            case FIELD_AGE:         v = (float)all_records[i].age; break;
            case FIELD_TEMPERATURE: v = all_records[i].temperature; break;
            case FIELD_BLOOD_SUGAR: v = all_records[i].blood_sugar; break;
        }
        sum += v;
        if (v < mn) mn = v;
        if (v > mx) mx = v;
        matched++;
    }
    sgx_thread_mutex_unlock(&records_mutex);

    if (matched < K_ANON_THRESHOLD) {
        ocall_print_string("Enclave: QUERY refused (k-anonymity)\n");
        return -10;
    }

    float result = 0.0f;
    switch (query_type) {
        case QUERY_AVG:   result = sum / (float)matched; break;
        case QUERY_MIN:   result = mn; break;
        case QUERY_MAX:   result = mx; break;
        case QUERY_COUNT: result = (float)matched; break;
    }

    uint8_t resp_pt[PROTO_QUERY_RESP_SIZE];
    memcpy(resp_pt, &result, sizeof(float));    /* host is little-endian */
    write_u32_le_(resp_pt + 4, matched);
    resp_pt[8] = (uint8_t)K_ANON_THRESHOLD;

    int erc = session_encrypt_envelope(handle, MSG_QUERY_RESP,
                                       resp_pt, sizeof(resp_pt),
                                       resp, resp_cap, resp_len_out);
    if (erc != 0) return erc;

    ocall_print_string("Enclave: QUERY OK\n");
    return 0;
}

/* ========== SEALING ==========
 *
 * Single MRENCLAVE-bound blob captures the durable enclave state —
 * authorized parties + accumulated patient records — so the server can
 * restart the enclave and resume without re-running the parties loader
 * and without losing uploaded data. Sessions are NOT sealed (volatile
 * by design: clients must re-attest after a restart). */

#define SEAL_STATE_MAGIC   0x53414843u   /* "SAHC" */
#define SEAL_STATE_VERSION 1u

typedef struct {
    uint32_t        magic;
    uint32_t        version;
    uint32_t        parties_count;
    uint32_t        parties_quorum_m;
    uint32_t        total_records;
    uint32_t        _reserved;
    AuthorizedParty parties[MAX_PARTIES];
    PatientRecord   all_records[MAX_RECORDS_TOTAL];
} SealedStatePT;

/* Match what sgx_seal_data uses internally, but pin key policy to
 * MRENCLAVE so a different build of the enclave (even by the same
 * signer) cannot unseal. */
static const sgx_attributes_t SEAL_ATTR_MASK = {
    0xFF0000000000000BULL, 0x0
};
#define SEAL_MISC_MASK 0xF0000000u

int ecall_seal_state(uint8_t* blob, size_t cap, size_t* out_len)
{
    if (out_len == NULL) return -1;
    *out_len = 0;

    uint32_t pt_size  = (uint32_t)sizeof(SealedStatePT);
    uint32_t need     = sgx_calc_sealed_data_size(0, pt_size);
    if (need == UINT32_MAX) return -2;
    if (blob == NULL || cap < need) return -1;

    SealedStatePT* pt = (SealedStatePT*)malloc(sizeof(SealedStatePT));
    if (pt == NULL) return -2;
    memset(pt, 0, sizeof(*pt));
    pt->magic            = SEAL_STATE_MAGIC;
    pt->version          = SEAL_STATE_VERSION;

    sgx_thread_mutex_lock(&records_mutex);
    pt->parties_count    = parties_count;
    pt->parties_quorum_m = parties_quorum_m;
    memcpy(pt->parties, parties, sizeof(parties));
    pt->total_records = (uint32_t)total_records;
    memcpy(pt->all_records, all_records, sizeof(all_records));
    sgx_thread_mutex_unlock(&records_mutex);

    sgx_status_t s = sgx_seal_data_ex(
        SGX_KEYPOLICY_MRENCLAVE, SEAL_ATTR_MASK, SEAL_MISC_MASK,
        0, NULL,
        pt_size, (const uint8_t*)pt,
        need, (sgx_sealed_data_t*)blob);

    memset(pt, 0, sizeof(*pt));
    free(pt);

    if (s != SGX_SUCCESS) {
        ocall_print_string("Enclave: sgx_seal_data_ex failed\n");
        return -2;
    }
    *out_len = need;
    ocall_print_string("Enclave: state sealed\n");
    return 0;
}

int ecall_unseal_state(uint8_t* blob, size_t blob_len)
{
    if (blob == NULL || blob_len == 0) return -1;

    sgx_sealed_data_t* sealed = (sgx_sealed_data_t*)blob;
    uint32_t pt_size = sgx_get_encrypt_txt_len(sealed);
    if (pt_size != (uint32_t)sizeof(SealedStatePT)) return -2;
    if (sgx_get_add_mac_txt_len(sealed) != 0) return -2;

    SealedStatePT* pt = (SealedStatePT*)malloc(sizeof(SealedStatePT));
    if (pt == NULL) return -1;

    uint32_t pt_out = pt_size;
    sgx_status_t s = sgx_unseal_data(sealed, NULL, NULL,
                                     (uint8_t*)pt, &pt_out);
    if (s != SGX_SUCCESS || pt_out != pt_size) {
        memset(pt, 0, sizeof(*pt));
        free(pt);
        ocall_print_string("Enclave: sgx_unseal_data failed\n");
        return -1;
    }

    if (pt->magic   != SEAL_STATE_MAGIC ||
        pt->version != SEAL_STATE_VERSION ||
        pt->parties_count > MAX_PARTIES   ||
        pt->total_records > MAX_RECORDS_TOTAL) {
        memset(pt, 0, sizeof(*pt));
        free(pt);
        return -2;
    }

    sgx_thread_mutex_lock(&records_mutex);
    parties_count    = pt->parties_count;
    parties_quorum_m = pt->parties_quorum_m;
    parties_rejected = 0;
    parties_loading  = 0;
    memcpy(parties, pt->parties, sizeof(parties));
    total_records = pt->total_records;
    memcpy(all_records, pt->all_records, sizeof(all_records));
    sgx_thread_mutex_unlock(&records_mutex);

    memset(pt, 0, sizeof(*pt));
    free(pt);

    ocall_print_string("Enclave: state unsealed\n");
    return 0;
}

int ecall_get_mrenclave(uint8_t* mrenclave)
{
    uint8_t mrsigner_unused[32];
    return self_measurement(mrenclave, mrsigner_unused);
}
