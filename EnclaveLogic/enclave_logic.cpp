/* SDK-neutral enclave logic.
 *
 * Ported verbatim from the pre-refactor Enclave/Enclave.cpp; every
 * sgx_* primitive is now reached through the crypto/identity/seal
 * backend abstractions, every sgx_thread_mutex via mutex_compat.h.
 * The wire/return-code surface is unchanged so the host-side wire
 * mapping in Server/server_main.cpp keeps working without edits.
 *
 * Compiles in two contexts:
 *  - inside the SGX-SDK enclave (-DSAHC_BACKEND_SGX, tlibc only)
 *  - inside a normal Linux process under Gramine (default, glibc)
 */

#include "enclave_logic.h"
#include "crypto_backend.h"
#include "identity_backend.h"
#include "seal_backend.h"
#include "mutex_compat.h"

#include "patient.h"          /* PatientRecord, FIELD_*, QUERY_* */
#include "protocol.h"         /* K_ANON_THRESHOLD, MSG_*, PROTO_* */
#include "secure_frame.h"     /* sf_build_iv / sf_build_aad */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========== LOGGING ========== */

static void noop_log(const char*) {}
static void (*g_log)(const char*) = noop_log;
extern "C" void sahc_log_install(void (*cb)(const char*)) {
    g_log = cb ? cb : noop_log;
}
#define LOG(s) g_log(s)

/* ========== ENCLAVE IDENTITY / QE ==========
 *
 * MRENCLAVE/MRSIGNER come from the identity backend (sgx_create_report
 * inside the SDK; /dev/attestation pseudo-files inside Gramine).
 *
 * The "QE" key is artisanal — a per-process P-256 keypair the enclave
 * generates on first attest. It signs (mrenclave||mrsigner||user_data),
 * which is what Client/quote_verify.cpp validates in the M2 pipeline.
 * QE_IDENTITY stays a placeholder until the real DCAP path is wired.
 */

static const uint8_t QE_IDENTITY[32] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11
};

static uint8_t qe_priv[32];
static uint8_t qe_pub[64];
static int     qe_keys_ready = 0;

static int init_qe_keys(void) {
    if (qe_keys_ready) return 0;
    if (sahc_ecc_keygen(qe_priv, qe_pub) != 0) return -1;
    qe_keys_ready = 1;
    LOG("Enclave: Quoting Enclave keys initialised\n");
    return 0;
}

/* ========== AUTHORIZED PARTIES ==========
 *
 * Layout (PartyRole enum width, AuthorizedParty padding) is preserved
 * byte-for-byte vs the pre-refactor enclave so a sealed blob from the
 * old build still unseals here.
 */

#define MAX_PARTIES      16
#define PARTY_ID_MAX_S   63
#define PUBKEY_SIZE_S    64
#define SIGNATURE_SIZE_S 64

typedef enum { PR_NONE = 0, PR_HOSPITAL = 1, PR_RESEARCHER = 2 } PartyRoleE;

typedef struct {
    PartyRoleE role;
    size_t     id_len;
    uint8_t    id[PARTY_ID_MAX_S + 1];
    uint8_t    pubkey[PUBKEY_SIZE_S];
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

static int find_hospital(const uint8_t* id, size_t id_len) {
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].role == PR_HOSPITAL &&
            parties[i].id_len == id_len &&
            memcmp(parties[i].id, id, id_len) == 0) return (int)i;
    }
    return -1;
}

static int find_party_any(const uint8_t* id, size_t id_len) {
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].id_len == id_len &&
            memcmp(parties[i].id, id, id_len) == 0) return (int)i;
    }
    return -1;
}

static int verify_approval(const uint8_t* hospital_pub,
                           const uint8_t* researcher_id, size_t rid_len,
                           const uint8_t* researcher_pub,
                           const uint8_t* signature) {
    uint8_t msg[APPROVAL_PREFIX_LEN + PARTY_ID_MAX_S + PUBKEY_SIZE_S];
    size_t off = 0;
    memcpy(msg + off, APPROVAL_PREFIX, APPROVAL_PREFIX_LEN); off += APPROVAL_PREFIX_LEN;
    memcpy(msg + off, researcher_id, rid_len);               off += rid_len;
    memcpy(msg + off, researcher_pub, PUBKEY_SIZE_S);        off += PUBKEY_SIZE_S;
    return sahc_ecdsa_verify(hospital_pub, msg, off, signature) == 0 ? 1 : 0;
}

extern "C" int sahc_parties_begin(uint32_t quorum_m) {
    if (quorum_m == 0) return -1;
    memset(parties, 0, sizeof(parties));
    parties_count = 0;
    parties_quorum_m = quorum_m;
    parties_rejected = 0;
    parties_loading = 1;
    LOG("Enclave: parties begin\n");
    return 0;
}

extern "C" int sahc_parties_add_hospital(uint8_t* id, size_t id_len, uint8_t* pubkey) {
    if (!parties_loading) return -1;
    if (id == NULL || pubkey == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX_S) return -1;
    if (parties_count >= MAX_PARTIES) return -2;
    if (find_party_any(id, id_len) >= 0) return -3;
    AuthorizedParty* p = &parties[parties_count++];
    p->role = PR_HOSPITAL;
    p->id_len = id_len;
    memcpy(p->id, id, id_len);
    p->id[id_len] = 0;
    memcpy(p->pubkey, pubkey, PUBKEY_SIZE_S);
    return 0;
}

extern "C" int sahc_parties_add_researcher(uint8_t* id, size_t id_len,
                                           uint8_t* pubkey,
                                           uint8_t* approvals_blob, size_t approvals_len,
                                           uint32_t* accepted) {
    *accepted = 0;
    if (!parties_loading) return -1;
    if (id == NULL || pubkey == NULL || approvals_blob == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX_S) return -1;
    if (parties_count >= MAX_PARTIES) return -2;
    if (find_party_any(id, id_len) >= 0) return -3;

    int signers[MAX_PARTIES];
    int n_signers = 0;
    size_t off = 0;

    while (off < approvals_len) {
        if (off + 1 > approvals_len) return -4;
        uint8_t hid_len = approvals_blob[off++];
        if (hid_len == 0 || hid_len > PARTY_ID_MAX_S) return -4;
        if (off + hid_len + SIGNATURE_SIZE_S > approvals_len) return -4;
        const uint8_t* hid = approvals_blob + off;  off += hid_len;
        const uint8_t* sig = approvals_blob + off;  off += SIGNATURE_SIZE_S;

        int h_idx = find_hospital(hid, hid_len);
        if (h_idx < 0) continue;
        int already = 0;
        for (int i = 0; i < n_signers; i++) if (signers[i] == h_idx) { already = 1; break; }
        if (already) continue;
        if (verify_approval(parties[h_idx].pubkey, id, id_len, pubkey, sig))
            signers[n_signers++] = h_idx;
    }

    if ((uint32_t)n_signers < parties_quorum_m) {
        parties_rejected++;
        return 0;
    }
    AuthorizedParty* p = &parties[parties_count++];
    p->role = PR_RESEARCHER;
    p->id_len = id_len;
    memcpy(p->id, id, id_len);
    p->id[id_len] = 0;
    memcpy(p->pubkey, pubkey, PUBKEY_SIZE_S);
    *accepted = 1;
    return 0;
}

extern "C" int sahc_parties_end(uint32_t* hospitals_count,
                                uint32_t* researchers_count,
                                uint32_t* rejected_count) {
    if (!parties_loading) return -1;
    uint32_t h = 0, r = 0;
    for (uint32_t i = 0; i < parties_count; i++) {
        if (parties[i].role == PR_HOSPITAL)        h++;
        else if (parties[i].role == PR_RESEARCHER) r++;
    }
    *hospitals_count   = h;
    *researchers_count = r;
    *rejected_count    = parties_rejected;
    parties_loading    = 0;
    LOG("Enclave: parties end\n");
    return 0;
}

/* ========== HKDF-SHA256 (single-block expand) ========== */

static const uint8_t HKDF_SALT[] = "SAHC-v1";
#define HKDF_SALT_LEN (sizeof(HKDF_SALT) - 1)

static int hkdf_expand_block(const uint8_t* prk, size_t prk_len,
                             const char* info, size_t info_len,
                             uint8_t* out, size_t out_len) {
    if (out_len > 32) return -1;
    uint8_t buf[64];
    if (info_len + 1 > sizeof(buf)) return -1;
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;

    uint8_t t1[32];
    if (sahc_hmac_sha256(prk, prk_len, buf, info_len + 1, t1) != 0) return -1;
    memcpy(out, t1, out_len);
    memset(t1, 0, sizeof(t1));
    return 0;
}

/* ========== SESSION TABLE ========== */

#define MAX_SESSIONS     8
#define SESSION_KEY_SIZE 16
#define IV_PREFIX_SIZE   4

typedef enum { S_FREE = 0, S_PENDING = 1, S_KEX_DONE = 2, S_READY = 3 } SessionState;

typedef struct {
    SessionState state;
    PartyRoleE   role;
    size_t       id_len;
    uint8_t      party_id[PARTY_ID_MAX_S + 1];
    uint8_t      session_key[SESSION_KEY_SIZE];
    uint8_t      iv_prefix[IV_PREFIX_SIZE];
    uint64_t     seq_send;
    uint64_t     seq_recv;
} SessionContext;

static SessionContext sessions[MAX_SESSIONS];
static sahc_mutex_t   sessions_mutex = SAHC_MUTEX_INITIALIZER;

static int session_reserve_locked(void) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].state == S_FREE) { sessions[i].state = S_PENDING; return i; }
    return -1;
}
static void session_clear_locked(int idx) {
    memset(&sessions[idx], 0, sizeof(sessions[idx]));
}

extern "C" int sahc_close_session(uint32_t handle) {
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    uint32_t idx = handle - 1;
    sahc_mutex_lock(&sessions_mutex);
    if (sessions[idx].state == S_FREE) { sahc_mutex_unlock(&sessions_mutex); return -2; }
    session_clear_locked(idx);
    sahc_mutex_unlock(&sessions_mutex);
    LOG("Enclave: session closed\n");
    return 0;
}

/* ECDH + HKDF + artisanal QE quote. Pulled out because the original
 * cleanup pattern needed gotos that g++ refuses to jump over C++
 * initialisers. */
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
                         uint8_t  iv_prefix_out[IV_PREFIX_SIZE]) {
    uint8_t e_priv[32];
    uint8_t e_pub[64];
    if (sahc_ecc_keygen(e_priv, e_pub) != 0) return -5;

    uint8_t shared[32];
    if (sahc_ecdh_shared(e_priv, client_ecdh_pub, shared) != 0) {
        memset(e_priv, 0, sizeof(e_priv));
        return -5;
    }
    memset(e_priv, 0, sizeof(e_priv));

    uint8_t prk[32];
    if (sahc_hmac_sha256(HKDF_SALT, HKDF_SALT_LEN, shared, 32, prk) != 0) {
        memset(shared, 0, sizeof(shared));
        return -7;
    }
    memset(shared, 0, sizeof(shared));

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
    memcpy(to_hash + 16, e_pub, 64);
    if (sahc_sha256(to_hash, sizeof(to_hash), user_data_out) != 0) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -7;
    }

    if (sahc_self_measurement(mrenclave_out, mrsigner_out) != 0) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -5;
    }
    *isv_prod_id_out = 1;
    *isv_svn_out     = 1;

    uint8_t to_sign[96];
    memcpy(to_sign,      mrenclave_out, 32);
    memcpy(to_sign + 32, mrsigner_out,  32);
    memcpy(to_sign + 64, user_data_out, 32);
    if (sahc_ecdsa_sign(qe_priv, to_sign, 96, quote_sig_out) != 0) {
        memset(session_key_out, 0, SESSION_KEY_SIZE);
        return -5;
    }
    memcpy(qe_identity_out,      QE_IDENTITY, 32);
    memcpy(enclave_ecdh_pub_out, e_pub,       64);
    return 0;
}

extern "C" int sahc_attest_begin(uint8_t* party_id, size_t id_len,
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
                                 uint8_t* qe_identity_out) {
    *handle_out = 0;
    if (party_id == NULL || nonce == NULL ||
        client_ecdh_pub == NULL || signature == NULL) return -1;
    if (id_len == 0 || id_len > PARTY_ID_MAX_S) return -1;

    int p_idx = find_party_any(party_id, id_len);
    if (p_idx < 0) { LOG("Enclave: attest_begin - unknown party\n"); return -2; }
    PartyRoleE role = parties[p_idx].role;

    {
        uint8_t to_verify[ATTEST_PREFIX_LEN + 16 + 64];
        size_t off = 0;
        memcpy(to_verify + off, ATTEST_PREFIX, ATTEST_PREFIX_LEN); off += ATTEST_PREFIX_LEN;
        memcpy(to_verify + off, nonce, 16);                        off += 16;
        memcpy(to_verify + off, client_ecdh_pub, 64);              off += 64;
        if (sahc_ecdsa_verify(parties[p_idx].pubkey, to_verify, off, signature) != 0) {
            LOG("Enclave: attest_begin - bad signature\n");
            return -3;
        }
    }

    if (init_qe_keys() != 0) return -6;

    sahc_mutex_lock(&sessions_mutex);
    int s_idx = session_reserve_locked();
    sahc_mutex_unlock(&sessions_mutex);
    if (s_idx < 0) { LOG("Enclave: session pool exhausted\n"); return -4; }

    uint8_t session_key[SESSION_KEY_SIZE];
    uint8_t iv_prefix[IV_PREFIX_SIZE];
    int rc = kex_and_quote(nonce, client_ecdh_pub,
                           enclave_ecdh_pub_out,
                           mrenclave_out, mrsigner_out,
                           isv_prod_id_out, isv_svn_out,
                           user_data_out, quote_sig_out, qe_identity_out,
                           session_key, iv_prefix);
    if (rc != 0) {
        sahc_mutex_lock(&sessions_mutex);
        session_clear_locked(s_idx);
        sahc_mutex_unlock(&sessions_mutex);
        return rc;
    }

    sahc_mutex_lock(&sessions_mutex);
    sessions[s_idx].state = S_KEX_DONE;
    sessions[s_idx].role  = role;
    sessions[s_idx].id_len = id_len;
    memcpy(sessions[s_idx].party_id, party_id, id_len);
    sessions[s_idx].party_id[id_len] = 0;
    memcpy(sessions[s_idx].session_key, session_key, SESSION_KEY_SIZE);
    memcpy(sessions[s_idx].iv_prefix,   iv_prefix,   IV_PREFIX_SIZE);
    sessions[s_idx].seq_send = 0;
    sessions[s_idx].seq_recv = 0;
    sahc_mutex_unlock(&sessions_mutex);
    memset(session_key, 0, sizeof(session_key));

    *handle_out = (uint32_t)(s_idx + 1);
    LOG("Enclave: KEX complete\n");
    return 0;
}

static int consttime_memeq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static const uint8_t KEY_CONFIRM_MSG[] = "confirm";
#define KEY_CONFIRM_MSG_LEN (sizeof(KEY_CONFIRM_MSG) - 1)

extern "C" int sahc_key_confirm(uint32_t handle,
                                uint8_t* client_mac,
                                uint8_t* assigned_role) {
    *assigned_role = 0;
    if (client_mac == NULL) return -1;
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    uint32_t idx = handle - 1;

    sahc_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_KEX_DONE) {
        sahc_mutex_unlock(&sessions_mutex);
        LOG("Enclave: key_confirm - invalid state\n");
        return -2;
    }

    uint8_t expected[32];
    if (sahc_hmac_sha256(sessions[idx].session_key, SESSION_KEY_SIZE,
                         KEY_CONFIRM_MSG, KEY_CONFIRM_MSG_LEN, expected) != 0) {
        session_clear_locked(idx);
        sahc_mutex_unlock(&sessions_mutex);
        memset(expected, 0, sizeof(expected));
        LOG("Enclave: key_confirm - HMAC failed\n");
        return -5;
    }
    if (!consttime_memeq(expected, client_mac, 32)) {
        session_clear_locked(idx);
        sahc_mutex_unlock(&sessions_mutex);
        memset(expected, 0, sizeof(expected));
        LOG("Enclave: key_confirm - MAC mismatch\n");
        return -3;
    }
    memset(expected, 0, sizeof(expected));

    sessions[idx].state = S_READY;
    *assigned_role = (uint8_t)sessions[idx].role;
    sahc_mutex_unlock(&sessions_mutex);
    LOG("Enclave: KEY_CONFIRM OK, session ready\n");
    return 0;
}

/* ========== PATIENT RECORDS STORE ========== */

#define MAX_RECORDS_TOTAL 1024
static PatientRecord all_records[MAX_RECORDS_TOTAL];
static size_t        total_records = 0;
static sahc_mutex_t  records_mutex = SAHC_MUTEX_INITIALIZER;

/* ========== AEAD HELPERS ========== */

static uint64_t read_u64_be_(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}
static void write_u64_be_(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

static int session_decrypt_envelope(uint32_t handle,
                                    uint8_t expected_type,
                                    const uint8_t* env, size_t env_len,
                                    uint8_t* pt_out, size_t pt_cap,
                                    size_t* pt_len_out,
                                    PartyRoleE* role_out) {
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    if (env == NULL || env_len < SF_PAYLOAD_OVERHEAD) return -1;

    uint32_t idx = handle - 1;
    sahc_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_READY) { sahc_mutex_unlock(&sessions_mutex); return -2; }

    uint8_t   key[SESSION_KEY_SIZE];
    uint8_t   ivp[IV_PREFIX_SIZE];
    uint64_t  last_seq = sessions[idx].seq_recv;
    PartyRoleE role    = sessions[idx].role;
    memcpy(key, sessions[idx].session_key, SESSION_KEY_SIZE);
    memcpy(ivp, sessions[idx].iv_prefix,   IV_PREFIX_SIZE);
    sahc_mutex_unlock(&sessions_mutex);

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

    int rc = sahc_aes128gcm_decrypt(key, expected_iv, aad, SF_AAD_SIZE,
                                    ct, ct_len, tag, pt_out);
    memset(key, 0, sizeof(key));
    if (rc != 0) return -7;

    sahc_mutex_lock(&sessions_mutex);
    if (sessions[idx].state == S_READY) sessions[idx].seq_recv = seq;
    sahc_mutex_unlock(&sessions_mutex);

    *pt_len_out = ct_len;
    *role_out   = role;
    return 0;
}

static int session_encrypt_envelope(uint32_t handle,
                                    uint8_t resp_type,
                                    const uint8_t* pt, size_t pt_len,
                                    uint8_t* env_out, size_t env_cap,
                                    size_t* env_len_out) {
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    if (env_cap < SF_PAYLOAD_OVERHEAD + pt_len) return -1;

    uint32_t idx = handle - 1;
    sahc_mutex_lock(&sessions_mutex);
    if (sessions[idx].state != S_READY) { sahc_mutex_unlock(&sessions_mutex); return -2; }
    uint64_t seq = sessions[idx].seq_send + 1;
    sessions[idx].seq_send = seq;
    uint8_t key[SESSION_KEY_SIZE];
    uint8_t ivp[IV_PREFIX_SIZE];
    memcpy(key, sessions[idx].session_key, SESSION_KEY_SIZE);
    memcpy(ivp, sessions[idx].iv_prefix,   IV_PREFIX_SIZE);
    sahc_mutex_unlock(&sessions_mutex);

    write_u64_be_(env_out, seq);
    uint8_t iv[SF_IV_SIZE];
    sf_build_iv(ivp, seq, iv);
    memcpy(env_out + SF_SEQ_SIZE, iv, SF_IV_SIZE);

    uint8_t* ct  = env_out + SF_SEQ_SIZE + SF_IV_SIZE;
    uint8_t* tag = ct + pt_len;
    uint8_t aad[SF_AAD_SIZE];
    sf_build_aad(resp_type, seq, aad);

    int rc = sahc_aes128gcm_encrypt(key, iv, aad, SF_AAD_SIZE,
                                    pt, pt_len, ct, tag);
    memset(key, 0, sizeof(key));
    if (rc != 0) return -5;
    *env_len_out = SF_PAYLOAD_OVERHEAD + pt_len;
    return 0;
}

extern "C" int sahc_upload_records(uint32_t handle,
                                   uint8_t* req, size_t req_len,
                                   uint8_t* resp, size_t resp_cap,
                                   size_t* resp_len_out) {
    *resp_len_out = 0;

    uint8_t pt_buf[MAX_RECORDS_TOTAL * sizeof(PatientRecord)];
    size_t  pt_len = 0;
    PartyRoleE role;

    int rc = session_decrypt_envelope(handle, MSG_UPLOAD,
                                      req, req_len,
                                      pt_buf, sizeof(pt_buf), &pt_len, &role);
    if (rc != 0) return rc;

    if (role != PR_HOSPITAL) {
        memset(pt_buf, 0, pt_len);
        LOG("Enclave: UPLOAD denied (role != HOSPITAL)\n");
        return -8;
    }
    if (pt_len == 0 || (pt_len % sizeof(PatientRecord)) != 0) {
        memset(pt_buf, 0, pt_len);
        return -9;
    }

    size_t n = pt_len / sizeof(PatientRecord);
    PatientRecord* recs = (PatientRecord*)pt_buf;

    sahc_mutex_lock(&records_mutex);
    size_t available = (total_records < MAX_RECORDS_TOTAL)
                     ? (MAX_RECORDS_TOTAL - total_records) : 0;
    size_t accepted = (n <= available) ? n : available;
    for (size_t i = 0; i < accepted; i++)
        all_records[total_records + i] = recs[i];
    total_records += accepted;
    sahc_mutex_unlock(&records_mutex);
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
    LOG("Enclave: UPLOAD persisted\n");
    return 0;
}

static uint32_t read_u32_le_(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void write_u32_le_(uint8_t* p, uint32_t v) {
    p[0]=v&0xFF; p[1]=(v>>8)&0xFF; p[2]=(v>>16)&0xFF; p[3]=(v>>24)&0xFF;
}

extern "C" int sahc_query(uint32_t handle,
                          uint8_t* req, size_t req_len,
                          uint8_t* resp, size_t resp_cap,
                          size_t* resp_len_out) {
    *resp_len_out = 0;
    uint8_t   pt[PROTO_QUERY_REQ_SIZE];
    size_t    pt_len = 0;
    PartyRoleE role;
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

    sahc_mutex_lock(&records_mutex);
    for (size_t i = 0; i < total_records; i++) {
        if (filter >= 0 && all_records[i].diagnosis != (uint32_t)filter) continue;
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
    sahc_mutex_unlock(&records_mutex);

    if (matched < K_ANON_THRESHOLD) {
        LOG("Enclave: QUERY refused (k-anonymity)\n");
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
    memcpy(resp_pt, &result, sizeof(float));
    write_u32_le_(resp_pt + 4, matched);
    resp_pt[8] = (uint8_t)K_ANON_THRESHOLD;

    int erc = session_encrypt_envelope(handle, MSG_QUERY_RESP,
                                       resp_pt, sizeof(resp_pt),
                                       resp, resp_cap, resp_len_out);
    if (erc != 0) return erc;
    LOG("Enclave: QUERY OK\n");
    return 0;
}

/* ========== SEALING ========== */

#define SEAL_STATE_MAGIC   0x53414843u
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

extern "C" int sahc_seal_state(uint8_t* blob, size_t cap, size_t* out_len) {
    if (out_len == NULL) return -1;
    *out_len = 0;
    if (blob == NULL) return -1;

    SealedStatePT* pt = (SealedStatePT*)malloc(sizeof(SealedStatePT));
    if (pt == NULL) return -2;
    memset(pt, 0, sizeof(*pt));
    pt->magic   = SEAL_STATE_MAGIC;
    pt->version = SEAL_STATE_VERSION;

    sahc_mutex_lock(&records_mutex);
    pt->parties_count    = parties_count;
    pt->parties_quorum_m = parties_quorum_m;
    memcpy(pt->parties, parties, sizeof(parties));
    pt->total_records = (uint32_t)total_records;
    memcpy(pt->all_records, all_records, sizeof(all_records));
    sahc_mutex_unlock(&records_mutex);

    int rc = sahc_seal((const uint8_t*)pt, sizeof(*pt), blob, cap, out_len);
    memset(pt, 0, sizeof(*pt));
    free(pt);
    if (rc != 0) {
        LOG("Enclave: seal failed\n");
        return -2;
    }
    LOG("Enclave: state sealed\n");
    return 0;
}

extern "C" int sahc_unseal_state(uint8_t* blob, size_t blob_len) {
    if (blob == NULL || blob_len == 0) return -1;
    SealedStatePT* pt = (SealedStatePT*)malloc(sizeof(SealedStatePT));
    if (pt == NULL) return -1;
    size_t pt_len = 0;
    int rc = sahc_unseal(blob, blob_len, (uint8_t*)pt, sizeof(*pt), &pt_len);
    if (rc != 0 || pt_len != sizeof(*pt)) {
        memset(pt, 0, sizeof(*pt));
        free(pt);
        LOG("Enclave: unseal failed\n");
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

    sahc_mutex_lock(&records_mutex);
    parties_count    = pt->parties_count;
    parties_quorum_m = pt->parties_quorum_m;
    parties_rejected = 0;
    parties_loading  = 0;
    memcpy(parties, pt->parties, sizeof(parties));
    total_records = pt->total_records;
    memcpy(all_records, pt->all_records, sizeof(all_records));
    sahc_mutex_unlock(&records_mutex);

    memset(pt, 0, sizeof(*pt));
    free(pt);
    LOG("Enclave: state unsealed\n");
    return 0;
}

extern "C" int sahc_get_mrenclave(uint8_t* mrenclave) {
    uint8_t mrsigner_unused[32];
    return sahc_self_measurement(mrenclave, mrsigner_unused);
}
