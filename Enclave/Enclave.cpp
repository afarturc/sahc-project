#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "types.h"
#include <string.h>

#define MAX_SESSIONS      8
#define SESSION_ID_MAX   63

typedef struct {
    int     in_use;
    size_t  id_len;
    uint8_t party_id[SESSION_ID_MAX + 1];
} SessionContext;

static SessionContext sessions[MAX_SESSIONS];
static sgx_thread_mutex_t sessions_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    memcpy(pub.gx, hospital_pub,              32);
    memcpy(pub.gy, hospital_pub + 32,         32);

    sgx_ec256_signature_t sig;
    memcpy(sig.x, signature,                  32);
    memcpy(sig.y, signature + 32,             32);

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
    if (find_party_any(id, id_len) >= 0) return -3;  // duplicate

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
    if (find_party_any(id, id_len) >= 0) return -3;  // duplicate

    // Walk approvals blob: [u8 hid_len | hid | sig[64]] repeated.
    // Count distinct hospitals that produce a valid signature.
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
        return 0;  // reported via *accepted = 0
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

// Identidade do enclave (em hardware real, vem do CPU)
static const uint8_t SIMULATED_MRENCLAVE[32] = {
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89
};

// MRSIGNER = hash da chave que assinou o enclave
static const uint8_t SIMULATED_MRSIGNER[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

// Identidade do Quoting Enclave simulado
static const uint8_t QE_IDENTITY[32] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11
};

// Chave ECDSA do Quoting Enclave (simulada)
static sgx_ec256_private_t qe_sign_key;
static sgx_ec256_public_t  qe_verify_key;
static int qe_keys_ready = 0;

static int init_qe_keys()
{
    if (qe_keys_ready) return 0;

    sgx_ecc_state_handle_t handle;
    sgx_status_t s = sgx_ecc256_open_context(&handle);
    if (s != SGX_SUCCESS) return -1;

    s = sgx_ecc256_create_key_pair(&qe_sign_key, &qe_verify_key, handle);
    sgx_ecc256_close_context(handle);

    if (s != SGX_SUCCESS) return -2;

    qe_keys_ready = 1;
    ocall_print_string("Enclave: Quoting Enclave keys inicializadas\n");
    return 0;
}

/* ========== SESSION LIFECYCLE ========== */

int ecall_open_session(uint8_t* party_id, size_t id_len, uint32_t* handle_out)
{
    *handle_out = 0;
    if (party_id == NULL || id_len == 0 || id_len > SESSION_ID_MAX) return -1;

    sgx_thread_mutex_lock(&sessions_mutex);
    int idx = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].in_use) { idx = i; break; }
    }
    if (idx < 0) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        ocall_print_string("Enclave: session pool exausto\n");
        return -2;
    }
    sessions[idx].in_use = 1;
    sessions[idx].id_len = id_len;
    memcpy(sessions[idx].party_id, party_id, id_len);
    sessions[idx].party_id[id_len] = 0;
    sgx_thread_mutex_unlock(&sessions_mutex);

    *handle_out = (uint32_t)(idx + 1);
    ocall_print_string("Enclave: session aberta\n");
    return 0;
}

int ecall_close_session(uint32_t handle)
{
    if (handle == 0 || handle > MAX_SESSIONS) return -1;
    uint32_t idx = handle - 1;

    sgx_thread_mutex_lock(&sessions_mutex);
    if (!sessions[idx].in_use) {
        sgx_thread_mutex_unlock(&sessions_mutex);
        return -2;
    }
    memset(&sessions[idx], 0, sizeof(sessions[idx]));
    sgx_thread_mutex_unlock(&sessions_mutex);

    ocall_print_string("Enclave: session fechada\n");
    return 0;
}

static int session_is_valid(uint32_t handle)
{
    if (handle == 0 || handle > MAX_SESSIONS) return 0;
    sgx_thread_mutex_lock(&sessions_mutex);
    int ok = sessions[handle - 1].in_use;
    sgx_thread_mutex_unlock(&sessions_mutex);
    return ok;
}

/* ========== DCAP ATTESTATION ========== */

int ecall_generate_report(uint32_t handle,
                           uint8_t* nonce,
                           uint8_t* mrenclave_out,
                           uint8_t* mrsigner_out,
                           uint16_t* isv_prod_id,
                           uint16_t* isv_svn,
                           uint8_t* user_data_out,
                           uint8_t* signature_out,
                           uint8_t* qe_identity_out)
{
    if (!session_is_valid(handle)) {
        ocall_print_string("Enclave: generate_report com handle invalido\n");
        return -4;
    }

    // 1. Inicializar Quoting Enclave
    if (init_qe_keys() != 0) {
        ocall_print_string("Enclave: erro ao inicializar QE\n");
        return -1;
    }

    // 2. Preencher report body
    memcpy(mrenclave_out, SIMULATED_MRENCLAVE, 32);
    memcpy(mrsigner_out, SIMULATED_MRSIGNER, 32);
    *isv_prod_id = 1;   // Product ID do enclave
    *isv_svn = 1;        // Security Version Number

    // 3. User data = hash(nonce)
    //    Em DCAP real, isto inclui nonce + hash da pub key
    //    Aqui simplificamos: copiamos o nonce + padding
    memset(user_data_out, 0, USER_DATA_SIZE);
    memcpy(user_data_out, nonce, NONCE_SIZE);

    // 4. Quoting Enclave assina o report
    //    Construir os dados a assinar: mrenclave + mrsigner + user_data
    uint8_t to_sign[96];
    memcpy(to_sign, SIMULATED_MRENCLAVE, 32);
    memcpy(to_sign + 32, SIMULATED_MRSIGNER, 32);
    memcpy(to_sign + 64, user_data_out, 32);

    sgx_ecc_state_handle_t ecc_ctx;
    sgx_status_t s = sgx_ecc256_open_context(&ecc_ctx);
    if (s != SGX_SUCCESS) {
        ocall_print_string("Enclave: erro ao abrir contexto ECC para assinatura\n");
        return -2;
    }

    sgx_ec256_signature_t sig;
    s = sgx_ecdsa_sign(to_sign, 96,
                        &qe_sign_key, &sig, ecc_ctx);
    sgx_ecc256_close_context(ecc_ctx);

    if (s != SGX_SUCCESS) {
        ocall_print_string("Enclave: erro ao assinar quote\n");
        return -3;
    }

    memcpy(signature_out, &sig, QUOTE_SIGNATURE_SIZE);

    // 5. Identidade do QE
    memcpy(qe_identity_out, QE_IDENTITY, 32);

    ocall_print_string("Enclave: DCAP quote gerado e assinado\n");
    return 0;
}

