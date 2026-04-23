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

// Session keys
static sgx_aes_gcm_128bit_key_t session_keys[MAX_HOSPITALS];
static int hospital_attested[MAX_HOSPITALS] = {0};

// Armazenamento de registos
static PatientRecord all_records[MAX_HOSPITALS * MAX_RECORDS];
static size_t total_records = 0;

static float get_field_value(const PatientRecord* rec, uint32_t field)
{
    switch (field) {
        case FIELD_AGE:         return (float)rec->age;
        case FIELD_TEMPERATURE: return rec->temperature;
        case FIELD_BLOOD_SUGAR: return rec->blood_sugar;
        default:                return 0.0f;
    }
}

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

/* ========== KEY EXCHANGE ========== */

int ecall_finish_key_exchange(uint32_t hospital_id,
                               uint8_t* hospital_pub_key,
                               uint8_t* session_key_out)
{
    if (hospital_id >= MAX_HOSPITALS) return -1;

    sgx_status_t status = sgx_read_rand(
        (uint8_t*)&session_keys[hospital_id], 16);
    if (status != SGX_SUCCESS) return -2;

    hospital_attested[hospital_id] = 1;
    memcpy(session_key_out, &session_keys[hospital_id], 16);

    ocall_print_string("Enclave: session key gerada!\n");
    return 0;
}

/* ========== UPLOAD ========== */

int ecall_upload_data(uint32_t hospital_id,
                      uint8_t* encrypted_data, size_t data_len,
                      uint8_t* iv, uint8_t* tag)
{
    if (hospital_id >= MAX_HOSPITALS) return -1;
    if (!hospital_attested[hospital_id]) {
        ocall_print_string("Enclave: hospital nao verificado!\n");
        return -3;
    }

    uint8_t* decrypted = new uint8_t[data_len];
    sgx_status_t status = sgx_rijndael128GCM_decrypt(
        &session_keys[hospital_id],
        encrypted_data, data_len, decrypted,
        iv, 12, NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*)tag);

    if (status != SGX_SUCCESS) {
        ocall_print_string("Enclave: erro ao desencriptar!\n");
        delete[] decrypted;
        return -2;
    }

    PatientRecord* records = (PatientRecord*)decrypted;
    size_t num = data_len / sizeof(PatientRecord);
    size_t capacity = MAX_HOSPITALS * MAX_RECORDS;

    if (total_records + num > capacity) {
        ocall_print_string("Enclave: AVISO - capacidade excedida, a truncar\n");
        num = capacity - total_records;
    }

    size_t offset = total_records;
    for (size_t i = 0; i < num; i++)
        all_records[offset + i] = records[i];

    total_records += num;
    ocall_print_string("Enclave: dados recebidos!\n");
    memset(decrypted, 0, data_len);
    delete[] decrypted;
    return (int)num;
}

/* ========== QUERY ========== */

void ecall_run_query(uint32_t field, uint32_t query_type,
                     int32_t filter_diag,
                     float* result_value,
                     uint32_t* total_processed,
                     uint32_t* total_matched)
{
    if (field > FIELD_BLOOD_SUGAR) {
        ocall_print_string("Enclave: campo invalido na query\n");
        *result_value = 0.0f;
        *total_processed = 0;
        *total_matched = 0;
        return;
    }
    if (query_type > QUERY_COUNT) {
        ocall_print_string("Enclave: tipo de query invalido\n");
        *result_value = 0.0f;
        *total_processed = 0;
        *total_matched = 0;
        return;
    }

    float sum = 0.0f, min_val = 999999.0f, max_val = -999999.0f;
    uint32_t matched = 0;

    for (size_t i = 0; i < total_records; i++) {
        if (filter_diag >= 0 &&
            all_records[i].diagnosis != (uint32_t)filter_diag)
            continue;

        float val = get_field_value(&all_records[i], field);
        sum += val;
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
        matched++;
    }

    switch (query_type) {
        case QUERY_AVG:
            *result_value = (matched > 0) ? sum / (float)matched : 0.0f;
            break;
        case QUERY_MIN:
            *result_value = (matched > 0) ? min_val : 0.0f;
            break;
        case QUERY_MAX:
            *result_value = (matched > 0) ? max_val : 0.0f;
            break;
        case QUERY_COUNT:
            *result_value = (float)matched;
            break;
    }

    *total_processed = (uint32_t)total_records;
    *total_matched = matched;
    ocall_print_string("Enclave: query concluida!\n");
}
