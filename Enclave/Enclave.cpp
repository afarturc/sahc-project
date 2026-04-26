/* SGX-SDK ECALL forwarders.
 *
 * After the EnclaveLogic refactor the actual logic lives in
 * EnclaveLogic/enclave_logic.cpp; this file is the SDK adapter — it
 * forwards each ECALL to the matching sahc_* function and routes log
 * lines back to the host via ocall_print_string. The Enclave.edl
 * surface is unchanged so the generated trusted/untrusted wrappers
 * keep working without regeneration.
 */

#include "Enclave_t.h"
#include "enclave_logic.h"

#include <stdint.h>
#include <stddef.h>

static void log_to_ocall(const char* s) { ocall_print_string(s); }

static int g_log_installed = 0;
static void ensure_log_installed(void) {
    if (!g_log_installed) {
        sahc_log_install(log_to_ocall);
        g_log_installed = 1;
    }
}

extern "C" {

int ecall_parties_begin(uint32_t quorum_m) {
    ensure_log_installed();
    return sahc_parties_begin(quorum_m);
}

int ecall_parties_add_hospital(uint8_t* id, size_t id_len, uint8_t* pubkey) {
    return sahc_parties_add_hospital(id, id_len, pubkey);
}

int ecall_parties_add_researcher(uint8_t* id, size_t id_len,
                                 uint8_t* pubkey,
                                 uint8_t* approvals_blob, size_t approvals_len,
                                 uint32_t* accepted) {
    return sahc_parties_add_researcher(id, id_len, pubkey,
                                       approvals_blob, approvals_len, accepted);
}

int ecall_parties_end(uint32_t* h, uint32_t* r, uint32_t* rj) {
    return sahc_parties_end(h, r, rj);
}

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
                       uint8_t* qe_identity_out) {
    ensure_log_installed();
    return sahc_attest_begin(party_id, id_len, nonce, client_ecdh_pub, signature,
                             handle_out, enclave_ecdh_pub_out,
                             mrenclave_out, mrsigner_out,
                             isv_prod_id_out, isv_svn_out,
                             user_data_out, quote_sig_out, qe_identity_out);
}

int ecall_key_confirm(uint32_t handle, uint8_t* mac, uint8_t* role) {
    return sahc_key_confirm(handle, mac, role);
}

int ecall_upload_records(uint32_t handle,
                         uint8_t* req, size_t req_len,
                         uint8_t* resp, size_t resp_cap, size_t* resp_len) {
    return sahc_upload_records(handle, req, req_len, resp, resp_cap, resp_len);
}

int ecall_query(uint32_t handle,
                uint8_t* req, size_t req_len,
                uint8_t* resp, size_t resp_cap, size_t* resp_len) {
    return sahc_query(handle, req, req_len, resp, resp_cap, resp_len);
}

int ecall_close_session(uint32_t handle) {
    return sahc_close_session(handle);
}

int ecall_seal_state(uint8_t* blob, size_t cap, size_t* out_len) {
    return sahc_seal_state(blob, cap, out_len);
}

int ecall_unseal_state(uint8_t* blob, size_t blob_len) {
    return sahc_unseal_state(blob, blob_len);
}

int ecall_get_mrenclave(uint8_t* mrenclave) {
    return sahc_get_mrenclave(mrenclave);
}

} /* extern "C" */
