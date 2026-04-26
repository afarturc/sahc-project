#ifndef SAHC_ENCLAVE_LOGIC_H
#define SAHC_ENCLAVE_LOGIC_H

/* SDK-neutral enclave logic.
 *
 * One function per legacy ECALL. Identical semantics, identical return
 * codes — the only difference is no [in,count]/[out] annotations: callers
 * pass plain pointers and are responsible for their lifetimes. The SGX-SDK
 * wrappers in Enclave/Enclave.cpp delegate verbatim; the gramine_server
 * binary calls these directly with no marshalling.
 *
 * Backed by:
 *   crypto_backend.h      (SGX tcrypto OR OpenSSL)
 *   identity_backend.h    (SGX self-target OR /dev/attestation)
 *   seal_backend.h        (sgx_seal_data_ex OR Gramine sealing key)
 *
 * All return codes match the pre-refactor enclave so wire-error mapping
 * in Server/server_main.cpp does not need to change.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Optional: install a logging callback. Default is no-op. The SGX-SDK
 * wrapper sets this to a function that issues ocall_print_string. */
void sahc_log_install(void (*cb)(const char*));

/* Parties loading — same semantics as ecall_parties_*. */
int sahc_parties_begin(uint32_t quorum_m);
int sahc_parties_add_hospital(uint8_t* id, size_t id_len, uint8_t* pubkey);
int sahc_parties_add_researcher(uint8_t* id, size_t id_len, uint8_t* pubkey,
                                uint8_t* approvals_blob, size_t approvals_len,
                                uint32_t* accepted);
int sahc_parties_end(uint32_t* hospitals_count,
                     uint32_t* researchers_count,
                     uint32_t* rejected_count);

/* Attestation + ECDH key exchange. */
int sahc_attest_begin(uint8_t* party_id, size_t id_len,
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
                      uint8_t* qe_identity_out);

int sahc_key_confirm(uint32_t handle, uint8_t* client_mac, uint8_t* assigned_role);

int sahc_upload_records(uint32_t handle,
                        uint8_t* req, size_t req_len,
                        uint8_t* resp, size_t resp_cap, size_t* resp_len_out);

int sahc_query(uint32_t handle,
               uint8_t* req, size_t req_len,
               uint8_t* resp, size_t resp_cap, size_t* resp_len_out);

int sahc_close_session(uint32_t handle);

int sahc_seal_state(uint8_t* blob, size_t cap, size_t* out_len);
int sahc_unseal_state(uint8_t* blob, size_t blob_len);

int sahc_get_mrenclave(uint8_t* mrenclave);

#ifdef __cplusplus
}
#endif

#endif
