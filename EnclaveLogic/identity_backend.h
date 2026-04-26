#ifndef SAHC_IDENTITY_BACKEND_H
#define SAHC_IDENTITY_BACKEND_H

/* Self-measurement of the running TEE.
 *
 * SGX-SDK backend (identity_backend_sgx.cpp): sgx_self_target +
 *   sgx_create_report — works in SIM and HW.
 * Gramine backend (identity_backend_gramine.cpp): reads the pseudo-files
 *   /dev/attestation/{mrenclave,mrsigner}. In gramine-sgx on real Intel
 *   HW these are the genuine measurements; in gramine-direct they return
 *   well-defined dev placeholders.
 *
 * The QE-signed quote is assembled in enclave_logic itself using the
 * crypto backend (artisanal, mirrors the M2 DCAP-style format) — the
 * real DCAP path is already gated by Client/quote_verify.cpp.
 *
 * Returns 0 on success, negative on failure.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int sahc_self_measurement(uint8_t mrenclave_out[32],
                          uint8_t mrsigner_out[32]);

#ifdef __cplusplus
}
#endif

#endif
