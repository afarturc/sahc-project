#ifndef SAHC_SEAL_BACKEND_H
#define SAHC_SEAL_BACKEND_H

/* MRENCLAVE-bound sealing of opaque state.
 *
 * SGX-SDK backend (seal_backend_sgx.cpp): sgx_seal_data_ex with
 *   SGX_KEYPOLICY_MRENCLAVE, attribute_mask 0xFF0000000000000B/0,
 *   misc_mask 0xF0000000.
 * Gramine backend (seal_backend_gramine.cpp): derives a 16-byte AES-GCM
 *   key from /dev/attestation/keys/_sgx_mrenclave (the per-MRENCLAVE
 *   sealing key the PSW exposes inside the LibOS), then wraps the
 *   plaintext with AES-128-GCM. In gramine-direct the pseudo-file
 *   returns deterministic dev bytes — sealing still works but offers
 *   no real confidentiality; documented as dev-only.
 *
 * Layout of the Gramine blob:
 *   magic(4) | version(4) | iv(12) | tag(16) | ciphertext(N)
 *
 * Layout of the SGX blob: opaque sgx_sealed_data_t produced by
 *   sgx_seal_data_ex. The two blob formats are NOT interchangeable —
 *   each backend can only unseal what it sealed.
 *
 * Returns 0 on success, negative on failure. cap < required → -1.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Worst-case overhead either backend adds on top of plaintext. Callers
 * size their seal buffers as plaintext_size + SAHC_SEAL_MAX_OVERHEAD. */
#define SAHC_SEAL_MAX_OVERHEAD 1024

int sahc_seal(const uint8_t* pt, size_t pt_len,
              uint8_t* blob_out, size_t blob_cap, size_t* blob_len_out);

int sahc_unseal(const uint8_t* blob, size_t blob_len,
                uint8_t* pt_out, size_t pt_cap, size_t* pt_len_out);

#ifdef __cplusplus
}
#endif

#endif
