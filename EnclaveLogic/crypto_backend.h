#ifndef SAHC_CRYPTO_BACKEND_H
#define SAHC_CRYPTO_BACKEND_H

/* Crypto contract used by the enclave logic. Two implementations:
 *  - crypto_backend_sgx.cpp   (sgx_tcrypto, runs inside SGX-SDK enclave)
 *  - crypto_backend_openssl.cpp (OpenSSL EVP, runs inside Gramine LibOS)
 *
 * Key/signature wire encoding stays as the rest of the project uses:
 *   ECC P-256 public key  : 64 B = gx(32 LE) || gy(32 LE)
 *   ECDSA signature       : 64 B = r(32 LE)  || s(32 LE)
 *   ECDH shared secret    : 32 B big-integer x-coord (LE)
 * Backends translate to/from their own native encodings internally.
 *
 * Return convention: 0 on success, negative on failure. No errno.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int sahc_random_bytes(uint8_t* out, size_t len);

/* ECC P-256 */
int sahc_ecc_keygen(uint8_t priv_out[32], uint8_t pub_out[64]);
int sahc_ecdh_shared(const uint8_t priv[32], const uint8_t peer_pub[64],
                     uint8_t shared_out[32]);
int sahc_ecdsa_sign(const uint8_t priv[32],
                    const uint8_t* msg, size_t msg_len,
                    uint8_t sig_out[64]);
int sahc_ecdsa_verify(const uint8_t pub[64],
                      const uint8_t* msg, size_t msg_len,
                      const uint8_t sig[64]);  /* 0=valid, -1=invalid */

/* SHA-256 / HMAC-SHA256 (one-shot) */
int sahc_sha256(const uint8_t* msg, size_t len, uint8_t out[32]);
int sahc_hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t out[32]);

/* AES-128-GCM. iv is exactly 12 B; tag is exactly 16 B. */
int sahc_aes128gcm_encrypt(const uint8_t key[16],
                           const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt,  size_t pt_len,
                           uint8_t* ct_out, uint8_t tag_out[16]);
int sahc_aes128gcm_decrypt(const uint8_t key[16],
                           const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct,  size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t* pt_out);

#ifdef __cplusplus
}
#endif

#endif
