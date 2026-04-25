#ifndef _SAHC_CLIENT_IDENTITY_H_
#define _SAHC_CLIENT_IDENTITY_H_

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

/* All sizes in this header match the SGX SDK's sgx_ec256_* / sgx_ecc256_*
 * structures: P-256 coordinates and ECDSA scalars are 32 bytes each, in
 * LITTLE-ENDIAN. OpenSSL works in big-endian internally; conversions
 * happen inside identity.cpp so callers only ever see the LE wire layout. */

#define ID_PUB_SIZE        64   /* X || Y, 32B LE each (sgx_ec256_public_t) */
#define ID_SIG_SIZE        64   /* r || s, 32B LE each (sgx_ec256_signature_t) */
#define ID_SHARED_SIZE     32   /* X-coord, 32B LE     (sgx_ec256_dh_shared_t) */
#define ID_HASH_SIZE       32

/* Long-term ECDSA P-256 key loaded from PEM PKCS8 (file written by
 * scripts/gen_identity.py). Returns NULL on error. */
EVP_PKEY* identity_load_pem(const char* path);
void      identity_free(EVP_PKEY* key);

/* Sign msg with the long-term key. out_sig is 64B raw r||s, each 32B
 * little-endian. Returns 0 on success. */
int identity_sign(EVP_PKEY* key,
                  const uint8_t* msg, size_t msg_len,
                  uint8_t out_sig[ID_SIG_SIZE]);

/* Generate ephemeral ECDH P-256 keypair. *priv_out must be freed with
 * identity_free(). pub_out is X||Y, 32B LE each. */
int ecdh_keygen(EVP_PKEY** priv_out, uint8_t pub_out[ID_PUB_SIZE]);

/* Compute ECDH shared secret. peer_pub is 64B LE (X||Y); out_secret is
 * the X coordinate of the shared point, 32B LE. */
int ecdh_compute_shared(EVP_PKEY* priv,
                        const uint8_t peer_pub[ID_PUB_SIZE],
                        uint8_t out_secret[ID_SHARED_SIZE]);

int crypto_sha256(const uint8_t* data, size_t len, uint8_t out[ID_HASH_SIZE]);

/* HKDF-SHA256, single-block expand (out_len ≤ 32). info is a NUL-terminated
 * label; the 0x01 counter byte is appended automatically per RFC 5869. */
int crypto_hkdf_expand(const uint8_t* prk, size_t prk_len,
                       const char* info,
                       uint8_t* out, size_t out_len);

int crypto_hmac_sha256(const uint8_t* key, size_t key_len,
                       const uint8_t* msg, size_t msg_len,
                       uint8_t out[ID_HASH_SIZE]);

#define ID_AES128_KEY_SIZE 16
#define ID_AES_GCM_IV_SIZE 12
#define ID_AES_GCM_TAG_SIZE 16

/* AES-128-GCM. ct_out must be at least pt_len bytes. Returns 0 on success. */
int crypto_aes128gcm_encrypt(const uint8_t key[ID_AES128_KEY_SIZE],
                             const uint8_t iv[ID_AES_GCM_IV_SIZE],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* pt, size_t pt_len,
                             uint8_t* ct_out,
                             uint8_t tag_out[ID_AES_GCM_TAG_SIZE]);

/* Returns 0 on success, -1 on auth failure or any other error. pt_out must
 * be at least ct_len bytes. */
int crypto_aes128gcm_decrypt(const uint8_t key[ID_AES128_KEY_SIZE],
                             const uint8_t iv[ID_AES_GCM_IV_SIZE],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* ct, size_t ct_len,
                             const uint8_t tag[ID_AES_GCM_TAG_SIZE],
                             uint8_t* pt_out);

#endif
