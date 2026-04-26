/* SGX-tcrypto implementation of crypto_backend.h.
 *
 * Compiled inside the SGX-SDK enclave (no glibc; uses tlibc + sgx_tcrypto).
 * The wire encoding stays in 32 B little-endian halves; sgx_ec256_*
 * already uses LE for the on-curve scalar/coordinate, so most conversions
 * are no-ops. ECDH shared.s is also LE 32 B.
 */

#include "crypto_backend.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <string.h>

extern "C" {

int sahc_random_bytes(uint8_t* out, size_t len) {
    return (sgx_read_rand(out, len) == SGX_SUCCESS) ? 0 : -1;
}

int sahc_ecc_keygen(uint8_t priv_out[32], uint8_t pub_out[64]) {
    sgx_ecc_state_handle_t ctx;
    if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) return -1;
    sgx_ec256_private_t priv;
    sgx_ec256_public_t  pub;
    sgx_status_t s = sgx_ecc256_create_key_pair(&priv, &pub, ctx);
    sgx_ecc256_close_context(ctx);
    if (s != SGX_SUCCESS) return -1;
    memcpy(priv_out,      priv.r,  32);
    memcpy(pub_out,       pub.gx,  32);
    memcpy(pub_out + 32,  pub.gy,  32);
    memset(&priv, 0, sizeof(priv));
    return 0;
}

int sahc_ecdh_shared(const uint8_t priv[32], const uint8_t peer_pub[64],
                     uint8_t shared_out[32]) {
    sgx_ec256_private_t  my_priv;
    sgx_ec256_public_t   peer;
    sgx_ec256_dh_shared_t shared;
    memcpy(my_priv.r, priv,         32);
    memcpy(peer.gx,   peer_pub,     32);
    memcpy(peer.gy,   peer_pub + 32, 32);

    sgx_ecc_state_handle_t ctx;
    if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) {
        memset(&my_priv, 0, sizeof(my_priv));
        return -1;
    }
    sgx_status_t s = sgx_ecc256_compute_shared_dhkey(&my_priv, &peer, &shared, ctx);
    sgx_ecc256_close_context(ctx);
    memset(&my_priv, 0, sizeof(my_priv));
    if (s != SGX_SUCCESS) { memset(&shared, 0, sizeof(shared)); return -1; }
    memcpy(shared_out, shared.s, 32);
    memset(&shared, 0, sizeof(shared));
    return 0;
}

int sahc_ecdsa_sign(const uint8_t priv[32],
                    const uint8_t* msg, size_t msg_len,
                    uint8_t sig_out[64]) {
    sgx_ec256_private_t   my_priv;
    sgx_ec256_signature_t sig;
    memcpy(my_priv.r, priv, 32);

    sgx_ecc_state_handle_t ctx;
    if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) {
        memset(&my_priv, 0, sizeof(my_priv));
        return -1;
    }
    sgx_status_t s = sgx_ecdsa_sign(msg, (uint32_t)msg_len, &my_priv, &sig, ctx);
    sgx_ecc256_close_context(ctx);
    memset(&my_priv, 0, sizeof(my_priv));
    if (s != SGX_SUCCESS) return -1;
    memcpy(sig_out,      sig.x, 32);
    memcpy(sig_out + 32, sig.y, 32);
    return 0;
}

int sahc_ecdsa_verify(const uint8_t pub[64],
                      const uint8_t* msg, size_t msg_len,
                      const uint8_t sig[64]) {
    sgx_ec256_public_t    p;
    sgx_ec256_signature_t s;
    memcpy(p.gx, pub,         32);
    memcpy(p.gy, pub + 32,    32);
    memcpy(s.x,  sig,         32);
    memcpy(s.y,  sig + 32,    32);

    sgx_ecc_state_handle_t ctx;
    if (sgx_ecc256_open_context(&ctx) != SGX_SUCCESS) return -1;
    uint8_t result = 0;
    sgx_status_t st = sgx_ecdsa_verify(msg, (uint32_t)msg_len, &p, &s, &result, ctx);
    sgx_ecc256_close_context(ctx);
    return (st == SGX_SUCCESS && result == SGX_EC_VALID) ? 0 : -1;
}

int sahc_sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
    sgx_sha256_hash_t h;
    sgx_status_t s = sgx_sha256_msg(msg, (uint32_t)len, &h);
    if (s != SGX_SUCCESS) return -1;
    memcpy(out, &h, 32);
    return 0;
}

int sahc_hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t out[32]) {
    sgx_status_t s = sgx_hmac_sha256_msg(msg, (int)msg_len,
                                         key, (int)key_len,
                                         out, 32);
    return (s == SGX_SUCCESS) ? 0 : -1;
}

int sahc_aes128gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt,  size_t pt_len,
                           uint8_t* ct_out, uint8_t tag_out[16]) {
    sgx_status_t s = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)key,
        pt, (uint32_t)pt_len, ct_out,
        iv, 12,
        aad, (uint32_t)aad_len,
        (sgx_aes_gcm_128bit_tag_t*)tag_out);
    return (s == SGX_SUCCESS) ? 0 : -1;
}

int sahc_aes128gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct,  size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t* pt_out) {
    sgx_status_t s = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)key,
        ct, (uint32_t)ct_len, pt_out,
        iv, 12,
        aad, (uint32_t)aad_len,
        (const sgx_aes_gcm_128bit_tag_t*)tag);
    return (s == SGX_SUCCESS) ? 0 : -1;
}

} /* extern "C" */
