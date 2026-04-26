/* OpenSSL EVP implementation of crypto_backend.h.
 *
 * Used inside the Gramine LibOS process. The wire encoding the rest of
 * the project assumes (little-endian 32 B halves for P-256 X/Y and
 * ECDSA r/s) is converted to/from OpenSSL's native big-endian internally.
 * Tested on OpenSSL 3.x; the deprecation-noisy EC_KEY API is avoided —
 * we go through EVP_PKEY everywhere.
 */

#include "crypto_backend.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <string.h>

namespace {

/* Reverse 32 bytes in place: LE↔BE for a 256-bit big-int. */
void rev32(uint8_t* x) {
    for (int i = 0; i < 16; i++) { uint8_t t = x[i]; x[i] = x[31-i]; x[31-i] = t; }
}

/* Build EVP_PKEY for a P-256 public key from 64 B (gx_LE || gy_LE). */
EVP_PKEY* pubkey_from_le64(const uint8_t pub_le[64]) {
    /* OSSL wants uncompressed point: 0x04 || X(BE,32) || Y(BE,32) */
    uint8_t pt[65];
    pt[0] = 0x04;
    memcpy(pt + 1,  pub_le,      32); rev32(pt + 1);
    memcpy(pt + 33, pub_le + 32, 32); rev32(pt + 33);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, "group", (char*)"prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, "pub", pt, sizeof(pt));
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    return pkey;
}

/* Build EVP_PKEY for a P-256 keypair from 32 B (priv_LE) — pub is
 * derived. Used by sign and ECDH. */
EVP_PKEY* keypair_from_le_priv(const uint8_t priv_le[32]) {
    uint8_t priv_be[32];
    memcpy(priv_be, priv_le, 32);
    rev32(priv_be);

    BIGNUM* bn = BN_bin2bn(priv_be, 32, NULL);
    OPENSSL_cleanse(priv_be, sizeof(priv_be));
    if (!bn) return NULL;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, "group", (char*)"prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, "priv", bn);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(bn);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    return pkey;
}

/* Extract 64 B (gx_LE||gy_LE) from a public EVP_PKEY. */
int pkey_to_le_pub(EVP_PKEY* pkey, uint8_t pub_le_out[64]) {
    uint8_t pt[256];
    size_t pt_len = sizeof(pt);
    if (EVP_PKEY_get_octet_string_param(pkey, "pub", pt, sizeof(pt), &pt_len) <= 0)
        return -1;
    if (pt_len != 65 || pt[0] != 0x04) return -1;
    memcpy(pub_le_out,      pt + 1,  32); rev32(pub_le_out);
    memcpy(pub_le_out + 32, pt + 33, 32); rev32(pub_le_out + 32);
    return 0;
}

/* Extract 32 B priv_LE from a keypair EVP_PKEY. */
int pkey_to_le_priv(EVP_PKEY* pkey, uint8_t priv_le_out[32]) {
    BIGNUM* bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, "priv", &bn) <= 0) return -1;
    uint8_t priv_be[32] = {0};
    int n = BN_bn2binpad(bn, priv_be, 32);
    BN_clear_free(bn);
    if (n != 32) return -1;
    memcpy(priv_le_out, priv_be, 32);
    rev32(priv_le_out);
    OPENSSL_cleanse(priv_be, sizeof(priv_be));
    return 0;
}

} /* namespace */

extern "C" {

int sahc_random_bytes(uint8_t* out, size_t len) {
    return (RAND_bytes(out, (int)len) == 1) ? 0 : -1;
}

int sahc_ecc_keygen(uint8_t priv_out[32], uint8_t pub_out[64]) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY*     pkey = NULL;
    int rc = -1;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_group_name(pctx, "prime256v1") <= 0) goto out;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto out;

    if (pkey_to_le_priv(pkey, priv_out) != 0) goto out;
    if (pkey_to_le_pub(pkey,  pub_out)  != 0) goto out;
    rc = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int sahc_ecdh_shared(const uint8_t priv[32], const uint8_t peer_pub[64],
                     uint8_t shared_out[32]) {
    EVP_PKEY* my   = keypair_from_le_priv(priv);
    EVP_PKEY* peer = pubkey_from_le64(peer_pub);
    EVP_PKEY_CTX* dctx = NULL;
    int rc = -1;

    if (!my || !peer) goto out;
    dctx = EVP_PKEY_CTX_new(my, NULL);
    if (!dctx) goto out;

    if (EVP_PKEY_derive_init(dctx) <= 0) goto out;
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) goto out;

    {
        uint8_t shared_be[32] = {0};
        size_t  out_len = sizeof(shared_be);
        if (EVP_PKEY_derive(dctx, shared_be, &out_len) <= 0) goto out;
        if (out_len != 32) goto out;
        memcpy(shared_out, shared_be, 32);
        rev32(shared_out);
        OPENSSL_cleanse(shared_be, sizeof(shared_be));
    }
    rc = 0;
out:
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(my);
    return rc;
}

int sahc_ecdsa_sign(const uint8_t priv[32],
                    const uint8_t* msg, size_t msg_len,
                    uint8_t sig_out[64]) {
    EVP_PKEY* pkey = keypair_from_le_priv(priv);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    int rc = -1;
    uint8_t  der[80];
    size_t   der_len = sizeof(der);
    ECDSA_SIG* esig  = NULL;
    const BIGNUM* r_bn = NULL;
    const BIGNUM* s_bn = NULL;

    if (!pkey || !mctx) goto out;
    if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto out;
    if (EVP_DigestSign(mctx, der, &der_len, msg, msg_len) <= 0) goto out;

    {
        const uint8_t* p = der;
        esig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
        if (!esig) goto out;
        ECDSA_SIG_get0(esig, &r_bn, &s_bn);

        uint8_t r_be[32] = {0}, s_be[32] = {0};
        if (BN_bn2binpad(r_bn, r_be, 32) != 32) goto out;
        if (BN_bn2binpad(s_bn, s_be, 32) != 32) goto out;
        memcpy(sig_out,      r_be, 32); rev32(sig_out);
        memcpy(sig_out + 32, s_be, 32); rev32(sig_out + 32);
    }
    rc = 0;
out:
    ECDSA_SIG_free(esig);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int sahc_ecdsa_verify(const uint8_t pub[64],
                      const uint8_t* msg, size_t msg_len,
                      const uint8_t sig[64]) {
    EVP_PKEY* pkey = pubkey_from_le64(pub);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    ECDSA_SIG* esig  = ECDSA_SIG_new();
    BIGNUM* r_bn = NULL;
    BIGNUM* s_bn = NULL;
    int rc = -1;

    if (!pkey || !mctx || !esig) goto out;

    {
        uint8_t r_be[32], s_be[32];
        memcpy(r_be, sig,      32); rev32(r_be);
        memcpy(s_be, sig + 32, 32); rev32(s_be);
        r_bn = BN_bin2bn(r_be, 32, NULL);
        s_bn = BN_bin2bn(s_be, 32, NULL);
        if (!r_bn || !s_bn) goto out;
        if (ECDSA_SIG_set0(esig, r_bn, s_bn) != 1) goto out;
        r_bn = s_bn = NULL;  /* owned by esig now */
    }

    {
        uint8_t der[80];
        uint8_t* p = der;
        int der_len = i2d_ECDSA_SIG(esig, &p);
        if (der_len <= 0) goto out;

        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto out;
        int v = EVP_DigestVerify(mctx, der, (size_t)der_len, msg, msg_len);
        rc = (v == 1) ? 0 : -1;
    }
out:
    BN_free(r_bn);
    BN_free(s_bn);
    ECDSA_SIG_free(esig);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int sahc_sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
    unsigned int n = 0;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    if (!c) return -1;
    int rc = -1;
    if (EVP_DigestInit_ex(c, EVP_sha256(), NULL) != 1) goto out;
    if (EVP_DigestUpdate(c, msg, len) != 1) goto out;
    if (EVP_DigestFinal_ex(c, out, &n) != 1 || n != 32) goto out;
    rc = 0;
out:
    EVP_MD_CTX_free(c);
    return rc;
}

int sahc_hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t out[32]) {
    unsigned int n = 32;
    return HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, out, &n)
           ? 0 : -1;
}

int sahc_aes128gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt,  size_t pt_len,
                           uint8_t* ct_out, uint8_t tag_out[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1, len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int sahc_aes128gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct,  size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t* pt_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1, len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

} /* extern "C" */
