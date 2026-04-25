#include "identity.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>

/* SGX uses little-endian 32-byte coordinates; OpenSSL gives us big-endian.
 * Reversing in place is the conversion. */
static void reverse_32(uint8_t* p)
{
    for (int i = 0; i < 16; i++) {
        uint8_t t = p[i];
        p[i] = p[31 - i];
        p[31 - i] = t;
    }
}

static void ssl_print_err(const char* where)
{
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    ERR_error_string_n(e, buf, sizeof(buf));
    fprintf(stderr, "openssl: %s: %s\n", where, buf);
}

/* ========== identity load / free ========== */

EVP_PKEY* identity_load_pem(const char* path)
{
    FILE* f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    EVP_PKEY* key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!key) { ssl_print_err("PEM_read_PrivateKey"); return NULL; }

    if (EVP_PKEY_id(key) != EVP_PKEY_EC) {
        fprintf(stderr, "%s: not an EC key\n", path);
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

void identity_free(EVP_PKEY* key) { if (key) EVP_PKEY_free(key); }

/* ========== ECDSA sign (DER → raw r||s LE 32B each) ========== */

int identity_sign(EVP_PKEY* key,
                  const uint8_t* msg, size_t msg_len,
                  uint8_t out_sig[ID_SIG_SIZE])
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    int rc = -1;
    uint8_t* der = NULL;
    size_t der_len = 0;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1) {
        ssl_print_err("EVP_DigestSignInit"); goto out;
    }
    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) != 1) {
        ssl_print_err("EVP_DigestSignUpdate"); goto out;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &der_len) != 1) {
        ssl_print_err("EVP_DigestSignFinal(sizing)"); goto out;
    }
    der = (uint8_t*)OPENSSL_malloc(der_len);
    if (!der) goto out;
    if (EVP_DigestSignFinal(mdctx, der, &der_len) != 1) {
        ssl_print_err("EVP_DigestSignFinal"); goto out;
    }

    /* Decode DER (SEQUENCE { r, s }) and pack as r||s, BE 32B each. */
    {
        const uint8_t* p = der;
        ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
        if (!sig) { ssl_print_err("d2i_ECDSA_SIG"); goto out; }

        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);
        if (BN_bn2binpad(r, out_sig,      32) != 32 ||
            BN_bn2binpad(s, out_sig + 32, 32) != 32) {
            ssl_print_err("BN_bn2binpad"); ECDSA_SIG_free(sig); goto out;
        }
        ECDSA_SIG_free(sig);
    }

    /* Convert each scalar BE → LE in place to match sgx_ec256_signature_t. */
    reverse_32(out_sig);
    reverse_32(out_sig + 32);
    rc = 0;

out:
    if (der) OPENSSL_free(der);
    EVP_MD_CTX_free(mdctx);
    return rc;
}

/* ========== ECDH keygen (output pub as X||Y, LE 32B each) ========== */

int ecdh_keygen(EVP_PKEY** priv_out, uint8_t pub_out[ID_PUB_SIZE])
{
    *priv_out = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    int rc = -1;
    EVP_PKEY* key = NULL;

    if (EVP_PKEY_keygen_init(pctx) != 1) {
        ssl_print_err("EVP_PKEY_keygen_init"); goto out;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
            NID_X9_62_prime256v1) != 1) {
        ssl_print_err("set_ec_paramgen_curve_nid"); goto out;
    }
    if (EVP_PKEY_keygen(pctx, &key) != 1) {
        ssl_print_err("EVP_PKEY_keygen"); goto out;
    }

    {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key);
        if (!ec) { ssl_print_err("EVP_PKEY_get1_EC_KEY"); goto out; }
        const EC_POINT* pt = EC_KEY_get0_public_key(ec);
        const EC_GROUP* grp = EC_KEY_get0_group(ec);

        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        int got = (x && y &&
                   EC_POINT_get_affine_coordinates(grp, pt, x, y, NULL) == 1);
        if (got &&
            BN_bn2binpad(x, pub_out,      32) == 32 &&
            BN_bn2binpad(y, pub_out + 32, 32) == 32) {
            reverse_32(pub_out);
            reverse_32(pub_out + 32);
            rc = 0;
        } else {
            ssl_print_err("get_affine/bn2binpad");
        }
        BN_free(x); BN_free(y);
        EC_KEY_free(ec);
    }

    if (rc == 0) { *priv_out = key; key = NULL; }

out:
    if (key) EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* ========== ECDH compute shared (peer pub LE, output X coord LE) ========== */

int ecdh_compute_shared(EVP_PKEY* priv,
                        const uint8_t peer_pub[ID_PUB_SIZE],
                        uint8_t out_secret[ID_SHARED_SIZE])
{
    /* Convert peer pub LE → BE coordinates and rebuild EC_POINT. */
    uint8_t x_be[32], y_be[32];
    for (int i = 0; i < 32; i++) x_be[i] = peer_pub[31 - i];
    for (int i = 0; i < 32; i++) y_be[i] = peer_pub[32 + 31 - i];

    int rc = -1;
    BIGNUM* x = BN_bin2bn(x_be, 32, NULL);
    BIGNUM* y = BN_bin2bn(y_be, 32, NULL);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* pt  = grp ? EC_POINT_new(grp) : NULL;
    EC_KEY*   peer_ec = EC_KEY_new();
    EVP_PKEY* peer = EVP_PKEY_new();
    EVP_PKEY_CTX* dctx = NULL;
    size_t  slen = 32;
    uint8_t shared_be[32];

    if (!x || !y || !grp || !pt || !peer_ec || !peer) goto out;
    if (EC_POINT_set_affine_coordinates(grp, pt, x, y, NULL) != 1) {
        ssl_print_err("EC_POINT_set_affine_coordinates"); goto out;
    }
    if (EC_KEY_set_group(peer_ec, grp) != 1 ||
        EC_KEY_set_public_key(peer_ec, pt) != 1) {
        ssl_print_err("EC_KEY_set_*"); goto out;
    }
    if (EVP_PKEY_assign_EC_KEY(peer, peer_ec) != 1) {
        ssl_print_err("EVP_PKEY_assign_EC_KEY"); goto out;
    }
    peer_ec = NULL;  /* owned by peer now */

    dctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!dctx) { ssl_print_err("EVP_PKEY_CTX_new"); goto out; }
    if (EVP_PKEY_derive_init(dctx) != 1 ||
        EVP_PKEY_derive_set_peer(dctx, peer) != 1) {
        ssl_print_err("EVP_PKEY_derive_init/set_peer"); goto out;
    }
    if (EVP_PKEY_derive(dctx, shared_be, &slen) != 1 || slen != 32) {
        ssl_print_err("EVP_PKEY_derive"); goto out;
    }
    for (int i = 0; i < 32; i++) out_secret[i] = shared_be[31 - i];
    memset(shared_be, 0, sizeof(shared_be));
    rc = 0;

out:
    if (dctx) EVP_PKEY_CTX_free(dctx);
    if (peer) EVP_PKEY_free(peer);
    if (peer_ec) EC_KEY_free(peer_ec);
    if (pt) EC_POINT_free(pt);
    if (grp) EC_GROUP_free(grp);
    if (x) BN_free(x);
    if (y) BN_free(y);
    return rc;
}

/* ========== Hash / HMAC / HKDF ========== */

int crypto_sha256(const uint8_t* data, size_t len, uint8_t out[ID_HASH_SIZE])
{
    SHA256_CTX c;
    if (SHA256_Init(&c) != 1) return -1;
    if (SHA256_Update(&c, data, len) != 1) return -1;
    if (SHA256_Final(out, &c) != 1) return -1;
    return 0;
}

int crypto_hmac_sha256(const uint8_t* key, size_t key_len,
                       const uint8_t* msg, size_t msg_len,
                       uint8_t out[ID_HASH_SIZE])
{
    unsigned int n = 32;
    if (!HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, out, &n)) {
        ssl_print_err("HMAC"); return -1;
    }
    return n == 32 ? 0 : -1;
}

int crypto_hkdf_expand(const uint8_t* prk, size_t prk_len,
                       const char* info,
                       uint8_t* out, size_t out_len)
{
    if (out_len > 32) return -1;
    size_t info_len = strlen(info);
    uint8_t buf[64];
    if (info_len + 1 > sizeof(buf)) return -1;
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;

    uint8_t t1[32];
    if (crypto_hmac_sha256(prk, prk_len, buf, info_len + 1, t1) != 0) {
        return -1;
    }
    memcpy(out, t1, out_len);
    memset(t1, 0, sizeof(t1));
    return 0;
}

/* ========== AES-128-GCM via OpenSSL EVP ========== */

int crypto_aes128gcm_encrypt(const uint8_t key[ID_AES128_KEY_SIZE],
                             const uint8_t iv[ID_AES_GCM_IV_SIZE],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* pt, size_t pt_len,
                             uint8_t* ct_out,
                             uint8_t tag_out[ID_AES_GCM_TAG_SIZE])
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    int outl = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        ssl_print_err("EncryptInit"); goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            ID_AES_GCM_IV_SIZE, NULL) != 1) {
        ssl_print_err("set IVLEN"); goto out;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ssl_print_err("EncryptInit(key,iv)"); goto out;
    }
    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) {
        ssl_print_err("EncryptUpdate(aad)"); goto out;
    }
    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx, ct_out, &outl, pt, (int)pt_len) != 1) {
        ssl_print_err("EncryptUpdate(pt)"); goto out;
    }
    if (EVP_EncryptFinal_ex(ctx, ct_out + outl, &outl) != 1) {
        ssl_print_err("EncryptFinal"); goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            ID_AES_GCM_TAG_SIZE, tag_out) != 1) {
        ssl_print_err("get TAG"); goto out;
    }
    rc = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int crypto_aes128gcm_decrypt(const uint8_t key[ID_AES128_KEY_SIZE],
                             const uint8_t iv[ID_AES_GCM_IV_SIZE],
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* ct, size_t ct_len,
                             const uint8_t tag[ID_AES_GCM_TAG_SIZE],
                             uint8_t* pt_out)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    int outl = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        ssl_print_err("DecryptInit"); goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            ID_AES_GCM_IV_SIZE, NULL) != 1) {
        ssl_print_err("set IVLEN"); goto out;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ssl_print_err("DecryptInit(key,iv)"); goto out;
    }
    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) {
        ssl_print_err("DecryptUpdate(aad)"); goto out;
    }
    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx, pt_out, &outl, ct, (int)ct_len) != 1) {
        ssl_print_err("DecryptUpdate(ct)"); goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            ID_AES_GCM_TAG_SIZE, (void*)tag) != 1) {
        ssl_print_err("set TAG"); goto out;
    }
    if (EVP_DecryptFinal_ex(ctx, pt_out + outl, &outl) != 1) {
        /* Auth failure: do not log via ssl_print_err — caller decides. */
        goto out;
    }
    rc = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
