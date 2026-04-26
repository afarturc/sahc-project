/* Standalone smoke test for the OpenSSL crypto backend.
 *
 * Exercises every primitive once and prints PASS/FAIL.
 *  - random bytes
 *  - ECC keypair + ECDH (two parties derive matching secret)
 *  - ECDSA sign / verify (round-trip + tamper detection)
 *  - SHA-256 against RFC 6234 vector
 *  - HMAC-SHA256 against RFC 4231 test case 1
 *  - AES-128-GCM round-trip with AAD + tamper detection
 *
 * Build standalone (no SGX SDK needed):
 *   g++ -std=c++17 -Wall -O2 -I. EnclaveLogic/smoke.cpp \
 *       EnclaveLogic/crypto_backend_openssl.cpp -lcrypto -o sahc_smoke
 */

#include "crypto_backend.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, name) do {                                  \
    if (cond) printf("  PASS  %s\n", name);                     \
    else { printf("  FAIL  %s\n", name); fails++; }             \
} while (0)

int main(void) {
    printf("== sahc crypto backend smoke ==\n");

    /* --- Random --- */
    uint8_t r1[32] = {0}, r2[32] = {0};
    sahc_random_bytes(r1, 32);
    sahc_random_bytes(r2, 32);
    CHECK(memcmp(r1, r2, 32) != 0, "random produces distinct draws");

    /* --- ECDH between Alice & Bob --- */
    uint8_t a_priv[32], a_pub[64], b_priv[32], b_pub[64];
    CHECK(sahc_ecc_keygen(a_priv, a_pub) == 0, "Alice keygen");
    CHECK(sahc_ecc_keygen(b_priv, b_pub) == 0, "Bob keygen");

    uint8_t s_a[32], s_b[32];
    CHECK(sahc_ecdh_shared(a_priv, b_pub, s_a) == 0, "Alice derives shared");
    CHECK(sahc_ecdh_shared(b_priv, a_pub, s_b) == 0, "Bob derives shared");
    CHECK(memcmp(s_a, s_b, 32) == 0, "ECDH shared secrets agree");

    /* --- ECDSA --- */
    const char* msg = "SAHC-test-message";
    uint8_t sig[64];
    CHECK(sahc_ecdsa_sign(a_priv, (const uint8_t*)msg, strlen(msg), sig) == 0,
          "ECDSA sign");
    CHECK(sahc_ecdsa_verify(a_pub, (const uint8_t*)msg, strlen(msg), sig) == 0,
          "ECDSA verify (good)");
    sig[0] ^= 0x01;
    CHECK(sahc_ecdsa_verify(a_pub, (const uint8_t*)msg, strlen(msg), sig) != 0,
          "ECDSA verify rejects tampered sig");

    /* --- SHA-256 vs "abc" → ba7816bf8f01cfea... --- */
    uint8_t h[32];
    sahc_sha256((const uint8_t*)"abc", 3, h);
    static const uint8_t exp_sha[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };
    CHECK(memcmp(h, exp_sha, 32) == 0, "SHA-256(\"abc\") matches RFC vector");

    /* --- HMAC-SHA256 RFC 4231 test 1: key=0x0b*20, msg="Hi There" --- */
    uint8_t hkey[20]; memset(hkey, 0x0b, 20);
    uint8_t hmac[32];
    sahc_hmac_sha256(hkey, 20, (const uint8_t*)"Hi There", 8, hmac);
    static const uint8_t exp_hmac[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
        0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
        0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7,
    };
    CHECK(memcmp(hmac, exp_hmac, 32) == 0, "HMAC-SHA256 matches RFC 4231 #1");

    /* --- AES-128-GCM round-trip --- */
    uint8_t gkey[16], iv[12];
    sahc_random_bytes(gkey, 16);
    sahc_random_bytes(iv,   12);
    const char* aad = "header-bytes";
    const char* pt  = "the quick brown fox jumps over the lazy dog";
    size_t pt_len = strlen(pt);
    uint8_t ct[64], tag[16], pt2[64];
    CHECK(sahc_aes128gcm_encrypt(gkey, iv,
                                 (const uint8_t*)aad, strlen(aad),
                                 (const uint8_t*)pt, pt_len, ct, tag) == 0,
          "GCM encrypt");
    CHECK(sahc_aes128gcm_decrypt(gkey, iv,
                                 (const uint8_t*)aad, strlen(aad),
                                 ct, pt_len, tag, pt2) == 0
          && memcmp(pt, pt2, pt_len) == 0,
          "GCM decrypt round-trip");
    tag[0] ^= 0x01;
    CHECK(sahc_aes128gcm_decrypt(gkey, iv,
                                 (const uint8_t*)aad, strlen(aad),
                                 ct, pt_len, tag, pt2) != 0,
          "GCM rejects tampered tag");

    printf("== %s (%d fail%s) ==\n",
           fails == 0 ? "OK" : "FAILED",
           fails, fails == 1 ? "" : "s");
    return fails == 0 ? 0 : 1;
}
