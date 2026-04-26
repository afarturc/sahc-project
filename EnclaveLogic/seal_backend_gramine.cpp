/* Gramine sealing backend.
 *
 * Derives a 16-byte AES-GCM key from /dev/attestation/keys/_sgx_mrenclave —
 * Gramine's per-MRENCLAVE wrap key. In gramine-sgx HW this is genuinely
 * MRENCLAVE-bound (CPU-derived inside the PSW). In gramine-direct the
 * pseudo-file returns deterministic dev bytes — sealing still works as a
 * persistence mechanism but offers no real confidentiality.
 *
 * Blob layout: magic(4 LE) | version(4 LE) | iv(12) | tag(16) | ciphertext
 */

#include "seal_backend.h"
#include "crypto_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GRAMINE_SEAL_KEY_PATH "/dev/attestation/keys/_sgx_mrenclave"
#define SAHC_SEAL_MAGIC   0x53534148u   /* 'SAHS' */
#define SAHC_SEAL_VERSION 1u

namespace {

int load_seal_key(uint8_t key_out[16]) {
    int fd = open(GRAMINE_SEAL_KEY_PATH, O_RDONLY);
    if (fd < 0) {
        /* Bare-Linux / gramine-direct fallback. Sealing still works as a
         * persistence mechanism, but the key is fixed dev bytes — NEVER
         * use the resulting blob outside dev. */
        static int warned = 0;
        if (!warned) {
            fprintf(stderr,
                "seal_backend_gramine: %s absent — running outside "
                "gramine-sgx. Using DEV-ONLY fixed seal key.\n",
                GRAMINE_SEAL_KEY_PATH);
            warned = 1;
        }
        const char* dev_seed = "SAHC-dev-seal-v1-not-for-production";
        uint8_t h[32];
        if (sahc_sha256((const uint8_t*)dev_seed, strlen(dev_seed), h) != 0)
            return -1;
        memcpy(key_out, h, 16);
        return 0;
    }
    uint8_t raw[128];  /* Gramine returns 16-128 B depending on backend */
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
    if (n < 16) return -1;
    /* Compress to 16 B via SHA-256 truncation so any returned width works. */
    uint8_t h[32];
    if (sahc_sha256(raw, (size_t)n, h) != 0) return -1;
    memcpy(key_out, h, 16);
    return 0;
}

void put_u32_le(uint8_t* p, uint32_t v) {
    p[0]=v&0xFF; p[1]=(v>>8)&0xFF; p[2]=(v>>16)&0xFF; p[3]=(v>>24)&0xFF;
}
uint32_t get_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

} /* namespace */

extern "C" {

int sahc_seal(const uint8_t* pt, size_t pt_len,
              uint8_t* blob_out, size_t blob_cap, size_t* blob_len_out) {
    const size_t hdr = 4 + 4 + 12 + 16;
    if (blob_cap < hdr + pt_len) return -1;

    uint8_t key[16];
    if (load_seal_key(key) != 0) return -1;

    uint8_t iv[12];
    if (sahc_random_bytes(iv, sizeof(iv)) != 0) {
        memset(key, 0, sizeof(key)); return -1;
    }

    put_u32_le(blob_out,     SAHC_SEAL_MAGIC);
    put_u32_le(blob_out + 4, SAHC_SEAL_VERSION);
    memcpy(blob_out + 8, iv, 12);

    uint8_t* tag = blob_out + 20;
    uint8_t* ct  = blob_out + 36;
    int rc = sahc_aes128gcm_encrypt(key, iv, NULL, 0, pt, pt_len, ct, tag);
    memset(key, 0, sizeof(key));
    if (rc != 0) return -1;

    *blob_len_out = hdr + pt_len;
    return 0;
}

int sahc_unseal(const uint8_t* blob, size_t blob_len,
                uint8_t* pt_out, size_t pt_cap, size_t* pt_len_out) {
    const size_t hdr = 4 + 4 + 12 + 16;
    if (blob_len < hdr) return -1;
    if (get_u32_le(blob)     != SAHC_SEAL_MAGIC)   return -1;
    if (get_u32_le(blob + 4) != SAHC_SEAL_VERSION) return -1;

    size_t ct_len = blob_len - hdr;
    if (ct_len > pt_cap) return -1;

    uint8_t key[16];
    if (load_seal_key(key) != 0) return -1;

    int rc = sahc_aes128gcm_decrypt(key, blob + 8, NULL, 0,
                                    blob + 36, ct_len,
                                    blob + 20, pt_out);
    memset(key, 0, sizeof(key));
    if (rc != 0) return -1;
    *pt_len_out = ct_len;
    return 0;
}

} /* extern "C" */
