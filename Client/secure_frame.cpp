#include "secure_frame.h"

#include "framing.h"
#include "identity.h"
#include "protocol.h"
#include "../Common/secure_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t read_u64_be(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

static void write_u64_be(uint8_t* p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

int sf_send(int fd, uint8_t type, uint64_t* seq_send,
            const uint8_t key[16], const uint8_t iv_prefix[4],
            const uint8_t* pt, uint32_t pt_len)
{
    uint64_t seq = (*seq_send) + 1;

    uint32_t env_len = SF_PAYLOAD_OVERHEAD + pt_len;
    uint8_t* env = (uint8_t*)malloc(env_len);
    if (!env) return -1;

    write_u64_be(env, seq);

    uint8_t iv[SF_IV_SIZE];
    sf_build_iv(iv_prefix, seq, iv);
    memcpy(env + SF_SEQ_SIZE, iv, SF_IV_SIZE);

    uint8_t aad[SF_AAD_SIZE];
    sf_build_aad(type, seq, aad);

    uint8_t* ct = env + SF_SEQ_SIZE + SF_IV_SIZE;
    uint8_t* tag = ct + pt_len;
    if (crypto_aes128gcm_encrypt(key, iv, aad, SF_AAD_SIZE,
                                 pt, pt_len, ct, tag) != 0) {
        free(env);
        return -1;
    }

    int r = frame_send(fd, type, env, env_len);
    free(env);
    if (r != 0) return r;

    *seq_send = seq;
    return 0;
}

int sf_recv(int fd, uint64_t* seq_recv,
            const uint8_t key[16], const uint8_t iv_prefix[4],
            uint8_t* type_out,
            uint8_t* pt_out, uint32_t pt_cap, uint32_t* pt_len_out)
{
    uint32_t env_cap = pt_cap + SF_PAYLOAD_OVERHEAD;
    uint8_t* env = (uint8_t*)malloc(env_cap);
    if (!env) return -1;

    uint32_t env_len = 0;
    int r = frame_recv(fd, type_out, env, env_cap, &env_len);
    if (r != 0) { free(env); return r; }

    /* MSG_ERROR is plaintext: pass the 2-byte code through. */
    if (*type_out == MSG_ERROR) {
        if (env_len > pt_cap) { free(env); return -1; }
        memcpy(pt_out, env, env_len);
        *pt_len_out = env_len;
        free(env);
        return 0;
    }

    if (env_len < SF_PAYLOAD_OVERHEAD) {
        fprintf(stderr, "sf_recv: undersized envelope (%u)\n", env_len);
        free(env); return -1;
    }

    uint64_t seq = read_u64_be(env);
    if (seq <= *seq_recv) {
        fprintf(stderr, "sf_recv: replay (seq=%llu last=%llu)\n",
                (unsigned long long)seq, (unsigned long long)*seq_recv);
        free(env); return -1;
    }

    uint8_t expected_iv[SF_IV_SIZE];
    sf_build_iv(iv_prefix, seq, expected_iv);
    if (memcmp(env + SF_SEQ_SIZE, expected_iv, SF_IV_SIZE) != 0) {
        fprintf(stderr, "sf_recv: IV mismatch\n");
        free(env); return -1;
    }

    uint32_t ct_len = env_len - SF_PAYLOAD_OVERHEAD;
    if (ct_len > pt_cap) { free(env); return -1; }

    const uint8_t* ct  = env + SF_SEQ_SIZE + SF_IV_SIZE;
    const uint8_t* tag = ct + ct_len;

    uint8_t aad[SF_AAD_SIZE];
    sf_build_aad(*type_out, seq, aad);

    if (crypto_aes128gcm_decrypt(key, expected_iv, aad, SF_AAD_SIZE,
                                 ct, ct_len, tag, pt_out) != 0) {
        fprintf(stderr, "sf_recv: AEAD decrypt failed (auth?)\n");
        free(env); return -1;
    }

    *seq_recv = seq;
    *pt_len_out = ct_len;
    free(env);
    return 0;
}
