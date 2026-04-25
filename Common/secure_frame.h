#ifndef _SAHC_SECURE_FRAME_H_
#define _SAHC_SECURE_FRAME_H_

#include <stddef.h>
#include <stdint.h>

/* Post-KEX frame envelope (sits inside frame_send/frame_recv payload):
 *
 *   seq(8 BE) | iv(12) | ciphertext(N) | tag(16)
 *
 * IV  = iv_prefix(4) || seq(8 BE)              -> 12 bytes
 * AAD = type(1)      || seq(8 BE)              ->  9 bytes
 *
 * AAD covers type (prevents cross-type confusion) and seq (prevents
 * replay). The IV is unique per send because seq strictly increases
 * within a session, so AES-GCM nonce-reuse is structurally impossible
 * provided seq never wraps (uint64 -> never in practice). */

#define SF_SEQ_SIZE        8
#define SF_IV_SIZE        12
#define SF_TAG_SIZE       16
#define SF_IV_PREFIX_SIZE  4
#define SF_AAD_SIZE        9

#define SF_PAYLOAD_OVERHEAD (SF_SEQ_SIZE + SF_IV_SIZE + SF_TAG_SIZE)  /* 36 */

/* Build the IV from iv_prefix and seq. */
static inline void sf_build_iv(const uint8_t iv_prefix[SF_IV_PREFIX_SIZE],
                               uint64_t seq,
                               uint8_t out_iv[SF_IV_SIZE])
{
    for (int i = 0; i < SF_IV_PREFIX_SIZE; i++) out_iv[i] = iv_prefix[i];
    for (int i = 0; i < 8; i++) {
        out_iv[SF_IV_PREFIX_SIZE + i] = (uint8_t)(seq >> (8 * (7 - i)));
    }
}

/* Build the AAD (type || seq_BE). */
static inline void sf_build_aad(uint8_t type, uint64_t seq,
                                uint8_t out_aad[SF_AAD_SIZE])
{
    out_aad[0] = type;
    for (int i = 0; i < 8; i++) {
        out_aad[1 + i] = (uint8_t)(seq >> (8 * (7 - i)));
    }
}

#endif
