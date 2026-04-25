#ifndef _SAHC_CLIENT_SECURE_FRAME_H_
#define _SAHC_CLIENT_SECURE_FRAME_H_

#include <stddef.h>
#include <stdint.h>

/* Wraps Common/framing.{h,cpp} with AES-128-GCM. The frame envelope is
 * the post-KEX layout from Common/secure_frame.h:
 *   payload = seq(8 BE) | iv(12) | ciphertext(N) | tag(16)
 *
 * Both sides keep mutable seq_send / seq_recv counters; this module
 * advances them after a successful send/recv. seq starts at 0 and is
 * incremented before use, so the first frame in either direction has
 * seq=1. */

/* Returns 0 on success. */
int sf_send(int fd, uint8_t type, uint64_t* seq_send,
            const uint8_t key[16], const uint8_t iv_prefix[4],
            const uint8_t* pt, uint32_t pt_len);

/* On success, sets *type_out and writes plaintext to pt_out (length in
 * *pt_len_out), advancing *seq_recv. If the server replied with MSG_ERROR
 * the raw 2-byte error code is passed through to pt_out (no decryption);
 * caller must check type_out before treating pt_out as plaintext. */
int sf_recv(int fd, uint64_t* seq_recv,
            const uint8_t key[16], const uint8_t iv_prefix[4],
            uint8_t* type_out,
            uint8_t* pt_out, uint32_t pt_cap, uint32_t* pt_len_out);

#endif
