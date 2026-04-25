#ifndef _SAHC_CLIENT_SESSION_H_
#define _SAHC_CLIENT_SESSION_H_

#include <stdint.h>

/* Opaque-ish handle to a live SGX session: the post-handshake key
 * material, AEAD counters, and the underlying socket. Bench harness and
 * client REPL share this surface so the security-critical handshake
 * code lives in a single place (session.cpp). */
typedef struct {
    int      fd;
    uint8_t  session_key[16];
    uint8_t  iv_prefix[4];
    uint8_t  role;
    uint64_t seq_send;
    uint64_t seq_recv;
} ClientSession;

#ifdef __cplusplus
extern "C" {
#endif

/* Connects, runs the full handshake (ATTEST_REQ → ATTEST_RESP → KEY_CONFIRM
 * → KEY_ACK), and returns a READY session.
 *   verbose=0  → silent on success
 *   verbose=1  → prints the same trace as the original sgx_client.
 * On failure: returns -1, and out is NOT populated (caller must NOT call
 * client_session_close). */
int client_session_open(const char* host, int port, const char* party_id,
                        ClientSession* out, int verbose);

/* SESSION_CLOSE (best-effort) + close(fd) + zero key material. Idempotent. */
void client_session_close(ClientSession* s);

/* Upload all records in csv_path. Returns 0 on completed (including
 * soft-reject like role-not-authorized), -1 on torn channel. out_accepted
 * may be NULL. */
int client_session_upload_csv(ClientSession* s, const char* csv_path,
                              uint32_t* out_accepted, int verbose);

/* Aggregate query. field is a FIELD_x enum, op is a QUERY_x enum, diag
 * is a DIAG_x code or -1 for "any". Returns 0 on completed (including
 * soft-reject like below-k-anon), -1 on torn channel. out_result and
 * out_matched may be NULL. */
int client_session_query(ClientSession* s, int field, int op, int diag,
                         float* out_result, uint32_t* out_matched,
                         int verbose);

#ifdef __cplusplus
}
#endif

#endif
