#ifndef _SAHC_PROTOCOL_H_
#define _SAHC_PROTOCOL_H_

#include <stdint.h>

#define SAHC_PROTO_VERSION 1

// Frame header: type(1) | len(4 BE)
#define FRAME_HEADER_SIZE 5

// Max payload accepted off the wire.
#define FRAME_MAX_PAYLOAD (16u * 1024u * 1024u)

// Message types
#define MSG_ATTEST_REQ      0x01
#define MSG_ATTEST_RESP     0x02
#define MSG_KEY_CONFIRM     0x03
#define MSG_KEY_ACK         0x04
#define MSG_UPLOAD          0x05
#define MSG_UPLOAD_ACK      0x06
#define MSG_QUERY_REQ       0x07
#define MSG_QUERY_RESP      0x08
#define MSG_HELLO           0x10
#define MSG_HELLO_ACK       0x11
#define MSG_SESSION_CLOSE   0xFE
#define MSG_ERROR           0xFF

// Error codes (wire)
#define E_OK                   0
#define E_INVALID_STATE        1
#define E_DECRYPT_FAIL         2
#define E_REPLAY               3
#define E_UNAUTHORIZED         4
#define E_UNKNOWN_PARTY        5
#define E_REVOKED              6
#define E_BAD_SIGNATURE        7
#define E_INSUFFICIENT_RECORDS 8
#define E_BAD_NONCE            9
#define E_INTERNAL             10

// Default network endpoint for local runs
#define SAHC_DEFAULT_HOST "127.0.0.1"
#define SAHC_DEFAULT_PORT 7878

// ATTEST_REQ payload:
//   party_id_len(1) | party_id(party_id_len) | nonce(16)
//   | client_ecdh_pub(64) | signature(64)
#define PROTO_NONCE_SIZE   16
#define PROTO_ECDH_PUB_SIZE 64
#define PROTO_SIG_SIZE     64

// ATTEST_RESP payload: serialized DCAPQuote followed by enclave_ecdh_pub(64).
//
// Serialized DCAPQuote layout (little-endian, native):
//   mrenclave(32) | mrsigner(32) | isv_prod_id(2) | isv_svn(2)
//   | user_data(32) | signature(64) | qe_identity(32)
#define PROTO_QUOTE_MRENCLAVE_SIZE 32
#define PROTO_QUOTE_MRSIGNER_SIZE  32
#define PROTO_QUOTE_USER_DATA_SIZE 32
#define PROTO_QUOTE_SIG_SIZE       64
#define PROTO_QUOTE_QE_ID_SIZE     32
#define PROTO_QUOTE_SIZE           (32 + 32 + 2 + 2 + 32 + 64 + 32)

#define PROTO_ATTEST_RESP_SIZE     (PROTO_QUOTE_SIZE + PROTO_ECDH_PUB_SIZE)

#endif
