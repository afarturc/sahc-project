#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>

// Sizes shared by enclave + server for the ATTEST_RESP quote layout.
// Slated to move into protocol.h once ecall_generate_report is rewritten
// in Passo 4b (C2 of Passo 4b).
#define NONCE_SIZE           16
#define USER_DATA_SIZE       32
#define QUOTE_SIGNATURE_SIZE 64

#endif
