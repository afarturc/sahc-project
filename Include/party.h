#ifndef _SAHC_PARTY_H_
#define _SAHC_PARTY_H_

#include <stdint.h>

// Party roles
#define ROLE_HOSPITAL   1
#define ROLE_RESEARCHER 2

// Max printable length of a party id (excluding null terminator).
#define PARTY_ID_MAX 63

// ECDSA P-256 public key: uncompressed X||Y, 64 bytes.
#define PARTY_PUBKEY_SIZE 64

// ECDSA P-256 signature: r||s, 64 bytes.
#define PARTY_SIG_SIZE 64

#endif
