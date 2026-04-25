#ifndef _SAHC_PARTIES_LOADER_H_
#define _SAHC_PARTIES_LOADER_H_

#include "sgx_urts.h"
#include <stdint.h>

// Loads authorized_parties.json and pushes its contents into the enclave
// via ecall_parties_begin / _add_hospital / _add_researcher / _end.
//
// Returns 0 on success. On success, the *_out counts reflect what the
// enclave accepted (researchers failing quorum land in out_rejected).
// Returns -1 if the file is absent, -2 on parse/schema error, -3 on
// ECALL failure.
int parties_load_into_enclave(sgx_enclave_id_t eid,
                              const char* json_path,
                              uint32_t* out_hospitals,
                              uint32_t* out_researchers,
                              uint32_t* out_rejected);

#endif
