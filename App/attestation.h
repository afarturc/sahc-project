#ifndef _ATTESTATION_H_
#define _ATTESTATION_H_

#include "sgx_urts.h"
#include "hospital_state.h"

void do_attestation(sgx_enclave_id_t eid, HospitalState* h, uint32_t id);

#endif
