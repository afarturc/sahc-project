#ifndef _UPLOAD_H_
#define _UPLOAD_H_

#include "sgx_urts.h"
#include "hospital_state.h"

void do_upload(sgx_enclave_id_t eid, HospitalState* h, uint32_t id);

#endif
