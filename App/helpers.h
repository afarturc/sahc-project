#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "types.h"
#include "hospital_state.h"

const char* diag_name(uint32_t d);
const char* field_name(uint32_t f);
const char* query_name(uint32_t q);
void print_records(PatientRecord* data, size_t count);
void print_status(HospitalState* hospitals, int num);

#endif
