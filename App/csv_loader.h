#ifndef _CSV_LOADER_H_
#define _CSV_LOADER_H_

#include "types.h"
#include "hospital_state.h"

int load_csv(const char* path, PatientRecord* records, size_t max_records);
void do_load_csv(HospitalState* h);

#endif
