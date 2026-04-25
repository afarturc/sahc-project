#ifndef _SAHC_CLIENT_CSV_LOADER_H_
#define _SAHC_CLIENT_CSV_LOADER_H_

#include "patient.h"
#include <stddef.h>

/* Parses a CSV with header
 *   patient_id,age,temperature,blood_sugar,diagnosis
 * into out[0..max_records). Returns the number of records parsed, or -1
 * on error. Lines that fail to parse are skipped with a warning. */
int csv_load(const char* path, PatientRecord* out, size_t max_records);

#endif
