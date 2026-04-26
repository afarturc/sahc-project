#ifndef SAHC_QUERY_ENGINE_H
#define SAHC_QUERY_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "patient.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Aggregate over `records` with optional diagnosis filter (filter < 0
 * disables filtering). Two implementations live in the tree: artisanal
 * (linked into sgx_server) and DuckDB (linked into gramine_server).
 * Both honour the same contract — out-of-range field/query_type
 * returns -1, success returns 0. K-anonymity gating stays in the
 * caller. */
int query_engine_run(const PatientRecord* records, size_t count,
                     uint32_t field, uint32_t query_type, int32_t filter,
                     float* result_out, uint32_t* matched_out);

#ifdef __cplusplus
}
#endif

#endif
