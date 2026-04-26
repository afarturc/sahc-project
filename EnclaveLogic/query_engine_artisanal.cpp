/* Hand-rolled aggregator. Linked into sgx_server because DuckDB
 * doesn't survive inside an SGX-SDK enclave (mmap, file I/O, libstdc++
 * ABI mismatch). The Gramine variant uses query_engine_duckdb.cpp. */

#include "query_engine.h"

extern "C" int query_engine_run(const PatientRecord* records, size_t count,
                                uint32_t field, uint32_t query_type, int32_t filter,
                                float* result_out, uint32_t* matched_out)
{
    if (field > FIELD_BLOOD_SUGAR || query_type > QUERY_COUNT) return -1;

    float    sum = 0.0f, mn = 1e30f, mx = -1e30f;
    uint32_t matched = 0;

    for (size_t i = 0; i < count; i++) {
        if (filter >= 0 && records[i].diagnosis != (uint32_t)filter) continue;
        float v = 0.0f;
        switch (field) {
            case FIELD_AGE:         v = (float)records[i].age;     break;
            case FIELD_TEMPERATURE: v = records[i].temperature;    break;
            case FIELD_BLOOD_SUGAR: v = records[i].blood_sugar;    break;
        }
        sum += v;
        if (v < mn) mn = v;
        if (v > mx) mx = v;
        matched++;
    }

    float result = 0.0f;
    if (matched > 0) {
        switch (query_type) {
            case QUERY_AVG:   result = sum / (float)matched; break;
            case QUERY_MIN:   result = mn;                   break;
            case QUERY_MAX:   result = mx;                   break;
            case QUERY_COUNT: result = (float)matched;       break;
        }
    }

    *result_out  = result;
    *matched_out = matched;
    return 0;
}
