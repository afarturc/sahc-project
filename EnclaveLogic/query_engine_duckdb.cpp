/* DuckDB-backed aggregator (gramine_server only). Builds a fresh
 * in-memory DB per query, INSERTs the snapshot, and runs a
 * narrowly-shaped SELECT.
 *
 * SQL surface is *not* user-controlled — the caller passes structured
 * (field, query_type, filter) tuples and we synthesise the SQL from a
 * fixed allowlist. So no injection surface, even if some upstream
 * channel ever started forwarding raw text.
 *
 * Per-call DB construction is wasteful (≈1-5 ms setup + ~µs/row
 * INSERT) but keeps the engine stateless. If query latency becomes a
 * concern we can switch to a persistent connection sealed alongside
 * the records array. */

#include "query_engine.h"

#include "duckdb.hpp"

#include <cstdio>
#include <memory>
#include <string>

using duckdb::DuckDB;
using duckdb::Connection;
using duckdb::Appender;
using duckdb::Value;

extern "C" int query_engine_run(const PatientRecord* records, size_t count,
                                uint32_t field, uint32_t query_type, int32_t filter,
                                float* result_out, uint32_t* matched_out)
{
    if (field > FIELD_BLOOD_SUGAR || query_type > QUERY_COUNT) return -1;

    static const char* kField[3] = { "age", "temperature", "blood_sugar" };
    static const char* kAgg[4]   = { "AVG", "MIN", "MAX", "COUNT" };

    try {
        DuckDB db(nullptr);
        Connection con(db);

        auto cr = con.Query(
            "CREATE TABLE r ("
            " patient_id  UINTEGER,"
            " age         UINTEGER,"
            " temperature REAL,"
            " blood_sugar REAL,"
            " diagnosis   UINTEGER)");
        if (cr->HasError()) {
            fprintf(stderr, "query_engine_duckdb: CREATE failed: %s\n",
                    cr->GetError().c_str());
            return -1;
        }

        {
            Appender app(con, "r");
            for (size_t i = 0; i < count; i++) {
                app.AppendRow(
                    (uint32_t)records[i].patient_id,
                    (uint32_t)records[i].age,
                    (float)records[i].temperature,
                    (float)records[i].blood_sugar,
                    (uint32_t)records[i].diagnosis);
            }
            app.Close();
        }

        /* Filter value is a uint32_t we just cast from our own int32_t —
         * no user-supplied text in the SQL, so direct formatting is safe
         * and avoids the PreparedStatement return-type juggling. */
        char filter_buf[32];
        if (filter >= 0) snprintf(filter_buf, sizeof(filter_buf),
                                  " WHERE diagnosis = %u", (uint32_t)filter);
        else             filter_buf[0] = '\0';

        std::string sql;
        sql  = "SELECT ";
        sql += kAgg[query_type];
        sql += "(";
        sql += (query_type == QUERY_COUNT) ? "*" : kField[field];
        sql += "), COUNT(*) FROM r";
        sql += filter_buf;

        auto qr = con.Query(sql);
        if (qr->HasError()) {
            fprintf(stderr, "query_engine_duckdb: SELECT failed: %s\n",
                    qr->GetError().c_str());
            return -1;
        }
        if (qr->RowCount() != 1) {
            fprintf(stderr, "query_engine_duckdb: unexpected row count %llu\n",
                    (unsigned long long)qr->RowCount());
            return -1;
        }

        Value agg     = qr->GetValue(0, 0);
        Value matched = qr->GetValue(1, 0);

        uint32_t m = matched.IsNull() ? 0u : (uint32_t)matched.GetValue<int64_t>();
        float    r = 0.0f;
        if (m > 0 && !agg.IsNull()) {
            switch (query_type) {
                case QUERY_AVG:   r = (float)agg.GetValue<double>();  break;
                case QUERY_MIN:
                case QUERY_MAX:
                    if (field == FIELD_AGE) r = (float)agg.GetValue<uint32_t>();
                    else                    r = (float)agg.GetValue<double>();
                    break;
                case QUERY_COUNT: r = (float)agg.GetValue<int64_t>();  break;
            }
        }

        *result_out  = r;
        *matched_out = m;
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "query_engine_duckdb: exception: %s\n", e.what());
        return -1;
    }
}
