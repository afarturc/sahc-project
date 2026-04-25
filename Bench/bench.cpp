/* Microbench harness for the SAHC client/server/enclave stack.
 *
 * Measures three things over an already-running sgx_server:
 *   1. handshake latency (open + close, end-to-end)
 *   2. upload throughput vs. batch size
 *   3. aggregate-query latency
 *
 * Output is markdown to stdout — paste straight into the report.
 *
 * Reproducibility note: the server's in-enclave store accumulates
 * records across runs (and survives restarts via sealing). For
 * comparable numbers between runs, wipe data/sealed/state.bin and
 * restart the server before each invocation. */

#include "patient.h"
#include "protocol.h"
#include "session.h"

#include <algorithm>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>

#define HOSPITAL_PARTY   "hosp-santa-maria"
#define RESEARCHER_PARTY "fcup-research"

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static double pct(std::vector<double>& v, double p)
{
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)((double)v.size() * p);
    if (idx >= v.size()) idx = v.size() - 1;
    return v[idx];
}

static double mean(const std::vector<double>& v)
{
    if (v.empty()) return 0;
    double sum = 0;
    for (double x : v) sum += x;
    return sum / (double)v.size();
}

static void gen_records(PatientRecord* out, int n, uint32_t seed_base)
{
    /* Deterministic synthetic data. Diagnosis distribution skewed so
     * "any" is always above k-anon and a single filter usually clears
     * threshold once n >= ~20. */
    unsigned int st = seed_base;
    for (int i = 0; i < n; i++) {
        out[i].patient_id  = seed_base + (uint32_t)i;
        out[i].age         = 20 + (uint32_t)(rand_r(&st) % 60);
        out[i].temperature = 36.0f + (float)(rand_r(&st) % 30) / 10.0f;
        out[i].blood_sugar = 70.0f + (float)(rand_r(&st) % 80);
        out[i].diagnosis   = (uint32_t)(rand_r(&st) % 4);
    }
}

/* ---------- benchmarks ---------- */

static int bench_handshake(const char* host, int port, int iters)
{
    printf("\n## Handshake latency\n\n");
    printf("End-to-end client_session_open + client_session_close, %d iterations.\n\n", iters);

    std::vector<double> samples;
    samples.reserve((size_t)iters);
    int errs = 0;

    for (int i = 0; i < iters; i++) {
        ClientSession s;
        double t0 = now_ms();
        int rc = client_session_open(host, port, HOSPITAL_PARTY, &s, 0);
        if (rc != 0) { errs++; continue; }
        client_session_close(&s);
        double dt = now_ms() - t0;
        samples.push_back(dt);
    }
    if (samples.empty()) {
        fprintf(stderr, "handshake bench: all %d attempts failed\n", iters);
        return -1;
    }

    printf("| metric | ms |\n|---|---|\n");
    printf("| mean | %.2f |\n", mean(samples));
    printf("| p50  | %.2f |\n", pct(samples, 0.50));
    printf("| p95  | %.2f |\n", pct(samples, 0.95));
    printf("| p99  | %.2f |\n", pct(samples, 0.99));
    printf("| min  | %.2f |\n", pct(samples, 0.0));
    printf("| max  | %.2f |\n", pct(samples, 1.0));
    if (errs) printf("\n*Errors: %d / %d*\n", errs, iters);
    return 0;
}

static int bench_upload(const char* host, int port,
                        const int* batch_sizes, int n_batches,
                        int ops_per_batch)
{
    printf("\n## Upload throughput vs batch size\n\n");
    printf("One open session, %d uploads per batch size. Latency is per upload, "
           "throughput is records/s based on mean latency.\n\n", ops_per_batch);

    ClientSession s;
    if (client_session_open(host, port, HOSPITAL_PARTY, &s, 0) != 0) {
        fprintf(stderr, "upload bench: handshake failed\n");
        return -1;
    }

    printf("| batch | mean ms | p95 ms | records/s | KB/s |\n");
    printf("|---|---|---|---|---|\n");

    uint32_t seed = 100000;
    int total_uploaded = 0;

    for (int b = 0; b < n_batches; b++) {
        int sz = batch_sizes[b];
        std::vector<double> samples;
        samples.reserve((size_t)ops_per_batch);

        std::vector<PatientRecord> recs((size_t)sz);
        int aborted = 0;
        for (int i = 0; i < ops_per_batch; i++) {
            gen_records(recs.data(), sz, seed);
            seed += (uint32_t)sz;
            uint32_t accepted = 0;
            double t0 = now_ms();
            int rc = client_session_upload_records(&s, recs.data(), sz,
                                                   &accepted, 0);
            double dt = now_ms() - t0;
            if (rc < 0) { aborted = 1; break; }
            if (accepted == 0) { aborted = 1; break; }  /* store full */
            samples.push_back(dt);
            total_uploaded += (int)accepted;
        }

        if (samples.empty()) {
            printf("| %d | — | — | — | — |\n", sz);
            if (aborted) {
                fprintf(stderr,
                    "upload bench: aborted at batch=%d (store likely full at %d records)\n",
                    sz, total_uploaded);
                break;
            }
            continue;
        }

        double m  = mean(samples);
        double recs_per_s = (double)sz / (m / 1000.0);
        double bytes_per_s = recs_per_s * sizeof(PatientRecord);
        printf("| %d | %.2f | %.2f | %.0f | %.1f |\n",
               sz, m, pct(samples, 0.95), recs_per_s, bytes_per_s / 1024.0);
        if (aborted) break;
    }

    client_session_close(&s);
    fprintf(stderr, "(uploaded %d records during throughput bench)\n", total_uploaded);
    return 0;
}

static int bench_query(const char* host, int port, int iters)
{
    printf("\n## Query latency\n\n");
    printf("Five aggregate queries, %d iterations each. Per-query latency, "
           "researcher role.\n\n", iters);

    struct QSpec { const char* label; int field; int op; int diag; };
    QSpec specs[] = {
        { "AVG age (any)",                FIELD_AGE,         QUERY_AVG, -1 },
        { "MIN temp (any)",               FIELD_TEMPERATURE, QUERY_MIN, -1 },
        { "MAX blood_sugar (diabetes)",   FIELD_BLOOD_SUGAR, QUERY_MAX, DIAG_DIABETES },
        { "COUNT age (hypertension)",     FIELD_AGE,         QUERY_COUNT, DIAG_HYPERTENSION },
        { "AVG blood_sugar (any)",        FIELD_BLOOD_SUGAR, QUERY_AVG, -1 },
    };
    int n_specs = (int)(sizeof(specs) / sizeof(specs[0]));

    ClientSession s;
    if (client_session_open(host, port, RESEARCHER_PARTY, &s, 0) != 0) {
        fprintf(stderr, "query bench: handshake failed\n");
        return -1;
    }

    printf("| query | mean ms | p50 ms | p95 ms | matched |\n");
    printf("|---|---|---|---|---|\n");

    for (int q = 0; q < n_specs; q++) {
        std::vector<double> samples;
        samples.reserve((size_t)iters);
        uint32_t last_matched = 0;
        int rejected = 0;

        for (int i = 0; i < iters; i++) {
            float r = 0;
            uint32_t matched = 0;
            double t0 = now_ms();
            int rc = client_session_query(&s, specs[q].field, specs[q].op,
                                          specs[q].diag, &r, &matched, 0);
            double dt = now_ms() - t0;
            if (rc < 0) { rejected++; break; }
            if (matched == 0) { rejected++; continue; }  /* below k-anon */
            samples.push_back(dt);
            last_matched = matched;
        }

        if (samples.empty()) {
            printf("| %s | — | — | — | (no data / k-anon) |\n", specs[q].label);
            continue;
        }
        printf("| %s | %.2f | %.2f | %.2f | %u |\n",
               specs[q].label, mean(samples),
               pct(samples, 0.50), pct(samples, 0.95), last_matched);
    }

    client_session_close(&s);
    return 0;
}

int main(int argc, char** argv)
{
    const char* host = SAHC_DEFAULT_HOST;
    int         port = SAHC_DEFAULT_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    printf("# SAHC bench results\n\n");
    printf("Target: `%s:%d`\n", host, port);

    int rc = 0;
    if (bench_handshake(host, port, 50) != 0) rc = 1;

    int batch_sizes[] = { 1, 5, 25, 100 };
    if (bench_upload(host, port, batch_sizes,
                     (int)(sizeof(batch_sizes)/sizeof(batch_sizes[0])),
                     5) != 0) rc = 1;

    if (bench_query(host, port, 20) != 0) rc = 1;

    printf("\n");
    return rc;
}
