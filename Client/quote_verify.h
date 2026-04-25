#ifndef _SAHC_QUOTE_VERIFY_H_
#define _SAHC_QUOTE_VERIFY_H_

/* Quote verification pipeline. Structured to mirror the steps a real
 * Intel DCAP verifier takes, so the migration to hardware is a matter
 * of replacing the SIM-only stages with the real Intel calls. See
 * quote_verify.cpp for the per-stage TODO HW: markers. */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t* quote;               /* ATTEST_RESP payload bytes */
    size_t         quote_len;
    const uint8_t* nonce;               /* 16 B nonce sent in ATTEST_REQ */
    const uint8_t* expected_mrenclave;  /* 32 B from Include/expected_mrenclave.h */
    int            require_dcap;        /* 0 = accept SIM-only checks
                                         * 1 = require full DCAP chain (HW) */
} QuoteVerifyCtx;

typedef struct {
    uint8_t mrenclave[32];
    uint8_t mrsigner[32];
    uint16_t isv_prod_id;
    uint16_t isv_svn;
    uint8_t enclave_ecdh_pub[64];       /* extracted from end of payload */
} QuoteVerifyOut;

/* 0 = OK; -1 = any verification step failed (logs to stderr).
 * On success *out is populated and caller proceeds to ECDH. */
int quote_verify(const QuoteVerifyCtx* ctx, QuoteVerifyOut* out);

/* Resolve the require_dcap policy from compile flags + env var.
 * Compile-time default: 1 if SAHC_HW is defined, 0 otherwise.
 * Runtime override: env SAHC_REQUIRE_DCAP=0|1 wins if set. */
int sahc_require_dcap(void);

#ifdef __cplusplus
}
#endif

#endif
