/* DCAP-style quote verification pipeline.
 *
 * The wire payload is the artisanal SAHC quote layout (see protocol.h):
 *
 *   mr_enclave(32) | mr_signer(32) | isv_prod_id(2) | isv_svn(2)
 *   | report_data(32) | quote_signature(64) | qe_identity(32)
 *   | enclave_ecdh_pub(64)
 *
 * Total 260 bytes. Each field maps to a real Intel DCAP equivalent:
 *
 *   mr_enclave/mr_signer/isv_*  → sgx_report_body_t fields
 *   report_data                 → sgx_report_body_t.report_data (64 B in real DCAP;
 *                                 we only use 32 B because that's all SHA-256 produces)
 *   quote_signature             → sgx_ql_ecdsa_sig_data_t.sig (signed by AK in real DCAP;
 *                                 here it's the enclave's self-signature with no chain)
 *   qe_identity                 → would be derived from sgx_ql_ecdsa_sig_data_t.qe_report
 *
 * On HW we'd replace the wire payload with sgx_quote3_t verbatim and
 * call sgx_qv_verify_quote() instead of the per-stage helpers below.
 * The structural binding stages (report_data, mr_enclave) stay the
 * same because they're our application-level invariants. */

#include "quote_verify.h"

#include "protocol.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SAHC_HW
#define SAHC_HW 0
#endif

int sahc_require_dcap(void)
{
    const char* env = getenv("SAHC_REQUIRE_DCAP");
    if (env && *env) {
        if (env[0] == '0' && env[1] == 0) return 0;
        if (env[0] == '1' && env[1] == 0) return 1;
        fprintf(stderr,
            "quote_verify: SAHC_REQUIRE_DCAP must be 0 or 1 (got '%s'); "
            "falling back to compile default\n", env);
    }
    return SAHC_HW ? 1 : 0;
}

/* ---------- stage 1: structural parse ---------- */

static int verify_quote_structure(const QuoteVerifyCtx* ctx, QuoteVerifyOut* out,
                                  const uint8_t** report_data_out,
                                  const uint8_t** quote_sig_out,
                                  const uint8_t** qe_identity_out)
{
    if (ctx->quote_len != PROTO_ATTEST_RESP_SIZE) {
        fprintf(stderr, "quote_verify: bad payload length %zu (expected %u)\n",
                ctx->quote_len, PROTO_ATTEST_RESP_SIZE);
        return -1;
    }
    const uint8_t* p = ctx->quote;
    memcpy(out->mrenclave, p,      32); p += 32;
    memcpy(out->mrsigner,  p,      32); p += 32;
    out->isv_prod_id = (uint16_t)p[0] | ((uint16_t)p[1] << 8); p += 2;
    out->isv_svn     = (uint16_t)p[0] | ((uint16_t)p[1] << 8); p += 2;
    *report_data_out = p; p += PROTO_QUOTE_USER_DATA_SIZE;
    *quote_sig_out   = p; p += PROTO_QUOTE_SIG_SIZE;
    *qe_identity_out = p; p += PROTO_QUOTE_QE_ID_SIZE;
    memcpy(out->enclave_ecdh_pub, p, PROTO_ECDH_PUB_SIZE);
    return 0;
}

/* ---------- stage 2: DCAP signature chain (HW only) ----------
 *
 * In real DCAP the verifier walks:
 *
 *   (1) sgx_qv_get_quote_supplemental_data_size() to size buffers
 *   (2) sgx_qv_verify_quote() which internally:
 *       - parses sgx_quote3_t
 *       - verifies the AK signature over header + report_body
 *       - verifies the QE report (qe_report) signature against the PCK
 *       - walks PCK certificate chain up to the Intel SGX root
 *       - cross-checks against the QE identity from the QE Identity Issuer
 *       - cross-checks the TCB level against the Intel TCB Issuer
 *   (3) returns sgx_ql_qv_result_t — accept OK/SW_HARDENING_NEEDED, reject
 *       OUT_OF_DATE, REVOKED, INVALID_SIGNATURE, etc.
 *
 * The colleague on Intel HW must replace the body of this function with
 * the call sequence above. Header to include: sgx_dcap_quoteverify.h.
 * Library to link: -lsgx_dcap_quoteverify (and optionally Intel PCCS/QPL).
 *
 * In SIM there is no AK, no PCK chain, and the quote_sig is signed by
 * the enclave's own ECDSA key (regenerated each restart, not pinned).
 * We can't validate it meaningfully, so we just refuse loudly when DCAP
 * is required. */
static int verify_qe_signature_chain(const QuoteVerifyCtx* ctx,
                                     const uint8_t* quote_sig,
                                     const uint8_t* qe_identity)
{
    (void)quote_sig; (void)qe_identity;

    if (!ctx->require_dcap) {
        /* SIM mode, flag off — explicit warning so nobody confuses this
         * trace with a real attestation. */
        fprintf(stderr,
            "quote_verify: DCAP signature chain NOT verified "
            "(SAHC_REQUIRE_DCAP=0). Acceptable in SIM only.\n");
        return 0;
    }

    /* TODO HW: implement here.
     *
     *   sgx_ql_qe_report_info_t qe_report;
     *   uint32_t supp_size = 0;
     *   sgx_qv_get_quote_supplemental_data_size(&supp_size);
     *   uint8_t* supp = (uint8_t*)malloc(supp_size);
     *   time_t now = time(NULL);
     *   sgx_ql_qv_result_t qv_result;
     *   uint32_t collateral_expir = 0;
     *
     *   sgx_status_t s = sgx_qv_verify_quote(
     *       ctx->quote, (uint32_t)ctx->quote_len,
     *       NULL,            // collateral (pulled from QPL/PCCS if NULL)
     *       now,
     *       &collateral_expir,
     *       &qv_result,
     *       &qe_report,
     *       supp_size, supp);
     *
     *   if (s != SGX_SUCCESS) { free(supp); return -1; }
     *   if (qv_result != SGX_QL_QV_RESULT_OK &&
     *       qv_result != SGX_QL_QV_RESULT_CONFIG_NEEDED &&
     *       qv_result != SGX_QL_QV_RESULT_SW_HARDENING_NEEDED) {
     *       free(supp); return -1;
     *   }
     *   free(supp);
     *   return 0;
     */
    fprintf(stderr,
        "quote_verify: DCAP chain verification required but this build "
        "doesn't include the DCAP QvL — rebuild with SAHC_HW=1 against "
        "-lsgx_dcap_quoteverify and provide a PCCS endpoint.\n");
    return -1;
}

/* ---------- stage 3: report_data binding ----------
 *
 * Application-level invariant: the enclave promises that report_data
 * == SHA256(nonce || enclave_ecdh_pub). Verifying this rules out
 * replay (the nonce is fresh per session) AND substitution of the
 * enclave's ECDH pubkey by a MITM. In real DCAP this exact check
 * still runs after sgx_qv_verify_quote — it's not something DCAP
 * gives us automatically. */
static int verify_report_binding(const QuoteVerifyCtx* ctx,
                                 const uint8_t* report_data,
                                 const uint8_t enclave_ecdh_pub[64])
{
    uint8_t to_hash[16 + 64];
    memcpy(to_hash,      ctx->nonce,       16);
    memcpy(to_hash + 16, enclave_ecdh_pub, 64);

    uint8_t expected[32];
    SHA256(to_hash, sizeof(to_hash), expected);

    if (memcmp(report_data, expected, 32) != 0) {
        fprintf(stderr,
            "quote_verify: report_data binding mismatch "
            "(replay or enclave_pub tampered)\n");
        return -1;
    }
    return 0;
}

/* ---------- stage 4: enclave identity pin ----------
 *
 * Independent from DCAP — even with a perfectly valid quote chain, we
 * still want to refuse anything that isn't *our* enclave binary. In
 * production, expected_mrenclave usually comes from a build attestation
 * step or an admin allowlist; here it's regenerated by
 * scripts/extract_mrenclave.sh after every enclave rebuild. */
static int verify_enclave_identity(const QuoteVerifyCtx* ctx,
                                   const uint8_t mrenclave[32])
{
    if (memcmp(mrenclave, ctx->expected_mrenclave, 32) != 0) {
        fprintf(stderr,
            "quote_verify: MRENCLAVE mismatch — wrong enclave binary\n");
        return -1;
    }
    return 0;
}

/* ---------- entry point ---------- */

int quote_verify(const QuoteVerifyCtx* ctx, QuoteVerifyOut* out)
{
    const uint8_t* report_data = NULL;
    const uint8_t* quote_sig   = NULL;
    const uint8_t* qe_identity = NULL;

    if (verify_quote_structure(ctx, out,
                               &report_data, &quote_sig, &qe_identity) != 0)
        return -1;

    /* Order matters: signature chain first (cheapest reject for
     * adversarial inputs in HW), then bindings, then identity pin.
     * In SIM the chain step is a no-op so the order is purely
     * cosmetic but kept for symmetry with the HW path. */
    if (verify_qe_signature_chain(ctx, quote_sig, qe_identity) != 0)
        return -1;
    if (verify_report_binding(ctx, report_data, out->enclave_ecdh_pub) != 0)
        return -1;
    if (verify_enclave_identity(ctx, out->mrenclave) != 0)
        return -1;

    return 0;
}
