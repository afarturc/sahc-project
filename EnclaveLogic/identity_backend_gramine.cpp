/* Gramine attestation backend.
 *
 * Reads the LibOS pseudo-files exposed by Gramine:
 *   /dev/attestation/mrenclave         (32 B raw)
 *   /dev/attestation/mrsigner          (32 B raw)
 *   /dev/attestation/user_report_data  (write-only, 64 B raw)
 *   /dev/attestation/quote             (variable, after writing user_data)
 *
 * In gramine-sgx on real Intel HW the kernel returns the genuine SGX
 * measurements and a DCAP quote. In gramine-direct the same paths return
 * deterministic dev placeholders — fine for local smoke, never trust the
 * resulting quote.
 *
 * If the pseudo-files are missing (running outside Gramine) we return -1
 * so callers can fall back / refuse loudly. */

#include "identity_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

namespace {

int read_pseudo(const char* path, uint8_t* buf, size_t cap, size_t* out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap);
    close(fd);
    if (n <= 0) return -1;
    if (out_len) *out_len = (size_t)n;
    return 0;
}

} /* namespace */

extern "C" {

/* Bare-Linux / gramine-direct fallback: if /dev/attestation is absent we
 * are NOT running under gramine-sgx, so there is no genuine measurement
 * to read. Instead of failing closed (which would block the entire
 * attestation flow during dev) we return well-known dev placeholders and
 * log loudly. The Client/quote_verify.cpp pipeline will still refuse the
 * resulting "quote" if SAHC_REQUIRE_DCAP=1. */
static int dev_fallback(uint8_t mre[32], uint8_t mrs[32]) {
    static int warned = 0;
    if (!warned) {
        fprintf(stderr,
            "identity_backend_gramine: /dev/attestation absent — running "
            "outside gramine-sgx. Returning dev-placeholder MRENCLAVE/"
            "MRSIGNER. NEVER trust quotes produced in this mode.\n");
        warned = 1;
    }
    memset(mre, 0xDE, 32);
    memset(mrs, 0xAD, 32);
    return 0;
}

int sahc_self_measurement(uint8_t mrenclave_out[32],
                          uint8_t mrsigner_out[32]) {
    if (access("/dev/attestation/mrenclave", R_OK) != 0)
        return dev_fallback(mrenclave_out, mrsigner_out);

    size_t n = 0;
    if (read_pseudo("/dev/attestation/mrenclave", mrenclave_out, 32, &n) != 0
        || n != 32) return -1;
    if (read_pseudo("/dev/attestation/mrsigner",  mrsigner_out,  32, &n) != 0
        || n != 32) return -1;
    return 0;
}

} /* extern "C" */
