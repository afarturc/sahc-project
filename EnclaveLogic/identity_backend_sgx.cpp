/* SGX-SDK self-measurement: targets ourselves with sgx_create_report. */

#include "identity_backend.h"
#include "sgx_utils.h"
#include <string.h>

extern "C" {

int sahc_self_measurement(uint8_t mrenclave_out[32],
                          uint8_t mrsigner_out[32]) {
    sgx_target_info_t ti;
    memset(&ti, 0, sizeof(ti));
    if (sgx_self_target(&ti) != SGX_SUCCESS) return -1;

    sgx_report_data_t rd;
    memset(&rd, 0, sizeof(rd));
    sgx_report_t report;
    if (sgx_create_report(&ti, &rd, &report) != SGX_SUCCESS) return -1;

    memcpy(mrenclave_out, &report.body.mr_enclave, 32);
    memcpy(mrsigner_out,  &report.body.mr_signer,  32);
    return 0;
}

} /* extern "C" */
