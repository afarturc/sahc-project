/* SGX-SDK sealing backend.
 *
 * sgx_seal_data_ex with SGX_KEYPOLICY_MRENCLAVE — same parameters as the
 * pre-refactor inline version in Enclave.cpp, so blobs sealed by the
 * old enclave remain unsealable by the new one. attribute_mask /
 * misc_mask values match what sgx_seal_data uses internally.
 */

#include "seal_backend.h"
#include "sgx_tseal.h"
#include "sgx_attributes.h"
#include <stdlib.h>
#include <string.h>

static const sgx_attributes_t SEAL_ATTR_MASK = { 0xFF0000000000000BULL, 0x0 };
#define SEAL_MISC_MASK 0xF0000000u

extern "C" {

int sahc_seal(const uint8_t* pt, size_t pt_len,
              uint8_t* blob_out, size_t blob_cap, size_t* blob_len_out) {
    uint32_t need = sgx_calc_sealed_data_size(0, (uint32_t)pt_len);
    if (need == UINT32_MAX) return -1;
    if (blob_cap < need) return -1;

    sgx_status_t s = sgx_seal_data_ex(
        SGX_KEYPOLICY_MRENCLAVE, SEAL_ATTR_MASK, SEAL_MISC_MASK,
        0, NULL,
        (uint32_t)pt_len, pt,
        need, (sgx_sealed_data_t*)blob_out);
    if (s != SGX_SUCCESS) return -1;
    *blob_len_out = need;
    return 0;
}

int sahc_unseal(const uint8_t* blob, size_t blob_len,
                uint8_t* pt_out, size_t pt_cap, size_t* pt_len_out) {
    if (blob_len == 0) return -1;
    sgx_sealed_data_t* sealed = (sgx_sealed_data_t*)blob;
    uint32_t pt_size = sgx_get_encrypt_txt_len(sealed);
    if (pt_size == UINT32_MAX || pt_size > pt_cap) return -1;
    if (sgx_get_add_mac_txt_len(sealed) != 0) return -1;

    uint32_t out = pt_size;
    sgx_status_t s = sgx_unseal_data(sealed, NULL, NULL, pt_out, &out);
    if (s != SGX_SUCCESS || out != pt_size) return -1;
    *pt_len_out = pt_size;
    return 0;
}

} /* extern "C" */
