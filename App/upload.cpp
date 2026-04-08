#include <stdio.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "upload.h"
#include "crypto.h"

void do_upload(sgx_enclave_id_t eid, HospitalState* h, uint32_t id)
{
    if (!h->attested) {
        printf("\n  %s ainda nao fez attestation!\n", h->name);
        return;
    }
    if (h->uploaded) {
        printf("\n  %s ja fez upload.\n", h->name);
        return;
    }
    if (h->count == 0) {
        printf("\n  %s nao tem dados carregados! Carrega o CSV primeiro.\n",
               h->name);
        return;
    }

    unsigned char ciphertext[8192], iv[12], tag[16];
    int ct_len = encrypt_data((unsigned char*)h->records,
                               h->count * sizeof(PatientRecord),
                               h->session_key, ciphertext, iv, tag);

    if (ct_len < 0) {
        printf("  ERRO: falha ao encriptar dados de %s\n", h->name);
        return;
    }

    printf("\n  %s: a enviar %zu registos encriptados (%d bytes)...\n",
           h->name, h->count, ct_len);

    int ret;
    sgx_status_t status = ecall_upload_data(eid, &ret, id,
                                             ciphertext, ct_len, iv, tag);
    if (status != SGX_SUCCESS) {
        printf("  ERRO: ECALL upload_data falhou (sgx_status 0x%x)\n", status);
        return;
    }
    if (ret > 0) {
        h->uploaded = 1;
        printf("  Upload completo: %d registos aceites\n", ret);
    } else {
        printf("  ERRO no upload (code %d)\n", ret);
    }
}
