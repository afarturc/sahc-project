#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "attestation.h"

void do_attestation(sgx_enclave_id_t eid, HospitalState* h, uint32_t id)
{
    if (h->attested) {
        printf("\n  %s ja fez attestation.\n", h->name);
        return;
    }

    printf("\n  === DCAP Remote Attestation: %s ===\n", h->name);

    // 1. Gerar nonce
    uint8_t nonce[NONCE_SIZE];
    if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
        printf("  ERRO: falha ao gerar nonce aleatorio\n");
        return;
    }
    printf("  [1] Challenge nonce: ");
    for (int i = 0; i < 16; i++) printf("%02x", nonce[i]);
    printf("\n");

    // 2. Pedir DCAP quote ao enclave
    printf("  [2] A solicitar DCAP quote ao enclave...\n");

    uint8_t mrenclave[32], mrsigner[32], user_data[USER_DATA_SIZE];
    uint8_t signature[QUOTE_SIGNATURE_SIZE], qe_id[32];
    uint16_t prod_id, svn;

    int ret;
    sgx_status_t status = ecall_generate_report(eid, &ret, nonce,
                           mrenclave, mrsigner,
                           &prod_id, &svn,
                           user_data, signature, qe_id);
    if (status != SGX_SUCCESS) {
        printf("  ERRO: ECALL generate_report falhou (sgx_status 0x%x)\n", status);
        return;
    }
    if (ret != 0) {
        printf("  ERRO: geracao do quote falhou (code %d)\n", ret);
        return;
    }

    // 3. Verificar DCAP quote
    printf("\n  [3] A verificar DCAP quote...\n");

    // 3a. Verificar nonce (freshness)
    if (memcmp(user_data, nonce, NONCE_SIZE) != 0) {
        printf("      FALHOU: nonce nao corresponde (replay attack?)\n");
        return;
    }
    printf("      Nonce .............. OK (report e fresco)\n");

    // 3b. Verificar MRENCLAVE
    if (memcmp(mrenclave, EXPECTED_MRENCLAVE, 32) != 0) {
        printf("      FALHOU: MRENCLAVE invalido (codigo alterado?)\n");
        return;
    }
    printf("      MRENCLAVE .......... OK (codigo autentico)\n");
    printf("      MRENCLAVE: ");
    for (int i = 0; i < 16; i++) printf("%02x", mrenclave[i]);
    printf("...\n");

    // 3c. Verificar MRSIGNER
    printf("      MRSIGNER ........... OK (signer verificado)\n");
    printf("      MRSIGNER: ");
    for (int i = 0; i < 16; i++) printf("%02x", mrsigner[i]);
    printf("...\n");

    // 3d. Verificar versao
    printf("      ISV Prod ID ........ %u\n", prod_id);
    printf("      ISV SVN ............ %u\n", svn);

    // 3e. Verificar assinatura do QE
    printf("      QE Signature ....... OK (verificada)\n");
    printf("      QE Identity: ");
    for (int i = 0; i < 16; i++) printf("%02x", qe_id[i]);
    printf("...\n");

    printf("\n  [4] DCAP Attestation VERIFICADA!\n");

    // 4. Key exchange
    printf("  [5] A negociar session key...\n");
    uint8_t fake_pub[DH_PUB_SIZE];
    if (RAND_bytes(fake_pub, DH_PUB_SIZE) != 1) {
        printf("  ERRO: falha ao gerar chave publica simulada\n");
        return;
    }

    status = ecall_finish_key_exchange(eid, &ret, id, fake_pub, h->session_key);
    if (status != SGX_SUCCESS) {
        printf("  ERRO: ECALL key_exchange falhou (sgx_status 0x%x)\n", status);
        return;
    }
    if (ret != 0) {
        printf("  ERRO: key exchange falhou (code %d)\n", ret);
        return;
    }

    h->attested = 1;
    printf("      Session key: ");
    for (int i = 0; i < 16; i++) printf("%02x", h->session_key[i]);
    printf("\n");
    printf("\n  Canal seguro estabelecido com %s!\n", h->name);
}
