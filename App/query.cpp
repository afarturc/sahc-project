#include <stdio.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "query.h"
#include "helpers.h"

void do_query(sgx_enclave_id_t eid)
{
    int choice;

    printf("\n  Campo:\n");
    printf("  [0] Idade\n");
    printf("  [1] Temperatura\n");
    printf("  [2] Acucar no sangue\n");
    printf("  > ");
    if (scanf("%d", &choice) != 1 || choice < 0 || choice > 2) {
        printf("  ERRO: campo invalido (esperado 0-2)\n");
        while (getchar() != '\n');
        return;
    }
    uint32_t field = (uint32_t)choice;

    printf("\n  Agregacao:\n");
    printf("  [0] Media\n");
    printf("  [1] Minimo\n");
    printf("  [2] Maximo\n");
    printf("  [3] Contagem\n");
    printf("  > ");
    if (scanf("%d", &choice) != 1 || choice < 0 || choice > 3) {
        printf("  ERRO: agregacao invalida (esperado 0-3)\n");
        while (getchar() != '\n');
        return;
    }
    uint32_t qtype = (uint32_t)choice;

    printf("\n  Filtrar por diagnostico?\n");
    printf("  [-1] Sem filtro (todos)\n");
    printf("  [ 0] Saudavel\n");
    printf("  [ 1] Diabetes\n");
    printf("  [ 2] Hipertensao\n");
    printf("  [ 3] Infecao\n");
    printf("  > ");
    if (scanf("%d", &choice) != 1 || choice < -1 || choice > 3) {
        printf("  ERRO: filtro invalido (esperado -1 a 3)\n");
        while (getchar() != '\n');
        return;
    }
    int32_t filter = (int32_t)choice;

    float value = 0;
    uint32_t processed = 0, matched = 0;

    sgx_status_t status = ecall_run_query(eid, field, qtype, filter,
                                           &value, &processed, &matched);
    if (status != SGX_SUCCESS) {
        printf("  ERRO: ECALL run_query falhou (sgx_status 0x%x)\n", status);
        return;
    }

    printf("\n  ========== RESULTADO ==========\n");
    printf("  Query: %s de %s", query_name(qtype), field_name(field));
    if (filter >= 0) printf(" (filtro: %s)", diag_name((uint32_t)filter));
    printf("\n");
    printf("  Total registos: %u\n", processed);
    printf("  Registos matched: %u\n", matched);
    printf("  Resultado: %.2f\n", value);
    printf("  ================================\n");
}
