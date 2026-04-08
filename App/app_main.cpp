#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"
#include "hospital_state.h"
#include "csv_loader.h"
#include "attestation.h"
#include "upload.h"
#include "query.h"
#include "helpers.h"

extern "C" void ocall_print_string(const char* str) { printf("%s", str); }

static int read_int(int* out)
{
    if (scanf("%d", out) != 1) {
        printf("  ERRO: entrada invalida (esperado numero)\n");
        while (getchar() != '\n');
        return -1;
    }
    return 0;
}

static void select_hospital_and_run(HospitalState* hospitals,
                                     void (*action)(HospitalState*))
{
    print_status(hospitals, 3);
    printf("\n  Qual hospital? [0-2] ou [9] para todos: ");
    int h;
    if (read_int(&h) != 0) return;
    if (h == 9) {
        for (int i = 0; i < 3; i++)
            action(&hospitals[i]);
    } else if (h >= 0 && h < 3) {
        action(&hospitals[h]);
    } else {
        printf("  Opcao invalida.\n");
    }
}

static void select_hospital_and_run_eid(sgx_enclave_id_t eid,
                                         HospitalState* hospitals,
                                         void (*action)(sgx_enclave_id_t, HospitalState*, uint32_t))
{
    print_status(hospitals, 3);
    printf("\n  Qual hospital? [0-2] ou [9] para todos: ");
    int h;
    if (read_int(&h) != 0) return;
    if (h == 9) {
        for (int i = 0; i < 3; i++)
            action(eid, &hospitals[i], (uint32_t)i);
    } else if (h >= 0 && h < 3) {
        action(eid, &hospitals[h], (uint32_t)h);
    } else {
        printf("  Opcao invalida.\n");
    }
}

int main()
{
    sgx_enclave_id_t eid;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
                                           NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Erro ao criar enclave: 0x%x\n", ret);
        return -1;
    }

    HospitalState hospitals[3];
    memset(hospitals, 0, sizeof(hospitals));

    strcpy(hospitals[0].name, "Hospital Santa Maria");
    strcpy(hospitals[0].csv_path, "data/hospital_0.csv");
    strcpy(hospitals[1].name, "Hospital Sao Joao");
    strcpy(hospitals[1].csv_path, "data/hospital_1.csv");
    strcpy(hospitals[2].name, "Hospital Santo Antonio");
    strcpy(hospitals[2].csv_path, "data/hospital_2.csv");

    printf("========================================\n");
    printf("   SECURE DATA LAKE - SGX Prototype\n");
    printf("========================================\n");

    int running = 1;
    while (running) {
        printf("\n============ MENU ============\n");
        printf("[1] Ver estado dos hospitais\n");
        printf("[2] Carregar dados (CSV)\n");
        printf("[3] Fazer attestation\n");
        printf("[4] Upload de dados\n");
        printf("[5] Executar query\n");
        printf("[6] Processo completo (todos)\n");
        printf("[0] Sair\n");
        printf("==============================\n");
        printf("> ");

        int opt;
        if (read_int(&opt) != 0) continue;

        switch (opt) {
        case 1:
            print_status(hospitals, 3);
            break;

        case 2:
            select_hospital_and_run(hospitals, do_load_csv);
            break;

        case 3:
            select_hospital_and_run_eid(eid, hospitals, do_attestation);
            break;

        case 4:
            select_hospital_and_run_eid(eid, hospitals, do_upload);
            break;

        case 5:
            do_query(eid);
            break;

        case 6:
            printf("\n  === Processo completo para todos os hospitais ===\n");
            for (int i = 0; i < 3; i++) {
                do_load_csv(&hospitals[i]);
                do_attestation(eid, &hospitals[i], (uint32_t)i);
                do_upload(eid, &hospitals[i], (uint32_t)i);
            }
            printf("\n  Todos os hospitais processados!\n");
            break;

        case 0:
            running = 0;
            break;

        default:
            printf("  Opcao invalida.\n");
        }
    }

    sgx_destroy_enclave(eid);
    printf("Enclave destruido. Adeus!\n");
    return 0;
}
