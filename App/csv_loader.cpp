#include <stdio.h>
#include <string.h>
#include "csv_loader.h"
#include "helpers.h"

int load_csv(const char* path, PatientRecord* records, size_t max_records)
{
    FILE* f = fopen(path, "r");
    if (!f) {
        printf("  ERRO: nao consegui abrir %s\n", path);
        return -1;
    }

    char line[512];
    int count = 0;

    // Saltar o header
    if (!fgets(line, sizeof(line), f)) {
        printf("  ERRO: ficheiro vazio ou sem header: %s\n", path);
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f) && count < (int)max_records) {
        PatientRecord* r = &records[count];

        int parsed = sscanf(line, "%u,%u,%f,%f,%u",
                            &r->patient_id, &r->age,
                            &r->temperature, &r->blood_sugar,
                            &r->diagnosis);

        if (parsed == 5) {
            count++;
        } else {
            printf("  AVISO: linha ignorada (formato invalido): %s", line);
        }
    }

    fclose(f);

    if (count == 0) {
        printf("  AVISO: nenhum registo valido em %s\n", path);
    }

    return count;
}

void do_load_csv(HospitalState* h)
{
    printf("\n  A carregar dados de: %s\n", h->csv_path);

    int count = load_csv(h->csv_path, h->records, MAX_RECORDS);
    if (count < 0) {
        printf("  Falha ao carregar CSV.\n");
        return;
    }

    h->count = (size_t)count;
    printf("  Carregados %d registos para %s\n", count, h->name);
    print_records(h->records, h->count);
}
