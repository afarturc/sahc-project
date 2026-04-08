#include <stdio.h>
#include "helpers.h"

const char* diag_name(uint32_t d)
{
    switch (d) {
        case DIAG_HEALTHY:      return "Saudavel";
        case DIAG_DIABETES:     return "Diabetes";
        case DIAG_HYPERTENSION: return "Hipertensao";
        case DIAG_INFECTION:    return "Infecao";
        default:                return "???";
    }
}

const char* field_name(uint32_t f)
{
    switch (f) {
        case FIELD_AGE:         return "Idade";
        case FIELD_TEMPERATURE: return "Temperatura";
        case FIELD_BLOOD_SUGAR: return "Acucar no sangue";
        default:                return "???";
    }
}

const char* query_name(uint32_t q)
{
    switch (q) {
        case QUERY_AVG:   return "MEDIA";
        case QUERY_MIN:   return "MINIMO";
        case QUERY_MAX:   return "MAXIMO";
        case QUERY_COUNT: return "CONTAGEM";
        default:          return "???";
    }
}

void print_records(PatientRecord* data, size_t count)
{
    printf("  %-8s %-6s %-6s %-12s %s\n",
           "ID", "Idade", "Temp", "Acucar", "Diag");
    printf("  --------------------------------------------------\n");
    for (size_t i = 0; i < count; i++) {
        printf("  %-8u %-6u %-6.1f %-12.1f %s\n",
               data[i].patient_id, data[i].age,
               data[i].temperature, data[i].blood_sugar,
               diag_name(data[i].diagnosis));
    }
}

void print_status(HospitalState* hospitals, int num)
{
    printf("\n  %-25s %-8s %-12s %-12s\n",
           "Hospital", "Registos", "Attestation", "Upload");
    printf("  -------------------------------------------------------\n");
    for (int i = 0; i < num; i++) {
        printf("  [%d] %-22s %-8zu %-12s %-12s\n", i,
               hospitals[i].name,
               hospitals[i].count,
               hospitals[i].attested ? "OK" : "Pendente",
               hospitals[i].uploaded ? "OK" : "Pendente");
    }
}
