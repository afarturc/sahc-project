#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>

// Codigos de diagnostico
#define DIAG_HEALTHY      0
#define DIAG_DIABETES     1
#define DIAG_HYPERTENSION 2
#define DIAG_INFECTION    3

// Campos
#define FIELD_AGE         0
#define FIELD_TEMPERATURE 1
#define FIELD_BLOOD_SUGAR 2

// Tipos de query
#define QUERY_AVG   0
#define QUERY_MIN   1
#define QUERY_MAX   2
#define QUERY_COUNT 3

// Limites
#define MAX_HOSPITALS    4
#define MAX_RECORDS    256

typedef struct {
    uint32_t patient_id;
    uint32_t age;
    float temperature;
    float blood_sugar;
    uint32_t diagnosis;
} PatientRecord;

// Remote attestation
#define NONCE_SIZE    16
#define DH_PUB_SIZE   64   // Chave publica ECDH (x,y de curva P-256)

typedef struct {
    uint8_t  mrenclave[32];     // Hash do codigo do enclave
    uint8_t  nonce[NONCE_SIZE]; // Nonce do challenger
    uint8_t  enclave_pub_key[DH_PUB_SIZE]; // Chave publica DH do enclave
} AttestationReport;

// DCAP Attestation structures
#define QUOTE_SIGNATURE_SIZE 64
#define USER_DATA_SIZE       32

typedef struct {
    uint8_t  mrenclave[32];
    uint8_t  mrsigner[32];
    uint16_t isv_prod_id;
    uint16_t isv_svn;
    uint8_t  user_data[USER_DATA_SIZE];  // nonce + pub key hash
} SGXReportBody;

typedef struct {
    SGXReportBody report_body;
    uint8_t  signature[QUOTE_SIGNATURE_SIZE]; // assinatura ECDSA
    uint8_t  qe_identity[32];  // identidade do Quoting Enclave
} DCAPQuote;

#endif
