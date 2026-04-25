#ifndef _SAHC_PATIENT_H_
#define _SAHC_PATIENT_H_

#include <stdint.h>

/* Patient record schema for the in-memory store. The on-the-wire form is
 * the raw little-endian bytes of this struct (sizeof = 20), so both sides
 * pack identically — keep this layout stable. */
typedef struct {
    uint32_t patient_id;
    uint32_t age;
    float    temperature;
    float    blood_sugar;
    uint32_t diagnosis;
} PatientRecord;

/* Diagnosis codes (mirror of the M1 dataset). */
#define DIAG_HEALTHY      0
#define DIAG_DIABETES     1
#define DIAG_HYPERTENSION 2
#define DIAG_INFECTION    3

/* Aggregate query selectors. */
#define FIELD_AGE         0
#define FIELD_TEMPERATURE 1
#define FIELD_BLOOD_SUGAR 2

#define QUERY_AVG   0
#define QUERY_MIN   1
#define QUERY_MAX   2
#define QUERY_COUNT 3

#endif
