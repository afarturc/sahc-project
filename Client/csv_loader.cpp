#include "csv_loader.h"

#include <stdio.h>
#include <string.h>

int csv_load(const char* path, PatientRecord* out, size_t max_records)
{
    FILE* f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[512];
    size_t n = 0;
    int line_no = 0;
    int header_skipped = 0;

    while (fgets(line, sizeof(line), f)) {
        line_no++;
        if (!header_skipped) {
            /* Always treat the first non-empty line as the header — the
             * sample CSVs ship with one and it's not parseable as ints. */
            header_skipped = 1;
            continue;
        }
        if (line[0] == '\n' || line[0] == '\0' || line[0] == '#') continue;

        if (n >= max_records) {
            fprintf(stderr, "csv_load(%s): truncated at %zu records\n",
                    path, max_records);
            break;
        }

        PatientRecord r;
        int matched = sscanf(line, "%u,%u,%f,%f,%u",
                             &r.patient_id, &r.age,
                             &r.temperature, &r.blood_sugar,
                             &r.diagnosis);
        if (matched != 5) {
            fprintf(stderr, "csv_load(%s): line %d malformed, skipping\n",
                    path, line_no);
            continue;
        }
        out[n++] = r;
    }

    fclose(f);
    return (int)n;
}
