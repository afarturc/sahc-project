#include "patient.h"
#include "protocol.h"
#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_field(const char* s)
{
    if (!s) return -1;
    if (!strcmp(s, "age"))                                  return FIELD_AGE;
    if (!strcmp(s, "temperature") || !strcmp(s, "temp"))    return FIELD_TEMPERATURE;
    if (!strcmp(s, "blood_sugar") || !strcmp(s, "sugar"))   return FIELD_BLOOD_SUGAR;
    return -1;
}

static int parse_op(const char* s)
{
    if (!s) return -1;
    if (!strcmp(s, "avg"))   return QUERY_AVG;
    if (!strcmp(s, "min"))   return QUERY_MIN;
    if (!strcmp(s, "max"))   return QUERY_MAX;
    if (!strcmp(s, "count")) return QUERY_COUNT;
    return -1;
}

static int parse_diag(const char* s)
{
    if (!s || !strcmp(s, "any"))                                     return -1;
    if (!strcmp(s, "healthy"))                                       return DIAG_HEALTHY;
    if (!strcmp(s, "diabetes"))                                      return DIAG_DIABETES;
    if (!strcmp(s, "hypertension") || !strcmp(s, "htn"))             return DIAG_HYPERTENSION;
    if (!strcmp(s, "infection"))                                     return DIAG_INFECTION;
    return -2;  /* signal "invalid" (since -1 already means "any") */
}

static void print_repl_help(void)
{
    printf(
        "commands:\n"
        "  upload <csv_path>             — push records (HOSPITAL only)\n"
        "  query <field> <op> [diag]     — aggregate (any role)\n"
        "      field: age | temperature | blood_sugar\n"
        "      op:    avg | min | max | count\n"
        "      diag:  any | healthy | diabetes | hypertension | infection\n"
        "  help                          — this message\n"
        "  quit                          — close the session and exit\n");
}

/* Returns 0 on clean exit (quit / EOF), -1 if the session died mid-command. */
static int repl_loop(ClientSession* s)
{
    char line[256];
    int  is_tty = isatty(fileno(stdin));

    if (is_tty) {
        printf("Entering REPL. 'help' for commands, 'quit' to exit.\n");
    }

    for (;;) {
        if (is_tty) { printf("sahc> "); fflush(stdout); }
        if (!fgets(line, sizeof(line), stdin)) break;  /* EOF */

        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r' ||
                         line[l-1] == ' '  || line[l-1] == '\t')) {
            line[--l] = 0;
        }
        if (l == 0) continue;

        char* tokens[8] = {0};
        int   n_tok = 0;
        char* tok = strtok(line, " \t");
        while (tok && n_tok < 8) { tokens[n_tok++] = tok; tok = strtok(NULL, " \t"); }
        if (n_tok == 0) continue;

        if (!strcmp(tokens[0], "quit") || !strcmp(tokens[0], "exit") ||
            !strcmp(tokens[0], "q")) {
            return 0;
        }
        if (!strcmp(tokens[0], "help") || !strcmp(tokens[0], "h") ||
            !strcmp(tokens[0], "?")) {
            print_repl_help();
            continue;
        }
        if (!strcmp(tokens[0], "upload")) {
            if (n_tok < 2) { fprintf(stderr, "usage: upload <csv_path>\n"); continue; }
            if (client_session_upload_csv(s, tokens[1], NULL, 1) < 0) return -1;
            continue;
        }
        if (!strcmp(tokens[0], "query")) {
            if (n_tok < 3) {
                fprintf(stderr, "usage: query <field> <op> [diag]\n");
                continue;
            }
            int f = parse_field(tokens[1]);
            int o = parse_op(tokens[2]);
            int d = (n_tok >= 4) ? parse_diag(tokens[3]) : -1;
            if (f < 0 || o < 0 || d == -2) {
                fprintf(stderr, "query: bad args (try 'help')\n");
                continue;
            }
            if (client_session_query(s, f, o, d, NULL, NULL, 1) < 0) return -1;
            continue;
        }
        fprintf(stderr, "unknown: %s (try 'help')\n", tokens[0]);
    }
    return 0;  /* EOF */
}

int main(int argc, char** argv)
{
    const char* host     = SAHC_DEFAULT_HOST;
    int         port     = SAHC_DEFAULT_PORT;
    const char* party_id = "hosp-santa-maria";
    const char* csv_path = NULL;   /* argv[4]; "-" or NULL = skip UPLOAD */
    const char* q_field  = NULL;   /* argv[5]; if set, send a QUERY */
    const char* q_op     = NULL;   /* argv[6] */
    const char* q_diag   = NULL;   /* argv[7]; default "any" */
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);
    if (argc >= 4) party_id = argv[3];
    if (argc >= 5 && strcmp(argv[4], "-") != 0) csv_path = argv[4];
    if (argc >= 6) q_field = argv[5];
    if (argc >= 7) q_op    = argv[6];
    if (argc >= 8) q_diag  = argv[7];

    int q_field_id = -1, q_op_id = -1, q_diag_id = -1;
    if (q_field != NULL) {
        q_field_id = parse_field(q_field);
        q_op_id    = parse_op(q_op);
        q_diag_id  = parse_diag(q_diag);
        if (q_field_id < 0 || q_op_id < 0 || q_diag_id == -2) {
            fprintf(stderr,
                "Client: bad query args. Usage: <field> <op> [diag]\n"
                "  field: age | temperature | blood_sugar\n"
                "  op:    avg | min | max | count\n"
                "  diag:  any | healthy | diabetes | hypertension | infection\n");
            return 2;
        }
    }

    ClientSession s;
    if (client_session_open(host, port, party_id, &s, 1) != 0) {
        return 1;
    }

    /* Single-shot mode: argv[4]=csv_path or argv[5..7]=query. If neither
     * is given, drop into the REPL after the handshake. */
    int single_shot = (csv_path != NULL) || (q_field != NULL);
    int rc = 0;

    if (csv_path != NULL) {
        if (client_session_upload_csv(&s, csv_path, NULL, 1) < 0) rc = 1;
    }
    if (rc == 0 && q_field != NULL) {
        if (client_session_query(&s, q_field_id, q_op_id, q_diag_id,
                                 NULL, NULL, 1) < 0) rc = 1;
    }
    if (rc == 0 && !single_shot) {
        if (repl_loop(&s) < 0) {
            fprintf(stderr, "Client: session torn down by AEAD failure\n");
            rc = 1;
        }
    }

    client_session_close(&s);
    return rc;
}
