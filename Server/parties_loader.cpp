#include "parties_loader.h"
#include "Enclave_u.h"
#include "third_party/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PARTY_PUBKEY_SIZE    64
#define PARTY_SIGNATURE_SIZE 64
#define PARTY_ID_MAX         63
#define MAX_APPROVALS        16

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_decode(const char* hex, uint8_t* out, size_t out_len)
{
    if (hex == NULL) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static char* slurp(const char* path, size_t* len_out)
{
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0) { fclose(f); return NULL; }
    size_t n = (size_t)st.st_size;
    char* buf = (char*)malloc(n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, n, f) != n) { free(buf); fclose(f); return NULL; }
    buf[n] = 0;
    fclose(f);
    if (len_out) *len_out = n;
    return buf;
}

static int add_hospital(sgx_enclave_id_t eid, cJSON* h)
{
    cJSON* jid  = cJSON_GetObjectItemCaseSensitive(h, "id");
    cJSON* jpub = cJSON_GetObjectItemCaseSensitive(h, "pubkey");
    if (!cJSON_IsString(jid) || !cJSON_IsString(jpub)) {
        fprintf(stderr, "parties: hospital entry missing id/pubkey\n");
        return -1;
    }
    const char* id = jid->valuestring;
    size_t id_len = strlen(id);
    if (id_len == 0 || id_len > PARTY_ID_MAX) {
        fprintf(stderr, "parties: hospital id length invalid (%zu)\n", id_len);
        return -1;
    }
    uint8_t pub[PARTY_PUBKEY_SIZE];
    if (hex_decode(jpub->valuestring, pub, sizeof(pub)) != 0) {
        fprintf(stderr, "parties: hospital '%s' pubkey hex invalid\n", id);
        return -1;
    }

    int rc = 0;
    sgx_status_t s = ecall_parties_add_hospital(eid, &rc,
                                                (uint8_t*)id, id_len,
                                                pub);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "parties: ecall_parties_add_hospital('%s') "
                        "failed (s=0x%x rc=%d)\n", id, s, rc);
        return -1;
    }
    return 0;
}

static int add_researcher(sgx_enclave_id_t eid, cJSON* r)
{
    cJSON* jid  = cJSON_GetObjectItemCaseSensitive(r, "id");
    cJSON* jpub = cJSON_GetObjectItemCaseSensitive(r, "pubkey");
    cJSON* japp = cJSON_GetObjectItemCaseSensitive(r, "approvals");
    if (!cJSON_IsString(jid) || !cJSON_IsString(jpub) || !cJSON_IsArray(japp)) {
        fprintf(stderr, "parties: researcher entry malformed\n");
        return -1;
    }
    const char* id = jid->valuestring;
    size_t id_len = strlen(id);
    if (id_len == 0 || id_len > PARTY_ID_MAX) {
        fprintf(stderr, "parties: researcher id length invalid (%zu)\n", id_len);
        return -1;
    }
    uint8_t pub[PARTY_PUBKEY_SIZE];
    if (hex_decode(jpub->valuestring, pub, sizeof(pub)) != 0) {
        fprintf(stderr, "parties: researcher '%s' pubkey hex invalid\n", id);
        return -1;
    }

    int n_app = cJSON_GetArraySize(japp);
    if (n_app <= 0 || n_app > MAX_APPROVALS) {
        fprintf(stderr, "parties: researcher '%s' has %d approvals "
                        "(expected 1..%d)\n", id, n_app, MAX_APPROVALS);
        return -1;
    }

    // Approvals blob: [u8 hid_len | hid | u8 sig[64]] repeated.
    size_t blob_cap = (size_t)n_app * (1 + PARTY_ID_MAX + PARTY_SIGNATURE_SIZE);
    uint8_t* blob = (uint8_t*)malloc(blob_cap);
    if (!blob) return -1;
    size_t off = 0;

    for (int i = 0; i < n_app; i++) {
        cJSON* a = cJSON_GetArrayItem(japp, i);
        cJSON* jhid = cJSON_GetObjectItemCaseSensitive(a, "hospital_id");
        cJSON* jsig = cJSON_GetObjectItemCaseSensitive(a, "signature");
        if (!cJSON_IsString(jhid) || !cJSON_IsString(jsig)) {
            fprintf(stderr, "parties: approval %d of '%s' malformed\n", i, id);
            free(blob); return -1;
        }
        size_t hid_len = strlen(jhid->valuestring);
        if (hid_len == 0 || hid_len > PARTY_ID_MAX) {
            fprintf(stderr, "parties: approval hospital_id invalid length\n");
            free(blob); return -1;
        }
        uint8_t sig[PARTY_SIGNATURE_SIZE];
        if (hex_decode(jsig->valuestring, sig, sizeof(sig)) != 0) {
            fprintf(stderr, "parties: approval %d signature hex invalid\n", i);
            free(blob); return -1;
        }
        blob[off++] = (uint8_t)hid_len;
        memcpy(blob + off, jhid->valuestring, hid_len); off += hid_len;
        memcpy(blob + off, sig, PARTY_SIGNATURE_SIZE);  off += PARTY_SIGNATURE_SIZE;
    }

    uint32_t accepted = 0;
    int rc = 0;
    sgx_status_t s = ecall_parties_add_researcher(eid, &rc,
                                                  (uint8_t*)id, id_len,
                                                  pub,
                                                  blob, off,
                                                  &accepted);
    free(blob);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "parties: ecall_parties_add_researcher('%s') "
                        "failed (s=0x%x rc=%d)\n", id, s, rc);
        return -1;
    }
    if (!accepted) {
        printf("parties: researcher '%s' REJECTED (quorum not met)\n", id);
    }
    return 0;
}

int parties_load_into_enclave(sgx_enclave_id_t eid,
                              const char* json_path,
                              uint32_t* out_hospitals,
                              uint32_t* out_researchers,
                              uint32_t* out_rejected)
{
    *out_hospitals = *out_researchers = *out_rejected = 0;

    size_t raw_len = 0;
    char* raw = slurp(json_path, &raw_len);
    if (!raw) return -1;

    cJSON* root = cJSON_ParseWithLength(raw, raw_len);
    free(raw);
    if (!root) {
        fprintf(stderr, "parties: JSON parse error near '%s'\n",
                cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "(unknown)");
        return -2;
    }

    cJSON* jver    = cJSON_GetObjectItemCaseSensitive(root, "version");
    cJSON* jquorum = cJSON_GetObjectItemCaseSensitive(root, "quorum_m");
    cJSON* jhosp   = cJSON_GetObjectItemCaseSensitive(root, "hospitals");
    cJSON* jres    = cJSON_GetObjectItemCaseSensitive(root, "researchers");
    if (!cJSON_IsNumber(jver) || (int)jver->valuedouble != 1 ||
        !cJSON_IsNumber(jquorum) ||
        !cJSON_IsArray(jhosp) ||
        !cJSON_IsArray(jres)) {
        fprintf(stderr, "parties: schema mismatch (version/quorum/arrays)\n");
        cJSON_Delete(root);
        return -2;
    }
    uint32_t quorum_m = (uint32_t)jquorum->valuedouble;

    int rc = 0;
    sgx_status_t s = ecall_parties_begin(eid, &rc, quorum_m);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "parties: ecall_parties_begin failed (s=0x%x rc=%d)\n", s, rc);
        cJSON_Delete(root);
        return -3;
    }

    cJSON* h;
    cJSON_ArrayForEach(h, jhosp) {
        if (add_hospital(eid, h) != 0) { cJSON_Delete(root); return -2; }
    }

    cJSON* r;
    cJSON_ArrayForEach(r, jres) {
        if (add_researcher(eid, r) != 0) {
            cJSON_Delete(root); return -2;
        }
    }

    uint32_t h_count = 0, r_count = 0, rej_count = 0;
    s = ecall_parties_end(eid, &rc, &h_count, &r_count, &rej_count);
    cJSON_Delete(root);
    if (s != SGX_SUCCESS || rc != 0) {
        fprintf(stderr, "parties: ecall_parties_end failed (s=0x%x rc=%d)\n", s, rc);
        return -3;
    }
    *out_hospitals   = h_count;
    *out_researchers = r_count;
    *out_rejected    = rej_count;
    return 0;
}
