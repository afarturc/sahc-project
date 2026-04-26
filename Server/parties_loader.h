#ifndef _SAHC_PARTIES_LOADER_H_
#define _SAHC_PARTIES_LOADER_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backend-neutral sink: parties_load_json calls these in order
 * (begin → add_hospital* → add_researcher* → end). The SGX server fills
 * each callback with a wrapper around the matching ECALL; the gramine
 * server fills them with direct sahc_* calls. ctx is opaque (eid for
 * SGX, NULL for gramine). Callbacks return 0 on success. */
typedef struct {
    void* ctx;
    int (*begin)(void* ctx, uint32_t quorum_m);
    int (*add_hospital)(void* ctx,
                        uint8_t* id, size_t id_len,
                        uint8_t* pubkey);
    int (*add_researcher)(void* ctx,
                          uint8_t* id, size_t id_len,
                          uint8_t* pubkey,
                          uint8_t* approvals_blob, size_t approvals_len,
                          uint32_t* accepted);
    int (*end)(void* ctx,
               uint32_t* hospitals, uint32_t* researchers, uint32_t* rejected);
} PartiesSink;

/* Returns 0 on success. -1 = file absent, -2 = parse/schema error,
 * -3 = sink callback failure. *out_* reflect what the sink accepted. */
int parties_load_json(const char* json_path,
                      PartiesSink* sink,
                      uint32_t* out_hospitals,
                      uint32_t* out_researchers,
                      uint32_t* out_rejected);

#ifdef __cplusplus
}
#endif

#endif
