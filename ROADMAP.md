# Roadmap - Secure Data Lake SGX

## Current State (Milestone 1)
- Modular SGX enclave prototype running in simulation mode
- 3 hospitals load CSV data, encrypt with AES-128-GCM, upload to enclave
- Simulated DCAP attestation with nonce verification, MRENCLAVE/MRSIGNER checks
- Aggregate queries (AVG/MIN/MAX/COUNT) with diagnosis filtering
- Interactive terminal menu
- Error handling throughout

## Milestone 2 - Real Data Lake Architecture

### Phase 1: Client-Server Split with TCP Protocol
Transform from single-process terminal app into a distributed system over TCP.

**Server (enclave host):**
- Listens on a TCP socket, hosts the SGX enclave
- Accepts connections from multiple hospital clients
- Manages per-connection state (attestation status, session keys)
- Dispatches incoming messages to the appropriate ECALL

**Client (per hospital):**
- Connects to the server over TCP
- Performs remote attestation against the server's enclave
- Encrypts local CSV data with the negotiated session key and uploads
- Submits queries and receives aggregate results

**Wire protocol:**
```
[msg_type (1 byte) | payload_length (4 bytes) | payload (N bytes)]
```

**Message types:**
| Type | Direction | Payload |
|------|-----------|---------|
| `ATTEST_REQ` (0x01) | Client → Server | nonce (16 bytes) |
| `ATTEST_RESP` (0x02) | Server → Client | mrenclave + mrsigner + user_data + signature + qe_id |
| `KEY_EXCHANGE_REQ` (0x03) | Client → Server | hospital_id + simulated pub key |
| `KEY_EXCHANGE_RESP` (0x04) | Server → Client | session_key (16 bytes) |
| `UPLOAD` (0x05) | Client → Server | hospital_id + iv + tag + encrypted_data |
| `UPLOAD_ACK` (0x06) | Server → Client | status + records_accepted |
| `QUERY` (0x07) | Client → Server | query string (encrypted) |
| `QUERY_RESULT` (0x08) | Server → Client | result values (encrypted) |
| `ERROR` (0xFF) | Server → Client | error code + message |

**Why TCP over REST:**
- SGX attestation is stateful (nonce → quote → key exchange) — fits connection-oriented TCP naturally
- Binary protocol is efficient for encrypted blobs — no base64 encoding overhead
- Closer to real SGX deployments which use binary protocols (gRPC, custom TLS)
- The reference implementation used SSH + named pipes — same philosophy
- No HTTP parsing layer between client and enclave

**Post-attestation message security:**
Every message after key exchange is wrapped:
```
[msg_type (1) | payload_length (4) | iv (12) | encrypted_payload (N) | auth_tag (16)]
```
- AES-128-GCM with session key provides confidentiality + integrity
- Sequence number inside encrypted payload prevents replay attacks
- Even the server's untrusted code cannot read the data — it just forwards encrypted bytes to the enclave

### Phase 2: Attestation Abstraction Layer
Abstract attestation behind a clean interface so the codebase supports both simulation and real hardware with zero changes to the rest of the system.

**Interface (both sides):**
```c
// Server-side (inside enclave or called by enclave host)
int attestation_generate_quote(uint8_t* nonce, AttestationQuote* quote_out);
int attestation_finish_key_exchange(uint32_t hospital_id, uint8_t* pub_key,
                                     uint8_t* session_key_out);

// Client-side (verification)
int attestation_verify_quote(AttestationQuote* quote, uint8_t* nonce,
                              const uint8_t* expected_mrenclave);
```

**Two implementations, selected at build time:**

| | Simulation (`SGX_MODE=SIM`) | Hardware (`SGX_MODE=HW`) |
|---|---|---|
| Quote generation | Hardcoded MRENCLAVE, self-signed ECDSA | `sgx_create_report()` → Intel QE → `sgx_qe_get_quote()` |
| Quote verification | Local `memcmp` checks | Azure Attestation Service REST API or `sgx_qv_verify_quote()` |
| MRENCLAVE | Hardcoded constant | Computed by CPU from enclave binary |
| QE signature | Local ECDSA key pair | Intel's Quoting Enclave with Intel-signed cert chain |
| Session key | `sgx_read_rand()` returned directly | Same (or upgrade to proper ECDH key agreement) |

**Makefile integration:**
```makefile
ifeq ($(SGX_MODE), SIM)
    ATTEST_SRC = attestation_sim.cpp
else
    ATTEST_SRC = attestation_dcap.cpp
    DCAP_LIBS = -lsgx_dcap_ql -lsgx_dcap_quoteverify
endif
```

**What this enables:**
- Develop and test everything locally with `SGX_MODE=SIM`
- Deploy to Azure DCsv3 VM, flip to `SGX_MODE=HW`, recompile — everything else stays identical
- TCP protocol, encryption, queries, persistence all work unchanged
- Only the attestation files are swapped

### Phase 3: SQL-Style Query Language
The project description explicitly asks for "SQL-style aggregate queries." Replace hardcoded query options with a query parser inside the enclave.

**Supported syntax:**
```sql
SELECT AVG(temperature) WHERE diagnosis = 'Diabetes'
SELECT COUNT(*) WHERE age > 60
SELECT MIN(blood_sugar), MAX(blood_sugar)
SELECT AVG(age) WHERE diagnosis = 'Hypertension' AND age > 50
```

**Implementation:**
- Simple recursive-descent parser inside the enclave (no external dependencies allowed)
- Query string sent encrypted from client → decrypted in enclave → parsed → executed
- Grammar: `SELECT <agg>(<field>) [WHERE <field> <op> <value> [AND ...]]`
- Aggregations: AVG, MIN, MAX, COUNT
- Operators: `=`, `!=`, `>`, `<`, `>=`, `<=`

### Phase 4: Encrypted Data Persistence
Make the data lake survive enclave restarts.

**Approach:**
- Enclave derives a sealing key (using `sgx_seal_data` in HW mode, simulated AES key in SIM mode)
- On upload: enclave writes an encrypted+authenticated copy of records to disk via OCALL
- On startup: enclave reloads and decrypts the sealed data file
- Each hospital's data sealed separately, tagged with hospital ID

**Data format on disk:**
```
[hospital_id (4 bytes) | iv (12 bytes) | encrypted_records (N bytes) | auth_tag (16 bytes)]
```

### Phase 5: Multi-Field Queries and GROUP BY
Extend query capabilities for real analytical workloads.

- Multi-field filtering: `WHERE age > 50 AND diagnosis = 'Diabetes'`
- Range queries: `WHERE temperature BETWEEN 37.0 AND 39.0`
- GROUP BY: `SELECT diagnosis, AVG(age) GROUP BY diagnosis`
- Multiple aggregations: `SELECT MIN(age), MAX(age), AVG(temperature)`

## Priority and Effort

| Priority | Phase | Impact | Effort |
|----------|-------|--------|--------|
| 1 | Client-Server + TCP | High - makes it a real distributed system | Medium-High |
| 2 | Attestation Abstraction | High - enables HW migration with zero rework | Low-Medium |
| 3 | SQL-Style Queries | High - directly from project description | Medium |
| 4 | Encrypted Persistence | Medium - makes it a real data lake | Low-Medium |
| 5 | Multi-Field Queries | Medium - richer analytics | Low |

## Technology Choices

| Component | Choice | Notes |
|-----------|--------|-------|
| Networking | POSIX sockets | Standard TCP, no external dependencies |
| Serialization | Custom binary | Matches wire protocol, simple pack/unpack |
| SQL parser | Custom recursive-descent | Runs inside enclave, no external libs allowed |
| Persistence | File-based sealed storage | Encrypted data written via OCALL |
| Client crypto | OpenSSL | AES-128-GCM encryption, same as current |
| Enclave crypto | sgx_tcrypto | Same as current |
| DCAP (HW mode) | sgx_dcap_ql + sgx_dcap_quoteverify | Intel DCAP libraries, available on Azure DCsv3 |
| Attestation verification (HW) | Azure Attestation Service | REST API for quote verification with Intel cert chain |

## HW-Readiness Summary

| Component | Ready for `SGX_MODE=HW`? | Change needed |
|-----------|--------------------------|---------------|
| TCP protocol | Yes | None |
| Client-server architecture | Yes | None |
| Wire protocol + message format | Yes | None |
| AES-128-GCM encryption | Yes | None |
| Query engine | Yes | None |
| Data upload flow | Yes | None |
| Enclave business logic | Yes | None |
| Attestation (server) | Abstracted | Swap `attestation_sim.cpp` → `attestation_dcap.cpp` |
| Attestation (client) | Abstracted | Swap verification to Azure Attestation Service |
| MRENCLAVE | Abstracted | Remove hardcoded value, use real CPU-computed one |
| Sealed persistence | Yes | `sgx_seal_data` works the same, keys differ |
| Makefile | Yes | Flip `SGX_MODE=HW`, link DCAP libs |

## Constraints
- Development uses simulation mode (`SGX_MODE=SIM`)
- Designed to run on Azure DCsv3 VMs with `SGX_MODE=HW` when ready
- Enclave code cannot use external libraries — only SGX SDK trusted libraries
- All crypto inside enclave uses `sgx_tcrypto`
- All crypto outside enclave uses OpenSSL
- Attestation module is the only component that changes between SIM and HW
