# SAHC - Secure Aggregation for Healthcare Consortiums

A secure data lake prototype using **Intel SGX** for confidential multi-hospital patient data analysis. Multiple hospitals encrypt their patient records and submit them to an SGX enclave, which decrypts and runs aggregate queries (AVG, MIN, MAX, COUNT) without exposing individual records.

Built as a university project for the **Security and Trusted Hardware Applications** course at FCUP (University of Porto).

## Motivation

Healthcare data lakes increasingly handle sensitive patient data across multiple institutions. This project explores how trusted hardware (Intel SGX) can enforce confidentiality and integrity guarantees that survive even a compromised cloud provider, enabling collaborative analysis without exposing individual records.

## Features

- **SGX enclave** for secure data processing in protected memory
- **AES-128-GCM encryption** per hospital using dynamically negotiated session keys
- **DCAP remote attestation** (simulated) with nonce verification, MRENCLAVE/MRSIGNER checks, and Quoting Enclave signature
- **Aggregate queries**: AVG, MIN, MAX, COUNT with filtering by diagnosis
- **Multi-hospital support**: 3 hospitals loading data from CSV files
- Interactive menu interface

## Architecture

The codebase follows the SGX **split-trust model**:

```
┌──────────────────────────────────────────────────────┐
│                  Untrusted (App/)                     │
│                                                      │
│  CSV Loading ─► AES-128-GCM Encryption ─► ECALLs ───┤──►┐
│                                                      │   │
│  Query Interface ◄── Results ◄── ECALLs ◄────────────┤──►│
│                                                      │   │
│  Attestation: nonce gen, MRENCLAVE/MRSIGNER verify   │   │
└──────────────────────────────────────────────────────┘   │
                                                           │
┌──────────────────────────────────────────────────────┐   │
│                  Trusted (Enclave/)                   │◄──┘
│                                                      │
│  Session keys + decrypted records in protected memory│
│  AES-GCM decryption (sgx_tcrypto)                    │
│  ECDSA-signed attestation reports                    │
│  Aggregate query execution                           │
└──────────────────────────────────────────────────────┘
```

**Data flow**: Hospital CSV → encrypt with session key → ECALL → enclave decrypts → stores internally → queries return only aggregates.

### ECALL Interface

| ECALL | Description |
|-------|-------------|
| `ecall_generate_report` | Generates a signed DCAP quote with MRENCLAVE, MRSIGNER, and nonce |
| `ecall_finish_key_exchange` | Generates a random AES-128 session key for a hospital |
| `ecall_upload_data` | Receives encrypted patient records, decrypts and stores internally |
| `ecall_run_query` | Runs an aggregate query with optional diagnosis filter |

## Project Structure

```
App/                    # Untrusted side (host application)
  app_main.cpp          # main(), menu loop, enclave init/teardown
  csv_loader.cpp/h      # CSV parsing and loading
  crypto.cpp/h          # AES-128-GCM encryption via OpenSSL
  attestation.cpp/h     # DCAP remote attestation orchestration
  upload.cpp/h          # Encrypted data upload to enclave
  query.cpp/h           # Interactive aggregate query interface
  helpers.cpp/h         # Display/translation utilities
  hospital_state.h      # HospitalState struct, EXPECTED_MRENCLAVE
Enclave/                # Trusted side (SGX enclave)
  Enclave.cpp           # Attestation, key exchange, decryption, queries
  Enclave.edl           # ECALL/OCALL interface definition
  Enclave.config.xml    # Enclave memory/thread configuration
  Enclave_private.pem   # Enclave signing key
Include/
  types.h               # Shared data structures (PatientRecord, DCAPQuote, etc.)
data/                   # Hospital CSV sample datasets
```

## Prerequisites

- Linux (developed on Debian)
- [Intel SGX SDK for Linux](https://github.com/intel/linux-sgx) installed at `/opt/intel/sgxsdk`
- OpenSSL development libraries (`libssl-dev`)
- GNU Make, GCC/G++

## Build & Run

```bash
# Source the SGX SDK environment
source /opt/intel/sgxsdk/environment

# Build
make

# Run
./app

# Clean build artifacts
make clean
```

The build runs in **simulation mode** (`SGX_MODE=SIM`) — no SGX hardware required.

## Data Format

Hospital CSV files follow this format:

```csv
patient_id,age,temperature,blood_sugar,diagnosis
1001,45,36.5,95.0,0
```

Diagnosis codes: `0` = Healthy, `1` = Diabetes, `2` = Hypertension, `3` = Infection

## Current Limitations

- **MRENCLAVE is hardcoded** — not computed from the actual enclave binary
- **Simplified key exchange** — enclave generates the session key unilaterally (not proper ECDH)
- **In-memory only** — data is lost on enclave restart
- **Single-process** — no client/server separation

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | C/C++ |
| Trusted crypto | SGX tcrypto (`sgx_rijndael128GCM_decrypt`, `sgx_ecdsa_sign`) |
| Untrusted crypto | OpenSSL (AES-128-GCM) |
| Attestation | Intel DCAP (simulated) |
| Build | GNU Make |
