# Secure Data Lake - SGX Prototype

## Project Overview
This is a university project for the "Security and Trusted Hardware Applications" course at FCUP (University of Porto). The goal is to implement a **collaborative medical data lake** where multiple hospitals can share patient data for aggregate analysis without exposing individual records.

The solution uses **Intel SGX (Software Guard Extensions)** enclaves to process data securely. Data is encrypted by each hospital before being sent to the enclave, which decrypts it internally, performs aggregate queries, and returns only the results.

## Current State
The prototype is functional with the following features:
- SGX enclave running in **simulation mode** (`SGX_MODE=SIM`) on Debian
- SGX SDK installed at `/opt/intel/sgxsdk`
- Structured medical records (PatientRecord) with fields: patient_id, age, temperature, blood_sugar, diagnosis
- AES-128-GCM encryption per hospital using session keys
- DCAP remote attestation flow (simulated) with nonce verification, MRENCLAVE/MRSIGNER checks, and Quoting Enclave signature
- Session keys negotiated dynamically per hospital during attestation
- Multiple hospitals (3) each loading data from CSV files
- Aggregate queries: AVG, MIN, MAX, COUNT with filtering by diagnosis
- Interactive menu interface

## Architecture

### Project Structure
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
  types.h               # Shared data structures (both sides)
data/                   # Hospital CSV sample datasets
```

### Trust Model
- **Untrusted side (App/)**: Modular host application handling user interaction, CSV loading, encryption with OpenSSL, and communication with the enclave via ECALLs
- **Trusted side (Enclave/)**: Holds session keys and decrypted data, performs all sensitive computations, signs attestation reports
- Data flows: Hospital → encrypt with session key → ECALL → enclave decrypts → stores internally → queries return only aggregates

### ECALL Interface (Enclave/Enclave.edl)
```
ecall_generate_report    - DCAP attestation: generates signed quote with MRENCLAVE, MRSIGNER, nonce
ecall_finish_key_exchange - Generates random session key for a hospital
ecall_upload_data        - Receives encrypted patient records, decrypts and stores internally
ecall_run_query          - Runs aggregate query (AVG/MIN/MAX/COUNT) with optional diagnosis filter
```

### OCALL Interface
```
ocall_print_string - Enclave requests printing to stdout
```

### Data Structures (Include/types.h)
```c
PatientRecord { patient_id, age, temperature, blood_sugar, diagnosis }
```
Diagnosis codes: HEALTHY(0), DIABETES(1), HYPERTENSION(2), INFECTION(3)
Query fields: AGE(0), TEMPERATURE(1), BLOOD_SUGAR(2)
Query types: AVG(0), MIN(1), MAX(2), COUNT(3)

### CSV Format
```
patient_id,age,temperature,blood_sugar,diagnosis
1001,45,36.5,95.0,0
```

## Build & Run
```bash
source /opt/intel/sgxsdk/environment
make clean && make
./app
```

## What Needs To Be Done

### Immediate
- ~~Split App.cpp into separate modules: crypto, csv_loader, attestation, helpers~~ (DONE)
- ~~Clean Makefile supporting the new structure~~ (DONE)
- Proper error handling throughout

### For Milestone 1 Report (due April 8)
- Detailed problem description
- Overview of approach and trusted hardware
- Security/functional requirements draft
- Progress description and next objectives

### For Milestone 2 (due May 27)
- Consider migrating to Azure VM with real SGX hardware (DCsv3 series)
- Real DCAP attestation with Azure Attestation Service
- Digital signatures on operations (require all hospitals to authorize queries)
- Key wrapping for master key persistence (survives enclave restarts)
- Separate client-server architecture (SSH + pipes or sockets)
- Performance benchmarks (encryption overhead, query times)
- More query types and multi-field filtering

### Reference Implementation
A previous group's report (report.pdf in project files) implemented a similar project with:
- Azure DCsv3 VM with real SGX hardware mode
- Azure Attestation Service for real DCAP
- Key wrapping with recursive encryption using each entity's key
- Dual signatures required for all operations
- SSH + named pipes for client-server communication
- Google Cloud Storage for encrypted data persistence

## Key Design Decisions
1. **Simulation mode**: Developer machine lacks SGX hardware, so all development uses `SGX_MODE=SIM`
2. **Session keys via simplified exchange**: Instead of full ECDH, enclave generates random session key and returns it. Report should note this limitation.
3. **MRENCLAVE hardcoded**: In real SGX, CPU calculates this from enclave code. We simulate with a constant.
4. **OpenSSL for untrusted crypto, SGX tcrypto for trusted**: App uses OpenSSL for encryption before sending to enclave; enclave uses `sgx_rijndael128GCM_decrypt` internally.
5. **Data stored in enclave memory**: No persistence between sessions. Key wrapping would address this.

## Technology Stack
- Language: C/C++
- SGX SDK: Intel SGX SDK for Linux (installed at /opt/intel/sgxsdk)
- Crypto (untrusted): OpenSSL (libssl-dev)
- Crypto (trusted): sgx_tcrypto (part of SGX SDK)
- Build: GNU Make
- OS: Debian (development machine)
