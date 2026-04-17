# SAHC — Secure Aggregation for Healthcare Consortiums

Data lake confidencial baseado em **Intel SGX** para análise colaborativa de dados de pacientes entre múltiplos hospitais. Os contribuidores cifram os registos com uma session key negociada por atestação, o enclave desencripta em memória protegida e executa queries agregadas (AVG, MIN, MAX, COUNT) sem expor registos individuais ao host, ao OS ou ao operador cloud.

Desenvolvido no âmbito da disciplina **Segurança e Aplicações de Hardware Confiável (SAHC)**, FCUP — Universidade do Porto, 2025/26.

## Estado Atual

- **Milestone 1 (Fase 1)**: protótipo funcional entregue. Tag `v1.0-milestone1` preserva este estado.
- **Milestone 2 (Fases 2–4)**: em desenvolvimento. Ver [`PLANO_FINAL.md`](PLANO_FINAL.md) para o plano completo (scope, decisões arquiteturais, sequenciamento de trabalho, infraestrutura Azure).

Os artefactos da Milestone 1 (relatório, slides, guião de apresentação, diagramas drawio) estão em [`docs/milestone1/`](docs/milestone1/).

## Arquitetura (Fase 1)

Modelo **split-trust** clássico do SGX: host não confiável trata de I/O, cifra e networking; enclave mantém session keys e registos desencriptados em memória protegida.

```
┌─────────────────────────────┐      ┌──────────────────────────────┐
│   Untrusted (App/)          │      │   Trusted (Enclave/)         │
│                             │      │                              │
│  CSV → AES-128-GCM encrypt  │─────▶│  sgx_rijndael128GCM_decrypt  │
│  nonce gen, MRENCLAVE check │◀─────│  ECDSA-signed quote          │
│  query UI                   │      │  session keys + records      │
└─────────────────────────────┘      │  aggregate engine            │
                                     └──────────────────────────────┘
```

### ECALLs implementados

| ECALL | Descrição |
|-------|-----------|
| `ecall_generate_report` | Quote DCAP simulado (MRENCLAVE, MRSIGNER, nonce, ECDSA) |
| `ecall_finish_key_exchange` | Gera session key AES-128 aleatória por hospital |
| `ecall_upload_data` | Recebe registos cifrados, desencripta e armazena |
| `ecall_run_query` | Agregação (AVG/MIN/MAX/COUNT) com filtro por diagnóstico |

## Estrutura do Repositório

```
App/                    # Host (untrusted)
  app_main.cpp          # menu, init/teardown do enclave
  csv_loader.cpp/h      # parsing CSV
  crypto.cpp/h          # AES-128-GCM via OpenSSL
  attestation.cpp/h     # orquestração DCAP simulado
  upload.cpp/h          # upload cifrado
  query.cpp/h           # UI de queries
  helpers.cpp/h         # utilitários
  hospital_state.h      # HospitalState, EXPECTED_MRENCLAVE
Enclave/                # Enclave (trusted)
  Enclave.cpp           # atestação, KEX, decrypt, queries
  Enclave.edl           # interface ECALL/OCALL
  Enclave.config.xml    # memória e threads
  Enclave_private.pem   # chave de assinatura
Include/
  types.h               # estruturas partilhadas
data/                   # CSVs de exemplo por hospital
docs/
  milestone1/           # relatório, slides, guião, secção do protótipo
  diagrams/             # diagramas drawio (arquitetura alvo + POC)
  refs/                 # papers (SgxPectre, Foreshadow)
PLANO_FINAL.md          # plano da Milestone 2 (fonte de verdade)
```

## Pré-requisitos

- Linux (testado em Debian)
- [Intel SGX SDK for Linux](https://github.com/intel/linux-sgx) em `/opt/intel/sgxsdk`
- OpenSSL (`libssl-dev`)
- GNU Make, g++

## Build & Run

```bash
source /opt/intel/sgxsdk/environment
make
./app
```

Compila em modo simulação (`SGX_MODE=SIM`) — não requer hardware SGX.

Para regressar ao protótipo da Milestone 1:

```bash
git checkout v1.0-milestone1
```

## Formato dos Dados

```csv
patient_id,age,temperature,blood_sugar,diagnosis
1001,45,36.5,95.0,0
```

Códigos de diagnóstico: `0` = saudável, `1` = diabetes, `2` = hipertensão, `3` = infeção.

## Limitações Conhecidas (Fase 1)

- MRENCLAVE hardcoded, não computado a partir do binário do enclave
- KEX unilateral: enclave gera a session key e devolve-a em claro (sem ECDH mútuo)
- Dados apenas em memória, sem sealing nem persistência
- Processo único, sem separação cliente/servidor
- Sem k-anonymity nos resultados

Todas estas limitações estão endereçadas no plano da Milestone 2.

## Stack

| Componente | Tecnologia |
|------------|------------|
| Linguagem | C/C++ |
| Crypto confiável | `sgx_tcrypto` (rijndael128GCM, ecdsa) |
| Crypto não confiável | OpenSSL (AES-128-GCM) |
| Atestação | Intel DCAP (simulada na Fase 1) |
| Build | GNU Make, `sgx_edger8r` |
