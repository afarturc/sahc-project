# SAHC — Secure Aggregation for Healthcare Consortiums

Data lake confidencial baseado em **Intel SGX** para análise colaborativa de dados de pacientes entre múltiplos hospitais. Hospitais e investigadores estabelecem sessões autenticadas com um servidor que aloja um enclave SGX; o enclave armazena os registos em memória protegida e responde a queries agregadas (AVG, MIN, MAX, COUNT) sem nunca expor registos individuais ao host, ao OS, nem ao operador cloud.

Desenvolvido no âmbito da disciplina **Segurança e Aplicações de Hardware Confiável (SAHC)**, FCUP — Universidade do Porto, 2025/26.

## Estado Atual

- **Milestone 1 (Fase 1)** — protótipo single-process entregue. Tag `v1.0-milestone1` preserva esse estado.
- **Milestone 2 (Fases 2–4)** — fechado em SIM. Implementado: cliente/servidor TCP concorrente (pthread por conexão, `MAX_SESSIONS=8`), identidades ECDSA P-256 com admissão por quórum, handshake atestação + ECDH P-256 + HKDF-SHA256, canal AEAD AES-128-GCM com sequence numbers, enforcement de roles (HOSPITAL/RESEARCHER), k-anonymity (k=5), sealing MRENCLAVE-bound, REPL, MRENCLAVE pinning auto-gerado de `sgx_sign dump`, **migração para Gramine 1.9 + DuckDB v1.1.3** (variante `gramine_server`), **atestação DCAP real** (`SAHC_HW=1`: servidor lê `/dev/attestation/quote`, cliente chama `sgx_qv_verify_quote()`).
- **Validação em hardware Intel**: pendente, ver [`docs/HW.md`](docs/HW.md). Quota Azure DCsv* recusada na subscrição Students; a validação HW é feita externamente.

Os artefactos da Milestone 1 (relatório, slides, guião, diagramas drawio) estão em [`docs/milestone1/`](docs/milestone1/).

## Arquitetura

Modelo split-trust com dois caminhos de servidor que partilham o
cliente e o protocolo. O trusted core (`EnclaveLogic/`) é neutro de
backend e compila para os dois lados:

- **`sgx_server`** — caminho SGX-SDK clássico, com enclave
  `enclave.signed.so` carregado via ECALLs. Motor de query artesanal.
- **`gramine_server`** — caminho Gramine LibOS, mesma `EnclaveLogic`
  linkada com OpenSSL + Gramine pseudofiles. Motor de query DuckDB
  (SQL real). Atestação DCAP real quando construído com `SAHC_HW=1`.

O canal cliente↔trusted-core passa fisicamente pelo servidor mas é
cifrado fim-a-fim com a chave de sessão derivada por ECDH.

```
┌──────────────────┐    TCP frames    ┌───────────────────────────────┐
│  sgx_client      │ ←──────────────→ │  Server (untrusted host)      │
│  ECDSA identity  │   AES-128-GCM    │  ┌──────────────────────────┐ │
│  ECDH ephemeral  │   (after KEX)    │  │  Trusted core            │ │
│  Quote verifier  │                  │  │  ─ SDK enclave (sgx_*)   │ │
│  CSV loader      │                  │  │  ─ ou Gramine LibOS      │ │
│  Query REPL      │                  │  │    + DuckDB              │ │
└──────────────────┘                  │  │  • parties + records     │ │
                                      │  │  • session keys          │ │
                                      │  │  • AEAD decrypt + agg.   │ │
                                      │  │  • seal/unseal           │ │
                                      │  └──────────────────────────┘ │
                                      │  data/sealed/state.bin ←──┘  │
                                      └───────────────────────────────┘
```

### Fluxo de uma sessão

1. **Bootstrap (servidor)**: carrega `enclave.signed.so`; tenta `unseal` de `data/sealed/state.bin`; se não existir, lê `authorized_parties.json`, valida o quórum dos investigadores e faz `seal` inicial.
2. **Conexão TCP** do cliente para `127.0.0.1:7878`.
3. **`ATTEST_REQ`** (C→S): `party_id || nonce(16) || client_ecdh_pub(64) || ECDSA_sig(64)`. A assinatura cobre `"SAHC-attest-v1" || nonce || client_ecdh_pub` com a chave long-term do cliente.
4. **`ATTEST_RESP`** (S→C): `quote_format(1) || body`. Em SIM o body é o quote artesanal (MRENCLAVE, MRSIGNER, ISV ids, `user_data = SHA256(nonce || enclave_ecdh_pub)`, ECDSA do quote, QE identity, `enclave_ecdh_pub`); em build HW (`SAHC_HW=1`) o body é `enclave_ecdh_pub || quote_len || sgx_quote3_t` real lido de `/dev/attestation/quote`. Cliente despacha por format byte: SIM valida binding + MRENCLAVE pin; HW chama `sgx_qv_verify_quote()` antes do mesmo binding + pin.
5. **HKDF**: `PRK = HMAC-SHA256("SAHC-v1", ECDH_shared)`; expande para `session_key (16 B AES-128)` e `iv_prefix (4 B)`.
6. **`KEY_CONFIRM`** (C→S): `HMAC-SHA256(session_key, "confirm")`. O enclave valida, atribui o role do `party_id` e responde **`KEY_ACK`** com `status || role`.
7. **Frames AEAD** a partir daqui: `[type | len | seq(8) | iv(12) | ciphertext | tag(16)]`, `iv = iv_prefix || seq`. AAD = cabeçalho. `seq` separado por sentido, monotónico.
8. **`UPLOAD`** (HOSPITAL apenas): vetor de `PatientRecord` cifrados. O enclave desencripta, agrega ao store, e o servidor faz `seal` antes de responder **`UPLOAD_ACK`**.
9. **`QUERY_REQ`** (qualquer role): `field || op || filter_diag`. O enclave executa a agregação; se `matched < K_ANON_THRESHOLD` (5), responde `E_INSUFFICIENT_RECORDS`. Caso contrário **`QUERY_RESP`** com `result || matched || applied_k`.
10. **`SESSION_CLOSE`**: cliente fecha; o enclave liberta o `SessionContext`.

### Modelo de identidades

`authorized_parties.json` define os participantes:

- **Hospitais** (founders) entram diretamente, com `id` e `pubkey` (P-256 hex 64 B).
- **Investigadores** só são aceites se reunirem `M=2` assinaturas válidas de hospitais sobre `SHA256("SAHC-approve-v1" || researcher_id || researcher_pubkey)`.

Roles atribuídos pelo enclave no `KEY_ACK`:

| Role | Upload | Query | k-anon |
|---|---|---|---|
| `HOSPITAL` | sim | sim | 5 |
| `RESEARCHER` | não | sim | 5 |

Identidades vivem em `parties/<id>.{key,pub}` (PEM), gerados por `scripts/gen_identity.py`. O ficheiro `authorized_parties.json` é montado por `scripts/build_authorized_parties.py`.

## Estrutura do Repositório

```
Server/                 # caminho SGX-SDK: TCP + dispatcher + enclave host
  server_main.cpp       # accept loop, sealing I/O, handlers por message type
  parties_loader.cpp/h  # parsing JSON, validação de quórum
Gramine/                # caminho Gramine LibOS
  server_main.cpp       # mesmo dispatcher, sem ECALL boundary
  server.manifest.template  # Jinja: dev (gramine-direct) e HW (gramine-sgx)
EnclaveLogic/           # trusted core neutro de backend (SDK ou Gramine)
  enclave_logic.cpp     # attest_begin, key_confirm, upload, query, seal
  crypto_backend_*.cpp  # sgx_tcrypto (SDK) ou OpenSSL (Gramine)
  identity_backend_*.cpp# sgx self-report ou /dev/attestation pseudofiles
  seal_backend_*.cpp    # sgx_seal_data_ex ou Gramine MRENCLAVE-bound key
  query_engine_*.cpp    # artesanal (SDK) ou DuckDB (Gramine)
Client/                 # cliente partilhado pelos dois caminhos
  client_main.cpp       # ATTEST_REQ → KEY_CONFIRM → REPL/single-shot
  session.cpp           # ClientSession API (reutilizada pelo bench)
  quote_verify.cpp      # dispatcher SAHC vs DCAP (sgx_qv_verify_quote em HW)
  identity.cpp          # ECDSA P-256 (load PEM, sign, verify)
  secure_frame.cpp      # AES-128-GCM AEAD, sequence numbers
  csv_loader.cpp        # parsing dos CSVs por hospital
Bench/                  # bench.cpp — handshake, upload throughput, query lat.
Common/                 # framing, tcp_util, cJSON (host-side, partilhado)
Enclave/                # SDK enclave (Enclave.{cpp,edl,config.xml})
Include/                # patient.h, protocol.h, party.h
scripts/                # gen_identity.py, build_authorized_parties.py,
                        # extract_mrenclave.sh, fetch_duckdb.sh
data/                   # CSVs por hospital + sealed/state.bin (gitignored)
parties/                # chaves long-term .key/.pub (gitignored)
authorized_parties.json # registo público de identidades autorizadas
docs/                   # RUNNING.md, HW.md,
                        # milestone1/, refs/
PLANO_FINAL.md          # plano de Milestone 2 (Fases 2-4 fechadas)
```

## Como correr

Guia operacional completo (pré-requisitos, build, run, troubleshooting)
em **[`docs/RUNNING.md`](docs/RUNNING.md)** — ponto único de entrada.

Para correr em hardware Intel real: [`docs/HW.md`](docs/HW.md).

## Limitações Conhecidas

- **DCAP real só no caminho Gramine**. O `sgx_server` (SGX-SDK) emite o quote artesanal SAHC mesmo em build HW; passar a DCAP real exigiria `sgx_qe_get_quote()` dentro do enclave — fora do escopo. O caminho de produção é o `gramine_server` com `SAHC_HW=1`.
- **HW não validado por nós**. O código DCAP foi escrito sem acesso a hardware Intel; a validação está delegada (ver [`docs/HW.md`](docs/HW.md)).
- **Sem cap de conexões simultâneas no servidor**: a 9ª sessão concorrente apanha `E_INTERNAL` (slot exhaustion) — comportamento correcto mas não elegante.
- **Sem revogação dinâmica**: para remover uma party é preciso editar o JSON e remover `data/sealed/state.bin` para forçar reload.
- **Sealed blob não migra entre backends**. Trocar SGX-SDK ↔ Gramine ou SIM ↔ HW invalida `data/sealed/state.bin` (sealing keys diferentes).

## Stack

| Componente | Tecnologia |
|---|---|
| Linguagem | C/C++ |
| Crypto trusted | `sgx_tcrypto` (caminho SDK) ou OpenSSL (caminho Gramine) — AES-128-GCM, ECDSA P-256, ECDH, HMAC-SHA256, sealing |
| Query engine | Artesanal (SDK) ou DuckDB v1.1.3 com SQL allowlist (Gramine) |
| LibOS | Gramine 1.9 (caminho `gramine_server`) |
| Crypto untrusted (cliente) | OpenSSL 1.1+ (EC, EVP, AES-128-GCM, HMAC) |
| Atestação | Intel DCAP (real no caminho Gramine sob `SAHC_HW=1`; SAHC artesanal em SIM e no caminho SDK) |
| Transporte | TCP cru + framing próprio (header 5 B, AEAD pós-KEX) |
| Build | GNU Make, `sgx_edger8r`, `sgx_sign` |
