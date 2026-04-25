# SAHC — Secure Aggregation for Healthcare Consortiums

Data lake confidencial baseado em **Intel SGX** para análise colaborativa de dados de pacientes entre múltiplos hospitais. Hospitais e investigadores estabelecem sessões autenticadas com um servidor que aloja um enclave SGX; o enclave armazena os registos em memória protegida e responde a queries agregadas (AVG, MIN, MAX, COUNT) sem nunca expor registos individuais ao host, ao OS, nem ao operador cloud.

Desenvolvido no âmbito da disciplina **Segurança e Aplicações de Hardware Confiável (SAHC)**, FCUP — Universidade do Porto, 2025/26.

## Estado Atual

- **Milestone 1 (Fase 1)** — protótipo single-process entregue. Tag `v1.0-milestone1` preserva esse estado.
- **Milestone 2 (Fase 2)** — em curso. Já implementado: separação cliente/servidor TCP, identidades ECDSA P-256 com admissão por quórum, handshake atestação + ECDH P-256 + HKDF-SHA256, canal AEAD AES-128-GCM com sequence numbers, enforcement de roles (HOSPITAL/RESEARCHER), k-anonymity (k=5), sealing do estado (parties + registos) entre reinícios, REPL interativo. Falta: multi-sessão concorrente, MRENCLAVE pinning a partir do binário assinado.
- **Fases 3–4** — planeadas. Ver [`PLANO_FINAL.md`](PLANO_FINAL.md).

Os artefactos da Milestone 1 (relatório, slides, guião, diagramas drawio) estão em [`docs/milestone1/`](docs/milestone1/).

## Arquitetura

Modelo split-trust com três processos: o cliente (`sgx_client`), o servidor untrusted (`sgx_server`) e o enclave (`enclave.signed.so`) que o servidor carrega. O canal cliente↔enclave passa fisicamente pelo servidor mas é cifrado fim-a-fim com a chave de sessão derivada por ECDH.

```
┌──────────────────┐                  ┌───────────────────────────────┐
│  sgx_client      │   TCP frames     │  sgx_server (untrusted)       │
│                  │ ←──────────────→ │  ┌──────────────────────────┐ │
│  ECDSA identity  │   AES-128-GCM    │  │  enclave.signed.so       │ │
│  ECDH ephemeral  │   (after KEX)    │  │  • parties + records     │ │
│  CSV loader      │                  │  │  • session keys          │ │
│  Query REPL      │                  │  │  • AEAD decrypt + agg.   │ │
└──────────────────┘                  │  │  • seal/unseal           │ │
                                      │  └──────────────────────────┘ │
                                      │  data/sealed/state.bin ←──┘  │
                                      └───────────────────────────────┘
```

### Fluxo de uma sessão

1. **Bootstrap (servidor)**: carrega `enclave.signed.so`; tenta `unseal` de `data/sealed/state.bin`; se não existir, lê `authorized_parties.json`, valida o quórum dos investigadores e faz `seal` inicial.
2. **Conexão TCP** do cliente para `127.0.0.1:7878`.
3. **`ATTEST_REQ`** (C→S): `party_id || nonce(16) || client_ecdh_pub(64) || ECDSA_sig(64)`. A assinatura cobre `"SAHC-attest-v1" || nonce || client_ecdh_pub` com a chave long-term do cliente.
4. **`ATTEST_RESP`** (S→C): quote serializado (MRENCLAVE, MRSIGNER, ISV ids, `user_data = SHA256(nonce || enclave_ecdh_pub)`, ECDSA do quote, QE identity) seguido de `enclave_ecdh_pub(64)`. O cliente verifica MRENCLAVE pinned e o binding `user_data`.
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
Server/                 # processo untrusted (TCP + dispatcher + enclave host)
  server_main.cpp       # accept loop, sealing I/O, handlers por message type
  parties_loader.cpp/h  # parsing JSON, validação de quórum, push para enclave
Client/                 # processo cliente (TCP + handshake + REPL)
  client_main.cpp       # ATTEST_REQ → KEY_CONFIRM → REPL/single-shot
  identity.cpp/h        # ECDSA P-256 (load PEM, sign, verify)
  secure_frame.cpp/h    # AES-128-GCM AEAD, sequence numbers
  csv_loader.cpp/h      # parsing dos CSVs por hospital
Common/                 # partilhado entre Server e Client (host-side)
  framing.cpp/h         # frame header, send/recv robustos
  tcp_util.cpp/h        # connect / listen / accept / timeouts
  third_party/cJSON.*   # parser JSON
Enclave/                # código trusted (compila com sgx_tcrypto)
  Enclave.cpp           # attest_begin, key_confirm, upload, query, seal
  Enclave.edl           # interface ECALL/OCALL
  Enclave.config.xml    # heap/stack/threads
Include/
  patient.h             # PatientRecord, diagnosis/field/op constants
  protocol.h            # message types, sizes, error codes, k-anon threshold
  party.h               # PartyRole, PartyEntry (passados ao enclave)
scripts/
  gen_identity.py             # gera <id>.{key,pub} P-256 PEM
  build_authorized_parties.py # monta authorized_parties.json + assinaturas
data/                   # CSVs por hospital + sealed/state.bin (gitignored)
parties/                # chaves long-term .key/.pub (gitignored)
authorized_parties.json # registo público de identidades autorizadas
PLANO_FINAL.md          # plano da Milestone 2 (fonte de verdade)
docs/milestone1/        # entregáveis da Fase 1
```

## Pré-requisitos

- Linux (testado em Debian)
- [Intel SGX SDK for Linux](https://github.com/intel/linux-sgx) em `/opt/intel/sgxsdk`
- OpenSSL ≥ 1.1 (`libssl-dev`) — usado no cliente para ECDSA, ECDH, HKDF, AEAD
- Python 3 — para `scripts/gen_identity.py` e `scripts/build_authorized_parties.py`
- GNU Make, `g++`

## Build

```bash
source /opt/intel/sgxsdk/environment
make                # gera sgx_server, sgx_client, enclave.signed.so
make sgx_server     # apenas o servidor
make sgx_client     # apenas o cliente
make enclave        # apenas o .signed.so
make clean
```

Build em modo simulação (`SGX_MODE=SIM`) — não requer hardware SGX.

## Setup inicial (uma vez)

Gerar identidades e o `authorized_parties.json`:

```bash
python3 scripts/gen_identity.py hosp-santa-maria
python3 scripts/gen_identity.py hosp-sao-joao
python3 scripts/gen_identity.py hosp-santo-antonio
python3 scripts/gen_identity.py fcup-research
python3 scripts/build_authorized_parties.py        # monta JSON + assinaturas de quórum
```

Os artefactos das chaves vão para `parties/`; o JSON resultante para a raiz do repo.

## Correr

Num terminal:

```bash
./sgx_server                       # 127.0.0.1:7878 por defeito
./sgx_server 0.0.0.0 9000          # host/porta custom
```

No primeiro arranque o servidor lê `authorized_parties.json` e cria `data/sealed/state.bin`. Em arranques seguintes faz unseal direto desse blob (parties + registos sobrevivem).

O servidor é concorrente: cada conexão é servida por uma thread dedicada (`pthread`) e o enclave aceita até `MAX_SESSIONS=8` sessões simultâneas (`TCSNum=8`). Múltiplos clientes podem estar em REPL ao mesmo tempo; UPLOADs concorrentes serializam apenas no `seal+write` para preservar a ordem do blob em disco.

Noutro terminal — modo REPL (recomendado):

```bash
./sgx_client 127.0.0.1 7878 hosp-santa-maria
sahc> upload data/hospital_0.csv
sahc> query age avg diabetes
sahc> query temperature max any
sahc> quit
```

Modo single-shot (útil para scripting):

```bash
# upload
./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv

# query (csv_path = "-" salta o upload)
./sgx_client 127.0.0.1 7878 fcup-research - blood_sugar avg diabetes
```

Demo de duas sessões em simultâneo (com o servidor a correr noutro terminal):

```bash
./sgx_client 127.0.0.1 7878 hosp-santa-maria &      # REPL hospital
./sgx_client 127.0.0.1 7878 fcup-research          # REPL investigador
# no log do servidor aparecem handles 1 e 2 atribuídos em paralelo
```

Argumentos do REPL:

- `upload <csv_path>` — apenas roles `HOSPITAL`.
- `query <field> <op> [diag]`
  - `field`: `age` | `temperature` | `blood_sugar`
  - `op`: `avg` | `min` | `max` | `count`
  - `diag`: `any` | `healthy` | `diabetes` | `hypertension` | `infection`
- `help`, `quit`.

## Formato dos Dados

```csv
patient_id,age,temperature,blood_sugar,diagnosis
1001,45,36.5,95.0,1
```

Códigos: `0` healthy, `1` diabetes, `2` hypertension, `3` infection.

## Limitações Conhecidas

- **MRENCLAVE pinned hardcoded** no cliente (`EXPECTED_MRENCLAVE` em `Client/client_main.cpp`). Em produção é lido do `.signed.so`.
- **Quote DCAP simulado**: a assinatura QE não é validada contra a raiz Intel. A Fase 4 do plano endereça isto (em hardware real Azure DCsv3 — bloqueado por quota na nossa subscrição Students; ver `PLANO_FINAL.md`).
- **Sem cap de conexões simultâneas no servidor**: a 9ª sessão concorrente apanha `E_INTERNAL` (slot exhaustion) — comportamento correcto mas não elegante.
- **Sem revogação dinâmica**: para remover uma party é preciso editar o JSON e remover `data/sealed/state.bin` para forçar reload.

## Stack

| Componente | Tecnologia |
|---|---|
| Linguagem | C/C++ |
| Crypto trusted | `sgx_tcrypto` (rijndael128GCM, ECDSA, ECDH, HMAC-SHA256, sealing) |
| Crypto untrusted (cliente) | OpenSSL 1.1+ (EC, EVP, AES-128-GCM, HMAC) |
| Atestação | Intel DCAP (simulada — Fases 2–3) |
| Transporte | TCP cru + framing próprio (header 5 B, AEAD pós-KEX) |
| Build | GNU Make, `sgx_edger8r`, `sgx_sign` |
