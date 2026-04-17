# Plano Final — Data Lake Seguro com Intel SGX

Documento de trabalho consolidado. Contém tudo o que é preciso para retomar o desenvolvimento numa conversa nova sem contexto prévio.

---

## 1. Contexto

### 1.1 Enquadramento académico
- **Curso**: Mestrado em Segurança Informática, FCUP — cadeira "Segurança e Aplicações de Hardware Confiável", ano letivo 2025/26.
- **Professor associado**: Bernardo Portela.
- **Tema 5**: Secure Data Lakes (ver `project_description.md`).
- **Milestone 1**: concluída (protótipo Fase 1 + relatório em `relatorio_data_lake_sgx.docx.pdf`).
- **Milestone 2**: entregável final. Exige cumprir o plano das quatro fases descrito na secção 6 do relatório.

### 1.2 Linguagem e comunicação
- **Documentação e comunicação**: Português de Portugal.
- **Identificadores de código, mensagens de commit, comentários inline**: Inglês (convenção padrão).

### 1.3 Documentos relacionados (já existentes, não duplicar)
- `relatorio_data_lake_sgx.docx.pdf` — relatório completo (Milestone 1). Secções 5–6 descrevem a arquitetura alvo; secção 7 descreve o protótipo Fase 1.
- `CLAUDE.md` — instruções e estrutura para o assistant.
- `CONTEXT.md` — overview técnico do estado atual.
- `ROADMAP.md` — versão anterior do roadmap (parcialmente superseded por este documento).
- `project_description.md` — descrição oficial do tema 5.
- `guiao_apresentacao.md` — guião dos slides 14–18 (Fase 1). Será reescrito no fim do projeto.
- `section_prototipo.md` — draft da secção 7 do relatório.

---

## 2. Objetivo Final

Entregar um sistema completo que cumpra a arquitetura descrita na secção 5 do relatório:

1. **Múltiplos participantes** de três tipos (hospitais, investigadores, autoridades de saúde) ligam-se a um servidor que hospeda o enclave SGX.
2. **Cada participante tem identidade autenticada** via keypair long-term verificado pelo enclave.
3. **Autorização role-based** determina o que cada tipo pode fazer.
4. **Atestação remota DCAP real** com verificação da cadeia de certificados Intel.
5. **Troca de chaves ECDH** estabelece chave de sessão AES-256-GCM via derivação HKDF.
6. **Upload cifrado** de registos de pacientes (só pelos hospitais), desencriptados só dentro do enclave.
7. **Motor de queries SQL-style** (via DuckDB sobre Gramine) executa agregações sobre o dataset combinado.
8. **Sealing + persistência** permite que o estado sobreviva a reinícios do enclave.
9. **Threshold de k-anonymity** diferenciado por role (K=5 / K=3) previne inferência trivial.
10. **Benchmarks em hardware real** (Azure DCsv3) documentados no relatório final.

### 2.1 Entregáveis finais
- **Código fonte** funcional do cliente e do servidor (C/C++).
- **Scripts de build e deployment** (`Makefile`, `setup_azure.sh`).
- **Relatório atualizado** (secções 7–9 reescritas para refletir Fase 2+3+4).
- **Tabela de benchmarks** em hardware SGX real.
- **README** com instruções de build, deploy e uso.
- **Apresentação** atualizada (só no fim; não é prioridade durante o desenvolvimento).

---

## 3. Modelo de Entidades e Autorização

### 3.1 Papéis

| Papel | Pode fazer | Exemplos |
|---|---|---|
| **`HOSPITAL`** | Upload de registos + queries (K≥5) | Hospital Santa Maria, Hospital São João, Hospital Santo António |
| **`RESEARCHER`** | Queries apenas (K≥5) | FCUP (Faculdade de Ciências), IPATIMUP |
| **`HEALTH_AUTHORITY`** | Queries apenas (K≥3) | INSA (Instituto Nacional de Saúde), DGS (Direção-Geral da Saúde) |

**Racional**:
- Hospitais contribuem dados clínicos e também analisam o dataset combinado para investigação própria.
- Instituições de investigação analisam mas não submetem dados clínicos individuais.
- Autoridades de saúde pública têm mandato legal para vigilância epidemiológica (deteção de surtos, eficácia de vacinas), onde o threshold alto mascararia sinais relevantes — daí K=3.

### 3.2 Matriz de autorização

| Operação | HOSPITAL | RESEARCHER | HEALTH_AUTHORITY |
|---|---|---|---|
| Abrir sessão (attestation) | ✅ | ✅ | ✅ |
| Upload de dados | ✅ | ❌ (`E_UNAUTHORIZED`) | ❌ (`E_UNAUTHORIZED`) |
| Query | ✅ (K≥5) | ✅ (K≥5) | ✅ (K≥3) |
| Fechar sessão própria | ✅ | ✅ | ✅ |

### 3.3 Identidade
- Cada participante tem **keypair long-term ECDSA P-256**.
- A chave privada fica **só com o cliente** (ficheiro local em `parties/<id>.key`, permissões 0600).
- A chave pública é registada em `authorized_parties.json` carregado pelo servidor/enclave no arranque.

**Escolha ECDSA P-256 em vez de Ed25519**: o `sgx_tcrypto` não tem Ed25519 nativo; P-256 já é usado para ECDH e tem `sgx_ecdsa_verify`. Reutiliza código.

### 3.4 Ficheiro `authorized_parties.json`
```json
{
  "version": 1,
  "parties": [
    {
      "id": "hosp-santa-maria",
      "name": "Hospital Santa Maria",
      "role": "HOSPITAL",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "hosp-sao-joao",
      "name": "Hospital São João",
      "role": "HOSPITAL",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "hosp-santo-antonio",
      "name": "Hospital Santo António",
      "role": "HOSPITAL",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "fcup-research",
      "name": "FCUP - Faculdade de Ciências",
      "role": "RESEARCHER",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "ipatimup",
      "name": "IPATIMUP - Investigação Biomédica",
      "role": "RESEARCHER",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "insa",
      "name": "INSA - Instituto Nacional de Saúde",
      "role": "HEALTH_AUTHORITY",
      "pubkey_p256_hex": "04...",
      "revoked": false
    },
    {
      "id": "dgs",
      "name": "DGS - Direção-Geral da Saúde",
      "role": "HEALTH_AUTHORITY",
      "pubkey_p256_hex": "04...",
      "revoked": false
    }
  ]
}
```

- **Simplificação**: sem assinatura de Authority externa. A integridade do ficheiro assume-se propriedade do operador durante setup inicial (configuração fora-de-banda). Na Fase 4 pode evoluir para assinatura com pubkey conhecida pelo enclave, se houver tempo.
- **Revogação**: `revoked: true` → enclave recusa sessões novas. Sessões abertas continuam até fecharem.

### 3.5 Autenticação mútua no ATTEST_REQ
- Cliente envia: `party_id || nonce || client_ephemeral_pubkey || ECDSA_sign(privkey_longterm, SHA256(nonce || client_ephemeral_pubkey || party_id))`.
- Enclave procura `party_id` em `authorized_parties.json`, verifica assinatura, rejeita se:
  - party_id não existe,
  - `revoked: true`,
  - assinatura inválida.
- Enclave responde com quote DCAP (em que `user_data = SHA256(enclave_ephemeral_pubkey)`).
- `SessionContext` guarda o `role` resolvido da lista para enforcement subsequente.

### 3.6 Future work documentado
- Authority central com assinatura do JSON.
- Audit log sealed com Merkle-chain.
- Roles granulares por categoria de dados (ex: farmacêuticas só veem agregados de `blood_sugar`).
- Revogação via CRL/OCSP-style.

---

## 4. Estado Atual — Fase 1 (concluída)

### 4.1 O que funciona
- Protótipo single-process em `SGX_MODE=SIM` na máquina Debian do utilizador.
- 3 hospitais (Santa Maria, São João, Santo António) carregam CSV do diretório `data/`.
- Cifra AES-128-GCM via OpenSSL no host; desencriptação com `sgx_rijndael128GCM_decrypt` no enclave.
- Atestação DCAP **simulada**: nonce de 16 bytes, MRENCLAVE/MRSIGNER hardcoded, assinatura ECDSA pelo "QE simulado".
- Session keys geradas unilateralmente pelo enclave via `sgx_read_rand`.
- Queries agregadas AVG/MIN/MAX/COUNT sobre `age`, `temperature`, `blood_sugar`, com filtro opcional por diagnóstico.
- Menu interativo no terminal.

### 4.2 Estrutura do código atual
```
App/                    # Host (não confiável) — modular
  app_main.cpp          # menu + init/teardown
  csv_loader.cpp/h
  crypto.cpp/h          # OpenSSL AES-128-GCM
  attestation.cpp/h     # fluxo DCAP simulado
  upload.cpp/h
  query.cpp/h
  helpers.cpp/h
  hospital_state.h
Enclave/                # Trusted
  Enclave.cpp
  Enclave.edl
  Enclave.config.xml
  Enclave_private.pem
Include/
  types.h               # PatientRecord, DCAPQuote, AttestationReport
data/
  hospital_0.csv
  hospital_1.csv
  hospital_2.csv
Makefile
```

### 4.3 Simplificações a remover (secção 7.8 do relatório)
| | Atual (Fase 1) | Alvo final |
|---|---|---|
| Processo | único (host+enclave) | cliente + servidor separados |
| Entidades | 3 hospitais iguais | 3 papéis distintos (HOSPITAL / RESEARCHER / HEALTH_AUTHORITY) |
| Identidade cliente | inexistente (auto-declarada) | ECDSA P-256 + verificação |
| Autorização | inexistente | role-based |
| Troca de chaves | enclave devolve em claro | ECDH + HKDF |
| Cifra | AES-128-GCM | AES-256-GCM |
| Atestação | simulada, MRENCLAVE hardcoded | DCAP real via PCCS |
| Persistência | nenhuma | sealing em disco |
| k-anonymity | ausente | threshold differenciado por role (K=5/3) |
| Motor queries | manual hardcoded | DuckDB SQL via Gramine |
| Sessões | array global partilhado | sessões isoladas por participante |

---

## 5. Decisões Arquiteturais

### 5.1 Stack tecnológico

| Componente | Tecnologia | Notas |
|---|---|---|
| Linguagem | C/C++ | Consistente com SDK SGX |
| Enclave (Fase 2) | Intel SGX SDK | Controlo total, fronteira explícita |
| Enclave (Fase 3+) | Gramine LibOS | Necessário para embutir DuckDB |
| Motor SQL | DuckDB embedded | Só na Fase 3 |
| Crypto host | OpenSSL | AES-256-GCM, P-256 ECDH + ECDSA, HKDF |
| Crypto enclave (SDK) | `sgx_tcrypto` | `sgx_ecc256_*`, `sgx_hmac256_*`, `sgx_ecdsa_verify` |
| Crypto enclave (Gramine) | OpenSSL | Gramine suporta libc |
| Transporte | TCP puro (sem TLS) | Canal seguro construído sobre attestation + ECDH |
| Serialização | Binário custom | Header packed + payload |
| Atestação (Fase 2) | Simulada (continuação) | `sgx_ecdsa_sign` com chave local |
| Atestação (Fase 4) | DCAP real | `libsgx_dcap_ql` + `libsgx_dcap_quoteverify` |
| Persistência | `sgx_seal_data` + ficheiros | Em `data/sealed/` via OCALL |
| Build | GNU Make | 3 targets: `sgx_server`, `sgx_client`, `enclave.signed.so` |
| JSON parsing (host) | parser minimal custom ou nlohmann/json single-header | JSON simples, sem necessidade de libs grandes |

### 5.2 Decisão: sem TLS explícito
A attestation com ECDH binding produz canal seguro end-to-end entre cliente e enclave. Adicionar TLS 1.3 por cima é redundante para o modelo de ameaças (operador cloud é adversário; MITM na rede é detetável pelo quote + ECDH). **Justificado no relatório**.

### 5.3 Decisão: SDK até fim da Fase 2, migrar para Gramine no início da Fase 3
- Fase 2 (cliente/servidor, ECDH, identidade, sealing, multi-sessão) mapeia bem para primitivas do SDK.
- Gramine só é necessário quando queremos executar DuckDB (binário Linux não modificado) dentro do enclave.
- Vantagem: até à Fase 2 mantemos ciclo de desenvolvimento rápido em simulação local.

### 5.4 Decisão: manter lógica "business" agnóstica de SDK
Desde o início da Fase 2, escrever funções core (gestão de sessões, execução de queries, role enforcement, k-anonymity, cifra aplicada) em C puro, sem tipos `sgx_*` no seu interior. Só os wrappers ECALL/OCALL tocam em SDK. Reduz custo de migração para Gramine na Fase 3.

### 5.5 Decisão: enclave pubkey bound to quote
O `user_data` do quote contém `SHA256(enclave_ephemeral_pubkey)` para prevenir MITM na troca ECDH. O cliente verifica esta ligação antes de aceitar a chave pública do enclave.

### 5.6 Decisão: infraestrutura híbrida
- **Fases 1 e 2**: desenvolvimento local em Debian com `SGX_MODE=SIM`.
- **Smoke test fim de Fase 2**: provisionar DCsv3, compilar com `SGX_MODE=HW`, validar que nada quebra.
- **Fases 3 e 4**: desenvolvimento em Azure DCsv3 (hardware SGX real).
- **Benchmarks finais**: sempre em HW real.

---

## 6. Plano de Trabalho

Organizado em 3 fases grandes. Cada fase em passos independentes e testáveis.

---

### FASE 2 — Cliente/Servidor + Multi-sessão + ECDH + Identidades + Roles + Sealing

**Objetivo**: transformar o protótipo single-process numa arquitetura distribuída com autenticação mútua de participantes, três papéis distintos e enforcement role-based, mantendo atestação simulada.

**Ambiente**: local, `SGX_MODE=SIM`.

#### Passo 1 — Scaffolding de protocolo e build (~1–2h)

Ficheiros a criar:
- `Include/protocol.h` — enum `MessageType`, enum `PartyRole`, structs packed para headers, constantes.
- `Include/party.h` — struct `AuthorizedParty { char id[64]; uint8_t pubkey[64]; PartyRole role; bool revoked; }`.
- `Common/framing.cpp/h` — `read_frame(fd)`, `write_frame(fd, type, payload, len)`.
- `Common/tcp_util.cpp/h` — `tcp_listen(port)`, `tcp_connect(host, port)`.

Reorganização:
- Renomear `App/` → `Server/`.
- Criar `Client/` com esqueleto de `client_main.cpp`.
- Atualizar Makefile para 3 targets.

**Wire protocol:**
```
Frame pré-KEX:   [type(1) | payload_len(4, BE) | payload(N)]
Frame pós-KEX:   [type(1) | payload_len(4, BE) | seq(8) | iv(12) | ciphertext(N) | tag(16)]
```

**Message types:**
| Code | Nome | Direção | Payload |
|---|---|---|---|
| 0x01 | `ATTEST_REQ` | C→S | party_id_len(1) + party_id + nonce(16) + client_ecdh_pubkey(64) + signature(64) |
| 0x02 | `ATTEST_RESP` | S→C | quote(var) + enclave_ecdh_pubkey(64) |
| 0x03 | `KEY_CONFIRM` | C→S | HMAC(session_key, "confirm") |
| 0x04 | `KEY_ACK` | S→C | status(1) + assigned_role(1) |
| 0x05 | `UPLOAD` | C→S | record_count(4) + records(N) (encrypted) |
| 0x06 | `UPLOAD_ACK` | S→C | records_accepted(4) |
| 0x07 | `QUERY_REQ` | C→S | query_spec (encrypted) |
| 0x08 | `QUERY_RESP` | S→C | result(16) + matched_count(4) + applied_k(1) (encrypted) |
| 0xFE | `SESSION_CLOSE` | C→S | — |
| 0xFF | `ERROR` | S→C | code(2) + message(N) |

**Error codes** (em `protocol.h`):
```c
enum ErrorCode : uint16_t {
  E_OK = 0x0000,
  E_INVALID_STATE = 0x0001,
  E_DECRYPT_FAIL = 0x0002,
  E_REPLAY = 0x0003,
  E_UNAUTHORIZED = 0x0004,       // role não tem permissão para a operação
  E_UNKNOWN_PARTY = 0x0005,      // party_id não na authorized list
  E_REVOKED = 0x0006,            // party revogado
  E_BAD_SIGNATURE = 0x0007,      // assinatura ECDSA inválida
  E_INSUFFICIENT_RECORDS = 0x0008, // matched_count < K
  E_BAD_NONCE = 0x0009,
  E_INTERNAL = 0xFFFF
};
```

**Critério de sucesso**: `make all` produz os três artefactos; hello round-trip `sgx_client` → `sgx_server` sobre TCP.

#### Passo 2 — Servidor TCP + dispatcher (~2–3h)

- `sgx_server` faz `socket/bind/listen/accept` loop. Uma thread por conexão (limite 10).
- Dispatcher: lê frame, invoca ECALL correspondente consoante `type`, serializa resposta.
- Inicialmente **sem crypto** — valida fluxo de mensagens primeiro.
- Port: default 7777, configurável via argumento.

**Critério de sucesso**: cliente envia `ATTEST_REQ`, recebe `ATTEST_RESP`. Fluxo Fase 1 portado para TCP, ainda em claro.

#### Passo 3 — Multi-sessão no enclave (~3–4h)

- Definir `SessionContext` em `Enclave.cpp`:
  ```c
  struct SessionContext {
      uint64_t handle;           // opaco, aleatório, não previsível
      char party_id[64];         // resolvido da authorized list
      PartyRole role;            // HOSPITAL / RESEARCHER / HEALTH_AUTHORITY
      uint8_t ecdh_priv[32];     // apagar após derivação
      uint8_t session_key[32];   // AES-256
      uint8_t iv_prefix[4];      // derivado via HKDF
      PatientRecord records[MAX_RECORDS_PER_PARTICIPANT];
      uint32_t records_count;
      uint64_t next_seq_out;
      uint64_t last_seq_in;
      enum { INIT, ATTESTING, READY, CLOSED } state;
      uint64_t created_at;
  };
  static SessionContext sessions[MAX_SESSIONS];
  ```
- `ecall_generate_report` aloca `SessionContext`, devolve handle 64-bit aleatório.
- ECALLs seguintes recebem handle como primeiro parâmetro.
- Novo `ecall_close_session(handle)` zera chaves antes de libertar.
- Atualizar `Enclave.edl`.

**Critério de sucesso**: duas sessões concorrentes de participantes diferentes não se misturam.

#### Passo 4a — Carregar `authorized_parties.json` no arranque (~2h)

**Host**:
- `parties_loader.cpp` lê `authorized_parties.json` (JSON parser — nlohmann single-header ou custom minimal).
- Serializa para estrutura binária packed:
  ```
  uint32_t count;
  for each:
    uint8_t id_len;
    char id[id_len];
    uint8_t role;        // 0=HOSPITAL, 1=RESEARCHER, 2=HEALTH_AUTHORITY
    uint8_t pubkey[64];
    uint8_t revoked;
  ```
- Invoca `ecall_load_authorized_parties(blob, len)`.

**Enclave**:
- Parseia blob, guarda em array estático (`MAX_PARTIES = 32`).
- Função interna `find_party(party_id) → AuthorizedParty*`.

**Critério de sucesso**: `./sgx_server` no arranque imprime "Loaded N parties: ..." listando id+role de cada um.

#### Passo 4b — ECDH + identidade + canal seguro (~5–8h)

**Geração de keypairs long-term (uma vez, fora do enclave):**
- Script `scripts/gen_identity.sh <party_id>` gera ECDSA P-256 keypair.
- Escreve `parties/<party_id>.key` (priv, 0600) e `parties/<party_id>.pub` (pub hex).
- Pub copiada manualmente para `authorized_parties.json` + recarregamento do servidor.

**No cliente (ao ligar):**
1. Lê long-term privkey de `parties/<party_id>.key`.
2. Gera keypair efémero P-256 (OpenSSL `EVP_PKEY_keygen`).
3. Calcula `msg_hash = SHA256(nonce || ephemeral_pubkey || party_id)`.
4. Assina com ECDSA P-256 + SHA-256.
5. Envia `ATTEST_REQ { party_id, nonce, ephemeral_pubkey, signature }`.

**No enclave:**
1. `find_party(party_id)`. Se não existe → `E_UNKNOWN_PARTY`. Se `revoked` → `E_REVOKED`.
2. Verifica assinatura: `sgx_ecdsa_verify(msg_hash, signature, party.pubkey)`. Falha → `E_BAD_SIGNATURE`.
3. `sgx_ecc256_open_context` + `sgx_ecc256_create_key_pair` → keypair efémero.
4. `sgx_ecc256_compute_shared_dhkey(client_pubkey, enclave_privkey)` → shared secret.
5. **HKDF-SHA256** (implementação local no enclave):
   ```
   PRK         = HMAC-SHA256(salt="DataLakeSGX-v1", ikm=shared_secret)
   session_key = HMAC-SHA256(PRK, info="session-aes256"||0x01)[0:32]
   iv_prefix   = HMAC-SHA256(PRK, info="iv-prefix"     ||0x01)[0:4]
   ```
6. Guarda `party_id`, `role`, `session_key`, `iv_prefix` no `SessionContext`. Apaga `ecdh_priv`.
7. Constrói quote: MRENCLAVE + MRSIGNER + `user_data = SHA256(enclave_ephemeral_pubkey)` + `sgx_ecdsa_sign`.
8. Envia `ATTEST_RESP`.

**Verificação no cliente:**
1. Nonce devolvido bate com o enviado.
2. MRENCLAVE coincide com `expected_mrenclave.hex`.
3. MRSIGNER coincide.
4. `SHA256(enclave_ephemeral_pubkey)` == `user_data`.
5. Assinatura ECDSA do quote válida.

Cliente faz seu lado do ECDH + HKDF → deriva mesma `session_key` e `iv_prefix` → envia `KEY_CONFIRM { HMAC(session_key, "confirm") }`.

Servidor verifica HMAC, responde `KEY_ACK { status=OK, assigned_role }`.

**Canal seguro (`secure_send` / `secure_recv`):**
- AES-256-GCM com `session_key`.
- IV: 12 bytes = `iv_prefix(4) || seq(8, big-endian)`.
- AAD: `type(1) || payload_len(4) || seq(8)`.
- Tag: 16 bytes.
- Seq num incrementado a cada envio; peer rejeita `seq <= last_seen_seq` → `E_REPLAY`.

**Critério de sucesso**:
- Cliente e enclave derivam a mesma `session_key`.
- Manipular 1 byte do ciphertext → peer rejeita.
- Replay de mensagem antiga → `E_REPLAY`.
- Cliente com chave privada errada → `E_BAD_SIGNATURE`.
- `party_id` não registado → `E_UNKNOWN_PARTY`.

#### Passo 5 — Enforcement role-based (~1–2h)

- `ecall_upload_data(handle, ...)`: verifica `sessions[handle].role == HOSPITAL`. Senão → `E_UNAUTHORIZED`.
- `ecall_run_query(handle, ...)`: permitido para todos os papéis autenticados.
- `threshold_for(role)`:
  - `HEALTH_AUTHORITY` → 3
  - outro → 5

**Critério de sucesso**:
- `RESEARCHER` tenta upload → recebe `E_UNAUTHORIZED`.
- `HEALTH_AUTHORITY` faz query com matched_count=4 → recebe resultado.
- `HOSPITAL` faz mesma query → recebe `E_INSUFFICIENT_RECORDS`.

#### Passo 6 — Sealing e persistência (~3–4h)

**OCALLs novos:**
- `ocall_write_sealed_blob(const char* party_id, const uint8_t* blob, size_t len)`.
- `ocall_read_sealed_blob(const char* party_id, uint8_t* buf, size_t max_len, size_t* out_len)`.
- `ocall_list_sealed_parties(char* ids_concat, size_t max_len, size_t* count, size_t* total_len)`.

**Na ingestão** (após `ecall_upload_data`):
- Enclave serializa `records + count + party_id`, chama `sgx_seal_data` (política MRENCLAVE), OCALL escreve em `data/sealed/<party_id>.bin`.

**No arranque** (`ecall_load_all_sealed()`):
- Enclave lista sealed blobs via OCALL.
- Para cada: desseal, criar "sessão fantasma" (contexto com dados mas sem chave de sessão ativa) até que um cliente com mesmo `party_id` faça attestation — aí a fantasma é promovida ao contexto dessa sessão.

**Formato em disco:**
```
[magic(4)="SEAL" | version(1) | party_id_len(1) | party_id(N) | sealed_blob(M)]
```

**Critério de sucesso**: upload → kill servidor → restart → cliente re-atesta → query devolve resultado idêntico sem novo upload.

#### Passo 7 — k-anonymity threshold por role (~30min)

- Constantes configuráveis via `-DK_ANON_DEFAULT=N` e `-DK_ANON_AUTHORITY=N`.
- `ecall_run_query` calcula `matched_count`; compara com `threshold_for(session.role)`.
- Se `matched_count < threshold`: `E_INSUFFICIENT_RECORDS` + `matched_count` + `applied_k`.
- Resposta inclui `applied_k` para o cliente mostrar contexto:
  - *"Resultado suprimido: 4 < 5 registos (threshold para RESEARCHER). Demasiado específico para k-anonymity."*
  - *"Resultado: 42.3 (matched=8, threshold=3 para HEALTH_AUTHORITY)."*

#### Passo 8 — Robustecimento + benchmarks locais (~3–4h)

- Error handling consistente.
- Timeouts em sessões (default 30min); cleanup de contextos idle.
- `memset_s` nas chaves antes de libertar.
- **Benchmarks preliminares em SIM**:
  - Throughput cifra cliente (MB/s).
  - Latência attestation + ECDH (ms).
  - Latência upload.
  - Latência query.

#### Passo 9 — Smoke test em hardware real (Azure, ~3h)

- Provisionar DCsv3 (ver secção 7).
- `git clone`, `make SGX_MODE=HW`, correr end-to-end.
- Confirmar que o código compila e roda.
- **Não** atualizar attestation para DCAP real ainda.

**Critério de sucesso**: fluxo completo funciona em HW com attestation simulada.

**Total Fase 2 estimado**: 22–37h de trabalho ativo; 5–18 dias corridos conforme cadência.

---

### FASE 3 — Gramine LibOS + DuckDB

**Objetivo**: substituir o motor de queries manual por DuckDB embebido dentro de enclave Gramine, suportando SQL real.

**Ambiente**: Azure DCsv3 (Gramine não tem modo SIM útil).

#### Passo 10 — Setup Gramine em Azure (~4–6h)
- Provisionar DCsv3 com Ubuntu 22.04 LTS + `setup_azure.sh`.
- Instalar Gramine via apt (repositório oficial).
- Configurar PCCS local.
- Build teste: `gramine-sgx helloworld`.

#### Passo 11 — Migrar servidor para Gramine (~6–10h)
- Eliminar `Enclave/` (SDK-specific).
- Lógica (sessões, cifra, queries, sealing, role enforcement) passa para `EnclaveLogic/` como módulo C++ normal.
- Criar `server.manifest.template`:
  - `libos.entrypoint = "sgx_server"`
  - Trusted files: binário, libs, `authorized_parties.json`.
  - Allowed files: `data/sealed/` com permissão de escrita.
  - `sgx.enclave_size = "1G"`.
  - `sgx.max_threads = 16`.
  - `sgx.remote_attestation = "dcap"`.
- Substituir `sgx_tcrypto` por OpenSSL (lógica agnóstica do Passo 4b paga-se aqui).
- Atestação via `sgx.attestation.*` do Gramine.
- Sealing via Gramine-compatible API.

#### Passo 12 — Integrar DuckDB no enclave Gramine (~6–10h)
- Adicionar DuckDB (submodule ou pré-compilado).
- Atualizar manifest para libs DuckDB.
- Substituir `execute_aggregation()` por DuckDB API:
  ```cpp
  duckdb::DuckDB db(":memory:");
  duckdb::Connection con(db);
  con.Query("CREATE TABLE patients (...)");
  auto result = con.Query(user_sql);
  ```
- **Whitelist de queries**: parser minimal rejeita DROP/UPDATE/subqueries.
- K-anonymity: após executar, verificar `matched_count` antes de devolver — role continua a determinar threshold.
- Fluxo: cliente envia SQL cifrado → enclave desencripta → whitelist → DuckDB → k-anon check → resultado cifrado.

**Critério de sucesso**: `SELECT AVG(blood_sugar) WHERE diagnosis = 1` via cliente → resultado correto + matched_count.

#### Passo 13 — Cliente suporta SQL (~2–3h)
- CLI: `./sgx_client --party hosp-santa-maria query "SELECT COUNT(*) WHERE age > 50"`.
- Query vai cifrada no `QUERY_REQ`.

#### Passo 14 — Mitigar timing side-channels em queries (~2h)
- Padding de respostas para tamanho fixo.
- Latência aleatória 0–50ms.
- Limitações documentadas.

**Total Fase 3 estimado**: 20–31h ativos.

---

### FASE 4 — DCAP Real + Benchmarks Finais

**Objetivo**: atestação DCAP real com cadeia de certificados Intel completa.

**Ambiente**: Azure DCsv3.

#### Passo 15 — DCAP real no servidor (~3–4h)
- Manifest: `sgx.remote_attestation = "dcap"`.
- Servidor expõe quote real produzido pelo QE.
- MRENCLAVE calculado pelo CPU.
- `user_data` continua a bind enclave pubkey.

#### Passo 16 — Verificação DCAP no cliente (~4–6h)
- Usar `libsgx_dcap_quoteverify` contra **PCCS local** na VM.
- Aceitar `SGX_QL_QV_RESULT_OK`; rejeitar outros.
- Substituir `attestation_sim.cpp` por `attestation_dcap.cpp`.
- Makefile escolhe consoante `SGX_MODE`.

#### Passo 17 — Limpeza (~1h)
- `attestation_sim.cpp` ainda compila para dev offline.
- `SGX_MODE=HW` usa `attestation_dcap.cpp`.

#### Passo 18 — Benchmarks finais em HW (~3–5h)
Métricas:
- Cifra cliente: MB/s por batch size.
- ECDH + attestation: tempo total.
- Upload: registos/segundo.
- Query: latência (com/sem filtros, com/sem GROUP BY).
- Efeito paginação EPC: 10K / 100K / 1M registos.
- Comparação Gramine vs. nativo.

#### Passo 19 — Atualizar relatório + README (~5–8h)
- Reescrever secções 7.4–7.8.
- Nova secção "7.X Benchmarks".
- Atualizar diagrama (Figura 5): cliente + servidor + 3 papéis + DCAP real.
- Conclusão (secção 9): reflexão sobre o que foi alcançado.
- README com build local, build Azure, exemplos de queries por role.

**Total Fase 4 estimado**: 16–25h ativos.

---

## 7. Setup Azure

### 7.1 Conta e crédito
- Crédito: **$100** (Azure for Students).
- SKU: **Standard_DC2s_v3** (2 vCPU, 16GB RAM, 8GB EPC) — ~$0.138/h.
- **$100 dá ≈ 300–700h** de VM ativa.

### 7.2 Configuração inicial da VM
1. **Imagem**: Ubuntu 22.04 LTS limpa.
2. **Região**: West Europe ou North Europe.
3. **SSH key** (não password).
4. **Networking**: só SSH aberto; servidor testado via SSH tunnel.
5. **Auto-shutdown** às 19h (obrigatório).
6. **Disco**: Standard SSD 64GB.

### 7.3 Script `setup_azure.sh` (a criar)
```bash
#!/bin/bash
set -e
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential git cmake libssl-dev pkg-config tmux

# Intel SGX SDK
wget https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.25.100.3.bin
chmod +x sgx_linux_x64_sdk_*.bin
./sgx_linux_x64_sdk_*.bin --prefix=/opt/intel
echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc

# Intel SGX PSW + DCAP
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt update
sudo apt install -y libsgx-dcap-ql libsgx-dcap-quote-verify libsgx-dcap-default-qpl sgx-dcap-pccs

# Gramine (Fase 3+)
curl -fsSLo /etc/apt/keyrings/gramine-keyring.gpg \
  https://packages.gramineproject.io/gramine-keyring.gpg
echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring.gpg] \
  https://packages.gramineproject.io/ jammy main' \
  | sudo tee /etc/apt/sources.list.d/gramine.list
sudo apt update
sudo apt install -y gramine
```

### 7.4 Dev loop
- **VS Code Remote-SSH**.
- **Git como ponte** entre laptop e VM.
- **tmux** para builds longos.

### 7.5 Hábitos para não queimar crédito
1. Auto-shutdown configurado ao criar VM.
2. Dashboard Azure semanal.
3. Destruir VM se inativa >3 dias.
4. Snapshots antes de experiências destrutivas.
5. Alerta de custo a $50.

---

## 8. Cadência e Estimativas

### 8.1 Estimativa total
| Fase | Esforço ativo | Wall-clock razoável |
|---|---|---|
| Fase 2 | 22–37h | 2–3 semanas |
| Fase 3 | 20–31h | 2–3 semanas |
| Fase 4 | 16–25h | 1–2 semanas |
| **Total** | **58–93h** | **5–8 semanas** |

### 8.2 Pontos de review do utilizador
- **Passo 1**: protocolo fixa tudo o resto. Review cuidado.
- **Passo 3**: modelo de sessão é estrutural.
- **Passo 4b**: segurança vive ou morre aqui.
- **Passo 5**: enforcement de roles é onde o modelo de ameaças se materializa.
- **Passo 11**: migração Gramine é point-of-no-return.
- **Passo 16**: DCAP tem nuances jurídicas/de trust.

Review "ok, ship it" chega para: 2, 4a, 6, 7, 8, 10, 13, 14, 17, 18.

### 8.3 Pontos de aceitação ao fim de cada passo
1. Código compila e passa critérios de sucesso.
2. Sem TODO/FIXME/hacks.
3. Debug logs temporários removidos.
4. Commit com mensagem descritiva.

---

## 9. Gestão de Risco

| Risco | Prob. | Impacto | Mitigação |
|---|---|---|---|
| ECDH cross-impl falha (OpenSSL ↔ sgx_tcrypto) | Alta | Bloqueante | Test vectors; logar shared secret temporariamente |
| ECDSA verify no enclave dá problemas (formato da pubkey) | Média | Médio | Testar com keypair conhecida antes de integrar JSON |
| JSON parsing corrompe estrutura no host | Baixa | Baixo | Validar campos obrigatórios; testar com JSON malformado |
| Gramine manifest precisa iterações | Alta | Médio | Prototipar DuckDB fora do enclave primeiro |
| DCAP cert chain desatualizada | Média | Médio | Atualizar PCCS antes; fallback Azure AS |
| EPC paging com dataset grande | Média | Médio | Benchmarks N=10K/100K/1M; documentar |
| Crédito Azure esgota | Baixa | Alto | Auto-shutdown; alertas; destruir se >3 dias inativo |
| SSH disconnect durante long build | Média | Baixo | tmux sempre |
| Debug no enclave sem stdout | Média | Médio | OCALL logging abundante |

---

## 10. Estrutura Final do Projeto (Alvo)

```
poc/
├── PLANO_FINAL.md               # este documento
├── relatorio_data_lake_sgx.pdf  # atualizado no fim
├── README.md
├── CLAUDE.md
├── Makefile                     # targets: sgx_server, sgx_client, enclave.signed.so
├── setup_azure.sh
├── authorized_parties.json      # registo de participantes com roles
├── scripts/
│   └── gen_identity.sh          # gera keypair long-term para um participante
├── parties/                     # .gitignore'd
│   ├── hosp-santa-maria.key
│   ├── hosp-santa-maria.pub
│   ├── fcup-research.key
│   ├── fcup-research.pub
│   ├── insa.key
│   ├── insa.pub
│   └── ...
├── Client/
│   ├── client_main.cpp          # CLI: attest, upload, query
│   ├── attestation_sim.cpp      # Fase 2 (local SIM)
│   ├── attestation_dcap.cpp     # Fase 4 (HW real)
│   ├── attestation.h
│   ├── secure_channel.cpp/h
│   ├── crypto.cpp/h             # OpenSSL: AES-256-GCM, P-256 ECDH+ECDSA, HKDF
│   ├── identity.cpp/h           # load long-term keypair
│   └── csv_loader.cpp/h
├── Server/
│   ├── server_main.cpp          # TCP listen + dispatcher
│   ├── session_manager.cpp/h    # threading, cleanup
│   └── parties_loader.cpp/h     # lê JSON, serializa para enclave
├── Enclave/                     # SDK (Fase 2); removido na Fase 3
│   ├── Enclave.cpp
│   ├── Enclave.edl
│   ├── Enclave.config.xml
│   └── Enclave_private.pem
├── EnclaveLogic/                # Core C puro, agnóstico de SDK/Gramine
│   ├── session.cpp/h
│   ├── parties.cpp/h            # find_party, check authorization
│   ├── query_engine.cpp/h       # agregações Fase 2; DuckDB Fase 3
│   ├── kanon.cpp/h              # threshold_for(role)
│   └── sealing.cpp/h
├── EnclaveGramine/              # Fase 3
│   ├── gramine_main.cpp
│   └── server.manifest.template
├── Common/
│   ├── protocol.h
│   ├── framing.cpp/h
│   └── tcp_util.cpp/h
├── Include/
│   ├── types.h                  # PatientRecord
│   └── party.h                  # AuthorizedParty, PartyRole
├── data/
│   ├── hospital_0.csv
│   ├── hospital_1.csv
│   ├── hospital_2.csv
│   └── sealed/                  # .gitignore'd
├── benchmarks/
│   ├── bench.sh
│   └── results.md
└── docs/
    ├── architecture.png
    └── phases.md
```

---

## 11. Convenções e Decisões Fixas

**Para retomar sem dúvidas numa nova conversa**:

1. **Língua**: respostas em Português de Portugal. Código, commits e comentários inline em Inglês.
2. **Stack enclave**: Intel SGX SDK até fim da Fase 2; Gramine a partir da Fase 3.
3. **Transporte**: TCP binário puro. Sem TLS (justificado em 5.2).
4. **Canal seguro pós-KEX**: AES-256-GCM com seq num anti-replay. GCM tag autentica; sem HMAC separado.
5. **Chaves**: P-256 para ECDH efémero *e* para identidade long-term (ECDSA). HKDF-SHA256 para derivar session_key + iv_prefix.
6. **Identidade e roles**: `authorized_parties.json` estático. 3 papéis: `HOSPITAL`, `RESEARCHER`, `HEALTH_AUTHORITY`. Revogação via flag no JSON.
7. **Autorização**: HOSPITAL pode upload+query (K≥5); RESEARCHER só query (K≥5); HEALTH_AUTHORITY só query (K≥3).
8. **k-anonymity**: thresholds configuráveis via macro `K_ANON_DEFAULT=5` e `K_ANON_AUTHORITY=3`.
9. **Audit log**: não implementado nesta milestone. Documentado como future work.
10. **Hardware**: dev local em SIM para Fases 1+2; Azure DCsv3 para Fases 3+4 e benchmarks.
11. **Princípio de código**: lógica core em C puro agnóstico de `sgx_*`. Só wrappers tocam em SDK/Gramine.
12. **Memory do assistant**: `/home/afartur/.claude/projects/-home-afartur-Documents-MSI-2S-SAHC-poc/memory/` — `language_portuguese.md`, `milestone2_scope.md`.
13. **Não criar ficheiros .md extra** durante desenvolvimento sem pedido explícito.

---

## 12. Próximo Passo Imediato

**Arrancar pelo Passo 1 da Fase 2**: scaffolding do protocolo e reorganização do build.

Entregáveis do Passo 1:
- `Include/protocol.h` (enum `MessageType`, enum `ErrorCode`)
- `Include/party.h` (`AuthorizedParty`, `PartyRole`)
- `Common/framing.cpp/h`
- `Common/tcp_util.cpp/h`
- Renomear `App/` → `Server/`, criar `Client/` com esqueleto.
- Makefile reorganizado com 3 targets.
- Teste "hello" round-trip cliente-servidor.

**Para retomar em conversa nova**:
> "Lê o `PLANO_FINAL.md` na raiz do projeto. Retoma o desenvolvimento a partir do Passo 1 da Fase 2."
