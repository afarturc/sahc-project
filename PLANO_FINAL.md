# Plano Final — Milestone 2

Plano objetivo para a Milestone 2 do projeto SAHC (FCUP 2025/26). Fonte de verdade para scope, decisões e próximos passos. Ver `docs/milestone1/relatorio.pdf` para contexto completo da arquitetura.

## 1. Objetivo

Cumprir as fases 2–4 descritas na secção 6 do relatório, partindo do protótipo da Fase 1 (tag `v1.0-milestone1`):

- **Fase 2** — cliente/servidor TCP, multi-sessão, ECDH, identidades com roles, sealing, k-anonymity.
- **Fase 3** — migração para Gramine + DuckDB (SQL real).
- **Fase 4** — atestação DCAP real em hardware Azure DCsv3, benchmarks finais.

Entregáveis finais: `sgx_server` + `sgx_client` funcionais em HW, `authorized_parties.json`, benchmarks, relatório atualizado, repo tagged `v2.0-final`.

## 2. Modelo de Entidades

Dois papéis:

| Role | Upload | Query | K-anon |
|---|---|---|---|
| `HOSPITAL` | sim | sim | 5 |
| `RESEARCHER` | não | sim | 5 |

**Identidade**: ECDSA P-256 long-term keypair por participante, gerada via `scripts/gen_identity.sh` e guardada em `parties/<id>.{key,pub}`.

**Admissão por quorum**: hospitais são founders (entram no JSON diretamente). Investigadores só são aceites se reunirem `M=2` assinaturas válidas de hospitais sobre `SHA256(researcher_id || researcher_pubkey)`. O enclave valida o quórum ao carregar o JSON e ignora entradas que não cumpram.

**`authorized_parties.json`** (formato):
```json
{
  "version": 1,
  "quorum_m": 2,
  "hospitals": [
    { "id": "hosp-santa-maria", "pubkey": "<hex 64B>" },
    { "id": "hosp-sao-joao",    "pubkey": "<hex 64B>" },
    { "id": "hosp-santo-antonio","pubkey": "<hex 64B>" }
  ],
  "researchers": [
    {
      "id": "fcup-research",
      "pubkey": "<hex 64B>",
      "approvals": [
        { "hospital_id": "hosp-santa-maria", "signature": "<hex 64B>" },
        { "hospital_id": "hosp-sao-joao",    "signature": "<hex 64B>" }
      ]
    }
  ]
}
```

Assinatura sobre `SHA256("SAHC-approve-v1" || researcher_id || researcher_pubkey)` com a chave long-term do hospital.

**Migração enclave→enclave**: quando o enclave reinicia, sealing blob (parties + registos) sobrevive em disco e é desselado pelo novo enclave (mesmo MRENCLAVE). Clientes reconectam e re-atestam transparentemente.

## 3. Decisões Arquiteturais

- **Stack**: C/C++, Intel SGX SDK até fim da Fase 2; Gramine a partir da Fase 3; OpenSSL do lado untrusted; `sgx_tcrypto` / mbedTLS dentro do enclave; DuckDB embed na Fase 3.
- **Canal seguro**: atestação + ECDH (P-256, HKDF-SHA256, AES-256-GCM). Sem TLS explícito — a atestação do enclave autentica o servidor e a identidade long-term autentica o cliente.
- **Lógica de negócio agnóstica de SDK**: sessões, roles, k-anon, quorum e crypto aplicada vivem em `EnclaveLogic/` (C puro) para que a migração Gramine toque só nos wrappers.
- **Infraestrutura**: desenvolvimento local em `SGX_MODE=SIM` para Fases 1+2; Azure DCsv3 spot para Fases 3+4. Orçamento ~$30 do crédito de $100.

## 4. Wire Protocol

**Frames:**
```
Pré-KEX:  [type(1) | len(4 BE) | payload(N)]
Pós-KEX:  [type(1) | len(4 BE) | seq(8) | iv(12) | ciphertext(N) | tag(16)]
```

**Message types:**
| Code | Nome | Dir | Payload |
|---|---|---|---|
| 0x01 | `ATTEST_REQ` | C→S | party_id_len(1) + party_id + nonce(16) + client_ecdh_pubkey(64) + signature(64) |
| 0x02 | `ATTEST_RESP` | S→C | quote(var) + enclave_ecdh_pubkey(64) |
| 0x03 | `KEY_CONFIRM` | C→S | HMAC(session_key, "confirm") |
| 0x04 | `KEY_ACK` | S→C | status(1) + assigned_role(1) |
| 0x05 | `UPLOAD` | C→S | record_count(4) + records(N)  *(enc)* |
| 0x06 | `UPLOAD_ACK` | S→C | records_accepted(4)  *(enc)* |
| 0x07 | `QUERY_REQ` | C→S | query_spec  *(enc)* |
| 0x08 | `QUERY_RESP` | S→C | result(16) + matched_count(4) + applied_k(1)  *(enc)* |
| 0x10 | `HELLO` | C→S | string (só para bring-up) |
| 0x11 | `HELLO_ACK` | S→C | string (só para bring-up) |
| 0xFE | `SESSION_CLOSE` | C→S | — |
| 0xFF | `ERROR` | S→C | code(2) + msg(N) |

**Error codes**: `E_OK`, `E_INVALID_STATE`, `E_DECRYPT_FAIL`, `E_REPLAY`, `E_UNAUTHORIZED`, `E_UNKNOWN_PARTY`, `E_REVOKED`, `E_BAD_SIGNATURE`, `E_INSUFFICIENT_RECORDS`, `E_BAD_NONCE`, `E_INTERNAL`.

**HKDF**:
```
PRK         = HMAC-SHA256(salt="SAHC-v1", ikm=ecdh_shared_secret)
session_key = HMAC-SHA256(PRK, "session-aes256" || 0x01)[0:32]
iv_prefix   = HMAC-SHA256(PRK, "iv-prefix"      || 0x01)[0:4]
```
IV = `iv_prefix (4) || seq (8, BE)` — 12 bytes. AAD = cabeçalho do frame.

## 5. Plano de Trabalho

### Fase 2 — SIM mode, local

| # | Passo | Esforço |
|---|---|---|
| 1 | Scaffolding: `Include/{protocol,party}.h`, `Common/{framing,tcp_util}`, `Server/`, `Client/`, Makefile 3 targets. Hello round-trip TCP. | 1–2h |
| 2 | Servidor TCP + dispatcher (sem crypto); cliente envia `ATTEST_REQ`, recebe `ATTEST_RESP`. | 2–3h |
| 3 | Multi-sessão no enclave: `SessionContext[]` indexado por handle. | 3–4h |
| 4a | Loader de `authorized_parties.json` com verificação de quórum. | 2–3h |
| 4b | ECDH + identidade + canal seguro: AES-256-GCM, HKDF, assinatura ECDSA do cliente verificada pelo enclave. | 5–8h |
| 5 | Enforcement role-based (HOSPITAL pode upload+query; RESEARCHER só query). | 1–2h |
| 6 | Sealing + persistência (parties + registos) → migração transparente entre reinícios. | 3–4h |
| 7 | K-anonymity threshold = 5 em todas as queries. | 30min |
| 8 | Robustecimento (timeouts, backpressure, erros) + benchmarks locais. | 3–4h |
| 9 | Smoke test em hardware real na Azure (ainda sem DCAP). | 3h |

**Critério Fase 2**: dois clientes (hospital + investigador) atestam, estabelecem sessões independentes, o hospital faz upload, o investigador faz query agregada, resultados corretos e k-anon enforced. Sealing sobrevive a restart.

| # | Passo | Esforço |
|---|---|---|
| 1 | Scaffolding: `Include/{protocol,party}.h`, `Common/{framing,tcp_util}`, `Server/`, `Client/`, Makefile 3 targets. Hello round-trip TCP. | 1–2h |
| 2 | Servidor TCP + dispatcher (sem crypto); cliente envia `ATTEST_REQ`, recebe `ATTEST_RESP`. | 2–3h |
| 3 | Multi-sessão no enclave: `SessionContext[]` indexado por handle. | 3–4h |
| 4a | Loader de `authorized_parties.json` com verificação de quórum. | 2–3h |
| 4b | ECDH + identidade + canal seguro: AES-256-GCM, HKDF, assinatura ECDSA do cliente verificada pelo enclave. | 5–8h |
| 5 | Enforcement role-based (HOSPITAL pode upload+query; RESEARCHER só query). | 1–2h |
| 6 | Sealing + persistência (parties + registos) → migração transparente entre reinícios. | 3–4h |
| 7 | K-anonymity threshold = 5 em todas as queries. | 30min |
| 8 | Robustecimento (timeouts, backpressure, erros) + benchmarks locais. | 3–4h |
| 9 | Smoke test em hardware real na Azure (ainda sem DCAP). | 3h |

**Critério Fase 2**: dois clientes (hospital + investigador) atestam, estabelecem sessões independentes, o hospital faz upload, o investigador faz query agregada, resultados corretos e k-anon enforced. Sealing sobrevive a restart.

### Fase 3 — Gramine + DuckDB

| # | Passo | Esforço |
|---|---|---|
| 10 | Setup Gramine em Azure DCsv3. | 4–6h |
| 11 | Migrar servidor para Gramine (substitui ECALLs por chamadas diretas; wrappers finos). | 6–10h |
| 12 | Integrar DuckDB em memória dentro do enclave; schema `patients`. | 6–10h |
| 13 | Cliente suporta SQL arbitrário com allowlist de agregações. | 2–3h |
| 14 | Mitigar timing side-channels em queries críticas. | 2h |

**Critério Fase 3**: queries SQL (`SELECT AVG(glucose) FROM patients WHERE diagnosis='diabetes'`) executam no enclave com k-anon.

### Fase 4 — DCAP real + benchmarks

| # | Passo | Esforço |
|---|---|---|
| 15 | Quote DCAP real no servidor (via `sgx_qe_*` ou Azure Attestation). | 3–4h |
| 16 | Verificação DCAP completa no cliente (cadeia Intel → PCCS local). | 4–6h |
| 17 | Limpeza de paths de simulação. | 1h |
| 18 | Benchmarks finais em HW (latência KEX, throughput upload, latência query). | 3–5h |
| 19 | Atualizar relatório + README + criar tag `v2.0-final`. | 5–8h |

**Estimativa total**: 60–90h de desenvolvimento ao longo de ~8–10 semanas.

## 6. Estrutura Alvo do Projeto

```
poc/
├── PLANO_FINAL.md
├── README.md
├── CLAUDE.md
├── Makefile
├── authorized_parties.json
├── scripts/gen_identity.sh
├── parties/                  # .gitignore'd
├── Client/                   # client_main, attestation, secure_channel, crypto, identity, csv_loader
├── Server/                   # server_main, session_manager, parties_loader
├── Enclave/                  # SDK wrapper (Fase 2); substituído por EnclaveGramine na Fase 3
├── EnclaveLogic/             # core C puro (session, parties, kanon, query_engine, sealing)
├── EnclaveGramine/           # Fase 3
├── Common/                   # protocol helpers (framing, tcp_util)
├── Include/                  # types.h, protocol.h, party.h
├── data/                     # CSVs + sealed/ (.gitignore'd)
├── benchmarks/
└── docs/                     # milestone1/, diagrams/, refs/
```

## 7. Setup Azure (Fase 3+)

- VM: Standard DC2s_v3 (Ubuntu 20.04, 2 vCPU, 16GB RAM) — spot para poupar.
- Instalar: Intel SGX DCAP drivers, Gramine, DuckDB.
- Script `setup_azure.sh` automatiza a provisão.
- Desligar a VM entre sessões (pay-per-minute).

## 8. Convenções

- Respostas em Português de Portugal; código, commits e comentários inline em Inglês.
- Branch `master`; commits atómicos; tags em marcos (`v1.0-milestone1` já existe, `v2.0-final` no fim).
- Makefile tem `make all`, `make clean`, `make sgx_server`, `make sgx_client`, `make enclave`.

## 9. Próximo Passo Imediato

**Passo 1 (scaffolding)** — reorganizar para `Server/`/`Client/`/`Common/`, criar `Include/{protocol,party}.h` já com 2 roles, fazer hello round-trip TCP sem crypto, enclave.signed.so continua a ser build target.
