# Correr e validar em hardware Intel SGX

Setup, build, testes esperados, bench e troubleshooting para correr o
protótipo numa máquina com Intel SGX habilitado. O caminho DCAP nunca
correu fim-a-fim contra um quoting enclave real durante o
desenvolvimento — este guia é deliberadamente determinístico para que
qualquer falha seja fácil de isolar entre bug de código e problema de
setup.

---

## 1. Pré-requisitos de hardware/SO

- CPU Intel com SGX habilitado na BIOS (geração ≥ Coffee Lake; ideal
  Ice Lake-SP / DCsv3 com FLC).
- Linux com drivers in-kernel `/dev/sgx_enclave` e `/dev/sgx_provision`
  (kernel ≥ 5.11).
- Utilizador no grupo `sgx_prv`.
- DCAP infra: `libsgx-dcap-quote-verify-dev`, `libsgx-dcap-default-qpl`,
  `libsgx-urts`, `libsgx-dcap-ql`.
- PCCS configurado em `/etc/sgx_default_qcnl.conf` (Azure expõe um por
  região; on-prem corre-se um local).
- Gramine 1.9 (para o caminho `gramine_server`).

Verificar antes de continuar:
```bash
ls -l /dev/sgx_enclave /dev/sgx_provision   # ambos têm de existir
groups | grep -E 'sgx_prv'                  # utilizador no grupo
dpkg -l | grep -E 'libsgx-dcap|libsgx-urts'
cat /etc/sgx_default_qcnl.conf | head -5    # PCCS endpoint
gramine-sgx --version                       # 1.9.x
```

Se algum destes falhar, parar aqui — os testes seguintes vão produzir
erros derivados e dificultar o diagnóstico.

## 2. Build

```bash
git clone <repo> sahc && cd sahc
source /opt/intel/sgxsdk/environment
./scripts/fetch_duckdb.sh
./scripts/gen_identity.py             # se ainda não existirem em parties/
./scripts/build_authorized_parties.py
gramine-sgx-gen-private-key           # se ainda não existir

make clean
make hw                                # all-in-one: SDK + Gramine + assina + pin Gramine
```

`make hw` é equivalente a:
```bash
make SGX_MODE=HW SAHC_HW=1 gramine_server gramine_manifest_hw
make SGX_MODE=HW SAHC_HW=1 sgx_server sgx_client
```
e regenera `Include/expected_mrenclave_gramine.h` (extraído de
`gramine_server.sig`) — é com este pin que o cliente compara em HW.

**Esperado:** todos os comandos terminam com exit 0. Para builds
incrementais durante desenvolvimento, as variantes detalhadas
continuam a funcionar isoladamente.

`SAHC_HW=1` activa o switch DCAP:
- Servidor Gramine lê `/dev/attestation/{user_report_data,quote}` e
  envia `sgx_quote3_t` real (`PROTO_QUOTE_FORMAT_DCAP=0x01`).
- Cliente parseia o `sgx_quote3_t`, chama `sgx_qv_verify_quote()` da
  QvL, valida cadeia + binding `report_data` + MRENCLAVE pin.

## 3. Caminho A — SGX-SDK (`sgx_server`)

### A.1 Sanity MRENCLAVE
```bash
./sgx_server --print-mrenclave
sha256sum Include/expected_mrenclave.h
```
**Esperado:** o hex impresso bate com o array em `expected_mrenclave.h`.
Se não bater → problema na geração do header.

### A.2 Run
```bash
rm -f data/sealed/state.bin              # se herdado do SIM
./sgx_server 127.0.0.1 7878 &
./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```
**Esperado:** sucesso (`Server: state persisted`, `UPLOAD_ACK`).

### A.3 Limitação conhecida
```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```
**Esperado: falha**. Razão: o `sgx_server` (caminho SDK) emite o quote
artesanal SAHC mesmo em HW; passar a DCAP real exigiria
`sgx_qe_get_quote()` dentro do enclave — fora do escopo desta
entrega. **Não é regressão.** O caminho que faz DCAP real é o
**Gramine** (§4).

## 4. Caminho B — Gramine-SGX (`gramine_server`) *(o teste principal)*

### B.1 Bring-up

Apagar sealed blob herdado do SIM/SDK (formato incompatível):
```bash
rm -f data/sealed/state.bin
gramine-sgx gramine_server 127.0.0.1 7878
```

**Esperado:** `parties loaded — 3 hospitals, 1 researchers`. Sem
warnings sobre `/dev/attestation absent` (esses só aparecem em
`gramine-direct`).

### B.2 Upload + query com DCAP forçado

```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria   data/hospital_0.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-sao-joao      data/hospital_1.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santo-antonio data/hospital_2.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```

**Esperado para CADA cliente:**
```
Client: ATTEST_RESP received (...) bytes
quote_verify: DCAP chain OK + binding OK + MRENCLAVE pin OK
Server: state persisted
```

**Servidor imprime:**
```
DCAP: quote read OK (~4096 bytes)         # tamanho exacto varia
```

**Query final:** `result=49.143 matched=15 applied_k=5` (igual ao SIM,
mas com o caminho DCAP a sério por baixo).

### B.3 Falhas de propósito (validar enforcement)

MRENCLAVE errado deve recusar:
```bash
SAHC_EXPECTED_MRENCLAVE=$(printf 'aa%.0s' {1..32}) \
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** `quote_verify: MRENCLAVE mismatch vs env override`.

Cliente sem `SAHC_HW=1` contra servidor HW deve recusar (anti-downgrade):
```bash
# rebuild client without SAHC_HW=1 first
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** `quote_verify: DCAP format received (qlen=...) but this
build does not include the DCAP verifier — Refusing.`

### B.4 K-anonymity
```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg pneumonia
```
**Esperado:** `E_INSUFFICIENT_RECORDS` se < 5 matches.

### B.5 Persistência

Matar o servidor (Ctrl-C), re-arrancar **sem** apagar nada:
```bash
gramine-sgx gramine_server 127.0.0.1 7878
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** servidor imprime `Server: state loaded from sealed blob`;
query devolve o mesmo `49.143` sem precisar de re-upload. Se o blob
não desselar é regressão — a sealing key derivada de
`/dev/attestation/keys/_sgx_mrenclave` é o ponto crítico para
sobreviver a restart.

## 5. Diferenças efectivas direct → sgx

| Aspecto                   | gramine-direct (dev)            | gramine-sgx (HW)                                   |
|---------------------------|---------------------------------|----------------------------------------------------|
| MRENCLAVE / MRSIGNER      | placeholder `0xDE`*32           | real via `/dev/attestation/{mrenclave,mrsigner}`   |
| Sealing key               | fixa DEV-ONLY (warning loud)    | PSW-derivada via `/dev/attestation/keys/_sgx_mrenclave` |
| Quote                     | stub (não verificável)          | DCAP real (`sgx.remote_attestation = "dcap"`)       |
| `SAHC_REQUIRE_DCAP`       | tem de ser 0 / unset            | **1** (recusa-se a correr sem DCAP)                |
| `SAHC_EXPECTED_MRENCLAVE` | tem de ser `''` (pin não bate)  | unset (cliente pina contra `.sig` do build HW)     |
| Sealed blob compatível?   | só direct ↔ direct              | só sgx ↔ sgx (apagar `data/sealed/state.bin`)      |

## 6. Bench
```bash
make sgx_bench
rm -f data/sealed/state.bin
gramine-sgx gramine_server 127.0.0.1 7878 &
SAHC_REQUIRE_DCAP=1 ./sgx_bench > bench-hw.md
```
Output: handshake p50/p95/p99, upload throughput por batch, query
latency. Comparar com `bench-sim.md` para quantificar overhead
DCAP + EPC.

## 7. Diagnóstico de falhas

Quando um teste falha, recolher:
1. Comando exacto.
2. Output completo do cliente e do servidor (stdout + stderr).
3. `dmesg | tail -50` se houver suspeita de driver SGX.
4. `cat /etc/sgx_default_qcnl.conf` (sem secrets).
5. Versões: `gramine-sgx --version`, `dpkg -l | grep sgx`.

## 8. Tolerância a falhas

Ver §10 de [`PLANO_FINAL.md`](../PLANO_FINAL.md) — cobre recuperação
de queda (sealed state + restart), rotação de chaves comprometidas,
comportamento sob TCP timeout, decrypt failure, k-anon insuficiente.

## 9. Troubleshooting

| Sintoma                                                | Causa / Solução                                              |
|--------------------------------------------------------|--------------------------------------------------------------|
| `aesm_service` / `SGX_ERROR_NO_DEVICE`                 | drivers in-kernel ausentes ou utilizador sem grupo `sgx_prv` |
| `gramine-sgx: enclave-key.pem not found`               | correr `gramine-sgx-gen-private-key` uma vez                 |
| `quote_verify: MRENCLAVE mismatch`                     | binário recompilado sem `make clean`, ou mistura SIM/HW      |
| `unseal failed` ao arrancar                            | trocou-se de backend → `rm data/sealed/state.bin`            |
| `sgx_qv_verify_quote 0x...A001` (NO_QPL)               | falta `libsgx-dcap-default-qpl`                              |
| `sgx_qv_verify_quote 0x...A002` (CRL_UNAVAILABLE)      | PCCS unreachable / `qcnl.conf` errado                        |
| `qv_result rejected 0xA006` (OUT_OF_DATE)              | TCB do CPU desactualizado — fazer microcode update           |
| `qv_result rejected 0xA00C` (REVOKED)                  | PCK revogada — máquina banida do TCB                         |
| `DCAP report_data binding mismatch`                    | bug de código — capturar hexdump do quote para diagnóstico   |
