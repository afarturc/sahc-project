# SIM → HW: correr o protótipo em Intel SGX real

Este documento é o passo-a-passo para clonar o repositório numa máquina
Intel com SGX e correr o protótipo em hardware. Cobre os **dois caminhos**
do servidor:

- **SGX-SDK** (`sgx_server`) — usa o enclave assinado tradicional.
- **Gramine-SGX** (`gramine_server`) — usa o LibOS Gramine + DuckDB.

O cliente é o mesmo nos dois casos.

---

## 0. Pré-requisitos de hardware/SO

- CPU Intel com SGX habilitado na BIOS (geração ≥ Coffee Lake; ideal
  Ice Lake-SP / DCsv3 com FLC).
- Linux com drivers in-kernel `/dev/sgx_enclave` e `/dev/sgx_provision`
  (kernel ≥ 5.11). Confirmar:
  ```bash
  ls -l /dev/sgx_enclave /dev/sgx_provision
  ```
- Utilizador no grupo `sgx_prv` (acesso ao provision device).
- DCAP infra para attestation real:
  - `libsgx-dcap-quote-verify`, `libsgx-dcap-default-qpl`, `libsgx-urts`
  - PCCS configurado (`/etc/sgx_default_qcnl.conf` a apontar para um PCCS
    válido — Azure expõe um por região; on-prem corre-se um local).

## 1. Build comum

```bash
git clone <repo> && cd Project
source /opt/intel/sgxsdk/environment        # se for usar o SGX-SDK path
./scripts/fetch_duckdb.sh                   # libduckdb.so (~57 MB)
./scripts/gen_identity.py                   # parties/* (apenas se ainda não existirem)
./scripts/build_authorized_parties.py       # authorized_parties.json
```

## 2. Caminho A — SGX-SDK em HW

```bash
make clean
make SGX_MODE=HW                            # liga sgx_urts/sgx_trts (não _sim)
```

O Makefile corre automaticamente `scripts/extract_mrenclave.sh`, que faz
parse do output de `sgx_sign dump` do `enclave.signed.so` HW e regenera
`Include/expected_mrenclave.h` com o MRENCLAVE real. **Não há valores
hardcoded** — o pin é sempre o do binário recém-construído.

Sanity check em runtime:

```bash
./sgx_server --print-mrenclave              # imprime o que o enclave reporta
diff <(./sgx_server --print-mrenclave) Include/expected_mrenclave.h
```

Os dois valores têm de coincidir.

Correr:

```bash
./sgx_server 127.0.0.1 7878
# noutro terminal:
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```

`SAHC_REQUIRE_DCAP=1` força o cliente a verificar a cadeia DCAP completa
(stage QE chain → `sgx_qv_verify_quote()`). Em SIM esta flag faz o cliente
recusar; em HW é o modo de produção.

⚠️ **Sealed blob é incompatível entre SIM e HW** (a sealing key é diferente
porque o enclave linka contra libs distintas, mudando o MRENCLAVE):
```bash
rm -f data/sealed/state.bin   # uma vez, na transição
```

## 3. Caminho B — Gramine-SGX em HW

Pré-requisito extra: chave SGX para assinar o enclave Gramine.
```bash
gramine-sgx-gen-private-key                 # gera ~/.config/gramine/enclave-key.pem
```

Build + manifest **HW**:

```bash
make clean
make SAHC_HW=1 gramine_server               # emite quote DCAP real
make SAHC_HW=1 sgx_client                   # linka -lsgx_dcap_quoteverify
make gramine_manifest_hw                    # debug=false, host_env explícito
```

`SAHC_HW=1` é o switch que activa o DCAP real:
- Servidor lê `/dev/attestation/{user_report_data,quote}` e envia o
  `sgx_quote3_t` real (formato `PROTO_QUOTE_FORMAT_DCAP=0x01`).
- Cliente parseia o `sgx_quote3_t`, chama `sgx_qv_verify_quote()` da
  QvL, valida cadeia + binding + MRENCLAVE pin.

Pré-requisito Debian/Ubuntu: `apt install libsgx-dcap-quote-verify-dev`.

Diferenças vs `gramine_manifest` (dev):
- `sgx.debug = false` — sem inspecção `gdb-sgx`
- Sem `loader.insecure__use_host_env` wildcard; só passam
  `SAHC_REQUIRE_DCAP` e `SAHC_EXPECTED_MRENCLAVE`
- `log_level = error` (default já era)
- O sign step **não** é tolerado a falhar (em dev é, em HW abortamos).

Correr:

```bash
gramine-sgx gramine_server 127.0.0.1 7878
```

Nota: usa-se `gramine-sgx`, **não** `gramine-direct`. O segundo é o smoke
sem enclave (CPU normal, identity/seal caem para placeholders DEV).

### Diferenças efectivas direct → sgx

| Aspecto                        | gramine-direct (dev)               | gramine-sgx (HW)                                   |
|--------------------------------|------------------------------------|----------------------------------------------------|
| MRENCLAVE / MRSIGNER           | placeholder `0xDE`*32              | real, via `/dev/attestation/{mrenclave,mrsigner}`  |
| Sealing key                    | fixa DEV-ONLY (warning loud)       | derivada PSW via `/dev/attestation/keys/_sgx_mrenclave` |
| Quote                          | stub (não verificável)             | DCAP real (`sgx.remote_attestation = "dcap"`)       |
| `SAHC_REQUIRE_DCAP`            | tem de ser 0 (ou unset)            | **1** (recusa-se a correr sem DCAP)                |
| `SAHC_EXPECTED_MRENCLAVE`      | tem de ser `''` (pin não bate)     | unset (o cliente pina contra o `.sig` do build HW) |
| Sealed blob compatível?        | só direct ↔ direct                 | só sgx ↔ sgx (apagar `data/sealed/state.bin`)      |

Cliente em HW:

```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```

Sem o env override `SAHC_EXPECTED_MRENCLAVE=''` — o pin agora é o real.

## 4. Bench em HW

```bash
make sgx_bench
rm -f data/sealed/state.bin                 # snapshot fresco
./sgx_server 127.0.0.1 7878 &               # ou ./gramine_server
SAHC_REQUIRE_DCAP=1 ./sgx_bench
```

Output em markdown — handshake p50/p95/p99, throughput de upload por
batch, latência de query. Comparar com `bench-sim.md` (SIM) para
quantificar o overhead de DCAP + EPC.

## 5. Tolerância a falhas

Ver §10 de `PLANO_FINAL.md` — cobre:
- Recuperação de queda (sealed state + restart),
- Manuseio de chaves comprometidas (rotação `authorized_parties.json`),
- Comportamento sob TCP timeout, decrypt failure, k-anon insuficiente.

## 6. Troubleshooting rápido

| Sintoma                                              | Causa provável                                          |
|------------------------------------------------------|---------------------------------------------------------|
| `aesm_service`/`SGX_ERROR_NO_DEVICE`                 | drivers in-kernel ausentes ou utilizador sem grupo      |
| `quote_verify: DCAP signature chain NOT verified`    | `SAHC_REQUIRE_DCAP=0`; em HW pôr `=1`                   |
| `quote_verify: MRENCLAVE mismatch`                   | binário recompilado sem `make clean`; ou mistura SIM/HW |
| `unseal failed` ao arrancar                          | trocou-se de backend (SDK↔Gramine) ou de enclave —      |
|                                                      | apagar `data/sealed/state.bin`                          |
| `gramine-sgx: enclave-key.pem not found`             | correr `gramine-sgx-gen-private-key` uma vez            |
| PCCS unreachable / `qpl: failed to get quote`        | `/etc/sgx_default_qcnl.conf` mal configurado            |
