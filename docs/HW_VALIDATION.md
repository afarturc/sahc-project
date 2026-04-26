# HW validation runbook

Documento operacional para o colega que vai correr o protótipo numa
máquina Intel real. Parte do princípio que `docs/SIM_TO_HW.md` foi
seguido para o setup. Aqui está o que **deve passar**, o que **deve
falhar de propósito**, e como **reportar resultados** sem ambiguidade.

> O autor não tem hardware Intel SGX, por isso o código DCAP nunca
> correu fim-a-fim contra um quoting enclave real. O objectivo deste
> documento é tornar o trabalho de validação determinístico — se algum
> teste falhar, é fácil isolar se o problema é nosso ou de setup.

## 0. Confirmar setup antes de testar

```bash
ls -l /dev/sgx_enclave /dev/sgx_provision   # ambos têm de existir
groups | grep -E 'sgx_prv'                  # utilizador no grupo
dpkg -l | grep -E 'libsgx-dcap-quote-verify-dev|libsgx-dcap-default-qpl|libsgx-urts'
cat /etc/sgx_default_qcnl.conf | head -5    # PCCS endpoint configurado
```

Se algum destes falhar, **parar e reportar** — não tentar correr os
testes. Os erros que vão surgir vão ser ruído.

## 1. Build SGX-SDK + Gramine, ambos em HW

```bash
git clone <repo> sahc && cd sahc
source /opt/intel/sgxsdk/environment
./scripts/fetch_duckdb.sh
./scripts/gen_identity.py             # se ainda não existirem em parties/
./scripts/build_authorized_parties.py
make clean
make SGX_MODE=HW                       # SDK path: sgx_server, sgx_client, enclave
make SAHC_HW=1 gramine_server          # Gramine path: emite DCAP real
make gramine_manifest_hw               # debug=false, host_env explícito
gramine-sgx-gen-private-key            # se ainda não existir
gramine-sgx-sign --manifest gramine_server.manifest \
                 --output gramine_server.manifest.sgx
```

**Esperado:** todos os comandos terminam com exit 0. O Makefile
regenera `Include/expected_mrenclave.h` automaticamente para o SDK
path.

**Se falhar:** reportar a saída completa do comando que falhou.

## 2. Teste A — SDK path (sgx_server) em HW

### A.1 Sanity MRENCLAVE

```bash
./sgx_server --print-mrenclave
sha256sum Include/expected_mrenclave.h
```

**Esperado:** o hex impresso bate com o array em
`expected_mrenclave.h`. Se não bater → problema na geração do header.

### A.2 Handshake DCAP

```bash
./sgx_server 127.0.0.1 7878 &
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```

**Esperado neste momento:** **falha**. Razão: o `sgx_server` (caminho
SDK) ainda emite o quote artesanal SAHC; o cliente em modo
`SAHC_REQUIRE_DCAP=1` recusa porque a stage QE chain está stub no
caminho SAHC. Não é regressão — é decisão arquitectural. Para validar
o caminho SDK em HW correr **sem** `SAHC_REQUIRE_DCAP`:

```bash
./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```

**Esperado:** sucesso (`Server: state persisted`, `UPLOAD_ACK`).

> Para fazer DCAP real no caminho SDK seria preciso `sgx_qe_get_quote()`
> dentro do enclave — fora do escopo desta entrega. O caminho que faz
> DCAP real é o **Gramine**.

## 3. Teste B — Gramine path (gramine_server) em HW *(o teste principal)*

### B.1 Bring-up

Apagar sealed blob herdado do SIM/SDK (formato incompatível):
```bash
rm -f data/sealed/state.bin
```

Servidor:
```bash
gramine-sgx gramine_server 127.0.0.1 7878
```

**Esperado:** `parties loaded — 3 hospitals, 1 researchers`. Sem
warnings sobre `/dev/attestation absent` (esses só aparecem em
`gramine-direct`).

### B.2 Upload + query com DCAP forçado

```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-sao-joao    data/hospital_1.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santo-antonio data/hospital_2.csv
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```

**Esperado para CADA cliente:**
```
Client: ATTEST_RESP received (...) bytes
quote_verify: DCAP chain OK + binding OK + MRENCLAVE pin OK
Server: state persisted
```

**E o servidor deve imprimir:**
```
DCAP: quote read OK (~4096 bytes)        # o tamanho exacto varia
```

Query final deve devolver `result=49.143 matched=15 applied_k=5`
(igual ao SIM, mas com o caminho DCAP a sério por baixo).

### B.3 Falhas de propósito (validar enforcement)

Tentar correr **sem** `SAHC_REQUIRE_DCAP=1` contra o servidor Gramine
HW:
```bash
./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** o cliente passa o handshake (em build SAHC_HW=1 a flag
`SAHC_REQUIRE_DCAP` default é 1, portanto **continua a aplicar DCAP** —
isto é, este teste deve ter o mesmo resultado que B.2). Se o colega
construiu o cliente sem `SAHC_HW=1` e correu contra o servidor HW,
deve ver:
```
quote_verify: DCAP format received (qlen=...) but this build does not
include the DCAP verifier — Refusing.
```
↑ comportamento esperado, não regressão.

Tentar com MRENCLAVE errado:
```bash
SAHC_EXPECTED_MRENCLAVE=$(printf 'aa%.0s' {1..32}) \
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** `quote_verify: MRENCLAVE mismatch vs env override`,
sessão recusada.

### B.4 K-anonymity

Query com filtro raro (poucos matches):
```bash
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg pneumonia
```
**Esperado:** `E_INSUFFICIENT_RECORDS` se < 5 matches; resultado
agregado se ≥ 5.

### B.5 Persistência

Matar o servidor (Ctrl-C), apagar nada, re-arrancar:
```bash
gramine-sgx gramine_server 127.0.0.1 7878
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```
**Esperado:** servidor imprime `Server: state loaded from sealed blob`;
query devolve o mesmo `49.143` sem precisar de re-upload. Se o blob
não desselar, **reportar** — a sealing key derivada de
`/dev/attestation/keys/_sgx_mrenclave` é o ponto crítico para garantir
que a persistência sobrevive a restart.

## 4. Bench

```bash
make sgx_bench
rm -f data/sealed/state.bin
gramine-sgx gramine_server 127.0.0.1 7878 &
SAHC_REQUIRE_DCAP=1 ./sgx_bench > bench-hw.md
```

**Capturar e reportar:** `bench-hw.md` na íntegra. Comparar com
`bench-sim.md` no repo (se ainda lá estiver) para quantificar overhead
DCAP+EPC.

## 5. Como reportar

Para cada teste que **falhar**, anexar:
1. O comando exacto que correu.
2. Output completo do **cliente E servidor** (stdout + stderr).
3. `dmesg | tail -50` se houver suspeita de driver SGX.
4. `cat /etc/sgx_default_qcnl.conf` (sem secrets).
5. Versão: `gramine-sgx --version`, `dpkg -l | grep sgx`.

Para testes que **passarem**, basta marcar OK na lista (B.1 → B.5).
Sem capturas a mais — o que importa é o que falhou.

## 6. Mapa rápido de falhas conhecidas

| Sintoma                                                | Causa                                                         |
|--------------------------------------------------------|---------------------------------------------------------------|
| `sgx_qv_verify_quote 0x...A001` (NO_QPL)               | falta `libsgx-dcap-default-qpl`                               |
| `sgx_qv_verify_quote 0x...A002` (CRL_UNAVAILABLE)      | PCCS unreachable / `qcnl.conf` errado                         |
| `qv_result rejected 0xA006` (OUT_OF_DATE)              | TCB do CPU desactualizado — fazer microcode update            |
| `qv_result rejected 0xA00C` (REVOKED)                  | PCK revogada — máquina banida do TCB; reportar                |
| `DCAP report_data binding mismatch`                    | bug nosso — reportar com hexdump do quote                     |
| `MRENCLAVE mismatch — wrong enclave binary`            | binário foi recompilado sem `make clean`; reconstruir         |
| `unseal failed` no startup                             | blob herdado de outro backend — `rm data/sealed/state.bin`    |
