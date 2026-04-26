# Como correr o SAHC

Guia único para pôr o protótipo a funcionar. Linear, copy-paste.

- Para correr **localmente sem hardware SGX** → segue da §1 à §5.
- Para correr em **Intel HW real** → §1, §2, depois salta para
  [`SIM_TO_HW.md`](SIM_TO_HW.md) e [`HW_VALIDATION.md`](HW_VALIDATION.md).

---

## 1. Pré-requisitos

Debian 13 / Ubuntu 22+:

```bash
# Toolchain + libs
sudo apt install build-essential git python3 libssl-dev curl

# Intel SGX SDK (modo simulação) — instala em /opt/intel/sgxsdk
# https://github.com/intel/linux-sgx (instalador .bin "for Linux")

# Gramine 1.9 — apenas se vais usar o caminho gramine_server
sudo curl -fsSLo /etc/apt/keyrings/gramine.asc \
    https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine.asc] \
    https://packages.gramineproject.io/ $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/gramine.list
sudo apt update && sudo apt install gramine
```

Verificar:
```bash
ls /opt/intel/sgxsdk/environment      # tem de existir
gramine-direct --version              # qualquer 1.9.x
```

## 2. Clonar e setup inicial

```bash
git clone <repo-url> sahc && cd sahc
source /opt/intel/sgxsdk/environment

# DuckDB (~57 MB, vai para Common/third_party/duckdb/, gitignored)
./scripts/fetch_duckdb.sh

# Identidades + authorized_parties.json (uma vez por checkout)
python3 scripts/gen_identity.py hosp-santa-maria
python3 scripts/gen_identity.py hosp-sao-joao
python3 scripts/gen_identity.py hosp-santo-antonio
python3 scripts/gen_identity.py fcup-research
python3 scripts/build_authorized_parties.py
```

Depois deste passo: `parties/*.{key,pub}` existem e
`authorized_parties.json` está na raiz.

## 3. Build (modo simulação — sem hardware)

Há **dois caminhos de servidor** que partilham o cliente. Escolhe um
ou compila ambos:

```bash
# Caminho A — SGX-SDK (enclave clássico, motor de query artesanal)
make sgx_server sgx_client

# Caminho B — Gramine + DuckDB (recomendado: SQL real)
make gramine_server gramine_manifest
```

Para limpar tudo: `make clean`.

## 4. Correr

### 4.A — Caminho SGX-SDK

Terminal 1:
```bash
./sgx_server                              # 127.0.0.1:7878 por defeito
```

Terminal 2:
```bash
# Upload (3 hospitais, 5 records cada → 15 totais)
./sgx_client 127.0.0.1 7878 hosp-santa-maria   data/hospital_0.csv
./sgx_client 127.0.0.1 7878 hosp-sao-joao      data/hospital_1.csv
./sgx_client 127.0.0.1 7878 hosp-santo-antonio data/hospital_2.csv

# Query agregada (researcher)
./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```

### 4.B — Caminho Gramine

Terminal 1:
```bash
gramine-direct gramine_server             # 0.0.0.0:7878 por defeito
```

Terminal 2 — em `gramine-direct` o MRENCLAVE é placeholder, então
desactiva-se o pin com `SAHC_EXPECTED_MRENCLAVE=''`:
```bash
SAHC_EXPECTED_MRENCLAVE='' ./sgx_client 127.0.0.1 7878 hosp-santa-maria   data/hospital_0.csv
SAHC_EXPECTED_MRENCLAVE='' ./sgx_client 127.0.0.1 7878 hosp-sao-joao      data/hospital_1.csv
SAHC_EXPECTED_MRENCLAVE='' ./sgx_client 127.0.0.1 7878 hosp-santo-antonio data/hospital_2.csv
SAHC_EXPECTED_MRENCLAVE='' ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```

### 4.C — Modo REPL (qualquer caminho)

Sem args extra, o cliente entra em REPL:
```bash
./sgx_client 127.0.0.1 7878 fcup-research
sahc> upload data/hospital_0.csv          # apenas roles HOSPITAL
sahc> query age avg diabetes
sahc> query temperature max any
sahc> help
sahc> quit
```

Comandos:
- `upload <csv_path>`
- `query <field> <op> [diag]`
  - `field`: `age` | `temperature` | `blood_sugar`
  - `op`: `avg` | `min` | `max` | `count`
  - `diag`: `any` | `healthy` | `diabetes` | `hypertension` | `infection`

## 5. O que esperar

Smoke saudável (com 3 hospitais carregados):

| Comando                                      | Resultado esperado                       |
|----------------------------------------------|------------------------------------------|
| `query age avg any`                          | `result=49.143 matched=15 applied_k=5`   |
| `query temperature max any`                  | `result=39.2 matched=15 applied_k=5`     |
| `query blood_sugar avg diabetes`             | resultado >0, `matched≥5`                |
| `query age avg pneumonia` (diag inexistente) | `E_INSUFFICIENT_RECORDS` (k<5)           |

O servidor imprime no log: `state persisted (22844 bytes)` após cada
upload (sealing). Reinício do servidor sem apagar `data/sealed/state.bin`
mantém os records — entrar logo a fazer queries deve devolver os
mesmos números sem re-upload.

## 6. Hardware Intel real

Se tens uma máquina com SGX habilitado e queres correr DCAP a sério
(não simulado), **não** sigas as secções 3-5 acima. Vai directo a:

1. [`docs/SIM_TO_HW.md`](SIM_TO_HW.md) — pré-requisitos HW (drivers,
   PCCS, DCAP libs), build com `SAHC_HW=1`, manifest HW.
2. [`docs/HW_VALIDATION.md`](HW_VALIDATION.md) — runbook de testes
   com expected outputs e mapa de erros.

## 7. Troubleshooting rápido

| Sintoma                                                  | Solução                                                              |
|----------------------------------------------------------|----------------------------------------------------------------------|
| `bash: ./sgx_client: No such file or directory`          | falta `make sgx_client`                                              |
| `tcp_listen: invalid host 7878`                          | passaste só a porta — args são `[host] [port]`                       |
| `quote_verify: MRENCLAVE mismatch`                       | em `gramine-direct` precisas de `SAHC_EXPECTED_MRENCLAVE=''`         |
| `unseal failed` ao arrancar servidor                     | trocaste de backend (SDK↔Gramine) — `rm data/sealed/state.bin`       |
| `fetch_duckdb.sh: ... not found`                         | correr `chmod +x scripts/*.sh` se vier sem permissões                |
| `fatal error: sgx_dcap_quoteverify.h`                    | só relevante para build HW; em SIM ignorar (não chega a esse path)   |
| `gramine-direct: command not found`                      | falta o passo Gramine na §1                                          |
| Build falha por `_GLIBCXX_USE_CXX11_ABI`                 | distro com libstdc++ muito antiga; usa Debian 13/Ubuntu 22+          |

## 8. Datasets

`data/hospital_{0,1,2}.csv` — 5 records cada, mock data.

Formato:
```csv
patient_id,age,temperature,blood_sugar,diagnosis
1001,45,36.5,95.0,1
```

Códigos de `diagnosis`: `0` healthy, `1` diabetes, `2` hypertension, `3` infection.
