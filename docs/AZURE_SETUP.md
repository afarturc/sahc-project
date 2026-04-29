# Setup do zero numa VM Azure DCsv3 (Intel SGX)

Guião sequencial para preparar uma VM `Standard_DC*s_v3` (Ice Lake-SP
com SGX). Cada comando numa única linha — copy-paste directo. Para
validação fim-a-fim ver [`HW.md`](HW.md).

---

## 0. Validar SGX vivo

```
lscpu | grep 'Model name'
```
```
grep -o sgx /proc/cpuinfo | head -1
```
```
ls -l /dev/sgx_enclave /dev/sgx_provision
```
```
sudo dmesg | grep -i sgx | head -5
```

Esperado: Xeon Platinum 83xx, flag `sgx`, ambos os device nodes
existem, EPC ≥ 168 MiB. Se vendor for `AuthenticAMD` ou cpuinfo sem
`sgx` → tamanho de VM errado, recriar como `DC*s_v3` (Intel).

## 1. Repo Intel SGX (assinatura GPG)

```
sudo rm -f /usr/share/keyrings/intel-sgx.gpg /etc/apt/sources.list.d/intel-sgx.list
```
```
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx.gpg
```
```
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
```
```
sudo apt update
```

`apt update` tem de mostrar `Get: ... intel-sgx ...` **sem** erro de GPG.
Se der `NO_PUBKEY`, importar a chave do keyserver:
```
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/intel-sgx.gpg --keyserver keyserver.ubuntu.com --recv-keys E5C7F0FA1C6C6C3C
```

## 2. Stack SGX userspace + DCAP

```
sudo apt install -y libsgx-urts libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-dcap-quote-verify-dev libsgx-quote-ex sgx-aesm-service libsgx-aesm-quote-ex-plugin libsgx-aesm-ecdsa-plugin libsgx-ae-qe3 libsgx-ae-qve
```

Validar:
```
sudo systemctl status aesmd --no-pager | head -5
```
```
cat /etc/sgx_default_qcnl.conf
```
Esperado: `aesmd` active (running); URL do PCCS Azure
(`acccache.azure.net`) já configurado.

## 3. SGX SDK

```
cd /tmp && wget https://download.01.org/intel-sgx/sgx-linux/2.23/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.23.100.2.bin
```
```
chmod +x sgx_linux_x64_sdk_2.23.100.2.bin
```
```
sudo ./sgx_linux_x64_sdk_2.23.100.2.bin --prefix=/opt/intel
```
```
echo 'source /opt/intel/sgxsdk/environment' >> ~/.bashrc
```
```
source /opt/intel/sgxsdk/environment
```

## 4. Gramine 1.9

```
sudo mkdir -p /etc/apt/keyrings
```
```
sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
```
```
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ noble main" | sudo tee /etc/apt/sources.list.d/gramine.list
```
```
sudo apt update && sudo apt install -y gramine
```
```
gramine-sgx --version
```
```
gramine-sgx-gen-private-key
```

## 5. Permissões SGX

```
sudo usermod -aG sgx_prv $USER
```
```
newgrp sgx_prv
```
```
groups | grep sgx_prv
```

## 6. Trazer o repo (correr na máquina LOCAL)

```
rsync -av --exclude='.git' --exclude='build/' --exclude='*.o' ~/Documents/MSI/2S/SAHC/Project/ azureuser@<IP-VM>:~/sahc/
```

## 7. Build (na VM)

```
cd ~/sahc && source /opt/intel/sgxsdk/environment
```
```
./scripts/fetch_duckdb.sh
```
```
./scripts/gen_identity.py
```
```
./scripts/build_authorized_parties.py
```
```
make clean
```
```
make hw
```
`make hw` faz tudo na ordem certa: enclave SDK + manifest Gramine assinado +
extracção automática do MRENCLAVE Gramine + cliente linkado contra esse pin.

## 8. Smoke test

Servidor numa sessão `tmux`:
```
tmux new -s sahc
```
```
rm -f data/sealed/state.bin
```
```
gramine-sgx gramine_server 127.0.0.1 7878
```
Detach: `Ctrl-B` depois `D`.

Notas Azure DCsv3 (uma vez por sessão SSH):
```
export AZDCAP_COLLATERAL_VERSION=v3
```
A QvL Intel ainda não aceita `v4` que a Azure devolve por defeito —
`v3` resolve o `sgx_qv_verify_quote 0xe03a`.

Cliente noutra sessão SSH:
```
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santa-maria data/hospital_0.csv
```
```
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-sao-joao data/hospital_1.csv
```
```
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 hosp-santo-antonio data/hospital_2.csv
```
```
SAHC_REQUIRE_DCAP=1 ./sgx_client 127.0.0.1 7878 fcup-research - age avg any
```

Esperado em cada cliente: `quote_verify: DCAP chain OK + binding OK +
MRENCLAVE pin OK`. Query final: `result=49.143 matched=14 applied_k=5`.

A partir daqui seguir [`HW.md`](HW.md) §B.3 (negativos), §B.5
(persistência), §6 (bench).

## 9. Quando paras de trabalhar

Stop-deallocate (na máquina LOCAL) para parar a faturação:
```
az vm deallocate -g <resource-group> -n <vm-name>
```
Retomar:
```
az vm start -g <resource-group> -n <vm-name>
```
