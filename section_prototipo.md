# 7. Protótipo Implementado

Esta secção descreve o protótipo funcional desenvolvido, correspondente à Fase 1 da implementação descrita na secção 6.2. O objetivo é validar o fluxo fundamental do sistema (receção de dados cifrados, desencriptação dentro do enclave e execução de queries agregadas) utilizando diretamente o Intel SGX SDK em modo de simulação.

## 7.1 Stack Tecnológica

O protótipo foi desenvolvido em C/C++ sobre o Intel SGX SDK para Linux. A decisão de usar o SDK diretamente, em vez de uma library OS como o Gramine, permite controlo total sobre o código do enclave e minimiza a complexidade inicial, facilitando a compreensão da fronteira de confiança.

A compilação e execução decorrem em **modo de simulação** (`SGX_MODE=SIM`), uma vez que a máquina de desenvolvimento não dispõe de hardware SGX. Este modo replica a interface de programação do SDK (ECALLs, OCALLs, bibliotecas criptográficas) mas não oferece as garantias de isolamento de memória do hardware real, pelo que os dados do enclave residem em memória convencional do processo.

No lado não confiável, a cifra dos dados utiliza a biblioteca OpenSSL (AES-128-GCM via interface EVP). No lado confiável, o enclave recorre exclusivamente às primitivas criptográficas do SDK (`sgx_rijndael128GCM_decrypt` para desencriptação e `sgx_ecdsa_sign` para assinaturas), evitando dependências externas dentro do ambiente protegido.

O sistema de build usa o `sgx_edger8r` para gerar automaticamente os wrappers de fronteira a partir do ficheiro EDL: `Enclave_t.{c,h}` (stubs confiáveis) e `Enclave_u.{c,h}` (proxies não confiáveis). O enclave é compilado como biblioteca partilhada, assinado com uma chave RSA privada, e carregado pela aplicação host como `enclave.signed.so`.

## 7.2 Estrutura do Código

O código segue o modelo split-trust do SGX, dividido em dois lados com responsabilidades distintas:

```
App/                         # Lado não confiável (aplicação host)
  app_main.cpp               # Ponto de entrada, menu interativo, init/teardown do enclave
  csv_loader.cpp/h           # Parsing de ficheiros CSV com dados de pacientes
  crypto.cpp/h               # Cifra AES-128-GCM via OpenSSL
  attestation.cpp/h          # Orquestração do fluxo de atestação remota DCAP
  upload.cpp/h               # Upload de dados cifrados para o enclave
  query.cpp/h                # Interface interativa de queries agregadas
  helpers.cpp/h              # Utilidades de formatação e apresentação
  hospital_state.h           # Estrutura HospitalState, MRENCLAVE esperado

Enclave/                     # Lado confiável (enclave SGX)
  Enclave.cpp                # Atestação, troca de chaves, desencriptação, queries
  Enclave.edl                # Definição da interface ECALL/OCALL
  Enclave.config.xml         # Configuração de memória e threads do enclave

Include/
  types.h                    # Estruturas partilhadas entre ambos os lados
```

A modularização do lado não confiável em ficheiros separados permite isolar responsabilidades e facilitar a evolução do código. Cada módulo expõe uma função principal que é invocada pelo menu em `app_main.cpp`.

## 7.3 Estruturas de Dados e Interface

A estrutura central do sistema é o `PatientRecord`, definida em `Include/types.h` e partilhada entre ambos os lados da fronteira de confiança. Cada registo contém o identificador do paciente, idade, temperatura corporal, glicemia e um código de diagnóstico (saudável, diabetes, hipertensão ou infeção), ocupando 20 bytes.

No lado não confiável, o estado de cada hospital é mantido numa estrutura `HospitalState` que guarda o nome do hospital, o caminho para o ficheiro CSV, os registos carregados em memória, a chave de sessão AES-128 obtida durante a atestação, e flags que indicam se a atestação e o upload foram concluídos. Dentro do enclave, os registos desencriptados são armazenados num array global, juntamente com as chaves de sessão indexadas por hospital.

A fronteira de confiança é definida pelo ficheiro `Enclave.edl`, que especifica quatro ECALLs: `ecall_generate_report` para geração do quote DCAP, `ecall_finish_key_exchange` para obtenção da chave de sessão, `ecall_upload_data` para receção e desencriptação de dados, e `ecall_run_query` para execução de queries agregadas. O único OCALL definido é `ocall_print_string`, que permite ao enclave solicitar a impressão de mensagens de diagnóstico no stdout. O EDL especifica anotações de tamanho para todos os buffers que cruzam a fronteira, garantindo que o SDK copia apenas a quantidade necessária de dados entre memória confiável e não confiável.

## 7.4 Fluxo de Atestação Remota

O protótipo implementa um fluxo de atestação DCAP simulado. A aplicação host começa por gerar um nonce aleatório de 16 bytes via `RAND_bytes()` do OpenSSL, garantindo freshness contra ataques de replay.

O nonce é enviado ao enclave através de `ecall_generate_report()`. O enclave constrói um report que inclui o MRENCLAVE (medição simulada do código), o MRSIGNER (medição da chave de assinatura), e o nonce embebido no campo `user_data`. Sobre a concatenação destes campos (96 bytes), o enclave gera uma assinatura ECDSA usando `sgx_ecdsa_sign()`, simulando o papel do Quoting Enclave.

De volta ao lado não confiável, a aplicação verifica o quote em três passos: confirma que o nonce devolvido corresponde ao desafio original (proteção contra replay), compara o MRENCLAVE com o valor esperado hardcoded (confirmação da identidade do código), e verifica o MRSIGNER. A verificação da assinatura do Quoting Enclave é aceite como válida nesta fase, ficando a verificação completa da cadeia de certificados Intel para fases futuras.

Após atestação bem-sucedida, a aplicação invoca `ecall_finish_key_exchange()`. O enclave gera uma chave de sessão aleatória de 16 bytes via `sgx_read_rand()`, armazena-a internamente indexada pelo identificador do hospital, e devolve uma cópia à aplicação host. Esta chave será usada para cifrar os dados antes do upload.

## 7.5 Cifra e Upload de Dados

O upload de dados segue um fluxo de cifra-transmissão-desencriptação. No lado não confiável, os registos de pacientes carregados a partir do ficheiro CSV são cifrados com AES-128-GCM usando a chave de sessão obtida durante a atestação. A função `encrypt_data()` gera um IV aleatório de 12 bytes, cifra o array de registos usando a interface EVP do OpenSSL, e produz o ciphertext acompanhado de um tag de autenticação de 16 bytes.

O ciphertext, IV e tag são passados ao enclave via `ecall_upload_data()`. Dentro do enclave, `sgx_rijndael128GCM_decrypt()` desencripta os dados usando a chave de sessão armazenada internamente. O tag GCM é verificado automaticamente, garantindo que os dados não foram adulterados em trânsito. Os registos desencriptados são armazenados no array global do enclave, e o buffer temporário é limpo com `memset` antes de ser libertado.

## 7.6 Motor de Queries

O enclave implementa um motor de queries agregadas que opera sobre todos os registos armazenados, independentemente do hospital de origem. A função `ecall_run_query()` aceita três parâmetros: o campo a agregar (idade, temperatura ou glicemia), o tipo de agregação (média, mínimo, máximo ou contagem) e um filtro opcional por diagnóstico.

A execução itera sobre todos os registos, aplica o filtro quando solicitado, e calcula o agregado pedido. Apenas o valor agregado, o total de registos processados e o número de registos correspondentes ao filtro são devolvidos à aplicação host, sem nunca expor registos individuais. Esta propriedade é central ao modelo de privacidade do sistema, uma vez que os dados em claro existem apenas dentro do enclave e o exterior recebe unicamente resultados estatísticos.

## 7.7 Execução do Protótipo

O protótipo configura três hospitais (Hospital Santa Maria, Hospital São João e Hospital Santo António), cada um associado a um ficheiro CSV com dados de exemplo. O menu principal permite executar cada passo individualmente (carregar CSV, atestar, fazer upload, executar query) ou correr o fluxo completo para os três hospitais de uma só vez. Após o upload dos três hospitais, as queries agregam dados de todas as fontes no enclave, demonstrando a análise segura multi-hospital sem exposição de dados individuais.

## 7.8 Simplificações Face à Arquitetura Alvo

O protótipo adota várias simplificações relativamente à arquitetura descrita na secção 5, consistentes com os objetivos da Fase 1.

A nível criptográfico, a troca de chaves não usa ECDH. O enclave gera a chave de sessão unilateralmente e devolve-a em claro, em vez do estabelecimento mútuo com derivação via HKDF previsto na arquitetura alvo. A cifra simétrica usa AES-128-GCM em vez de AES-256-GCM, e os resultados das queries não são autenticados com HMAC.

A atestação DCAP é simulada, com o MRENCLAVE hardcoded em vez de ser calculado pelo processador, e a assinatura do Quoting Enclave aceite sem verificação da cadeia de certificados Intel. Em hardware real, esta verificação encadearia até à CA raiz da Intel via o serviço PCCS.

A nível arquitetural, o protótipo funciona como processo único (host e enclave no mesmo processo), sem a separação cliente/servidor com TLS prevista para fases posteriores. Os dados existem apenas em memória protegida do enclave, sem persistência em disco com sealing key. O motor de queries implementa agregações simples (AVG, MIN, MAX, COUNT) de forma manual, em vez de recorrer ao DuckDB via Gramine. Não existe threshold mínimo de registos por resultado (k-anonymity), pelo que todas as queries são respondidas independentemente do número de registos correspondentes.

Estas simplificações são deliberadas: o protótipo foca-se na validação do fluxo end-to-end (atestação → cifra → upload → desencriptação → query) e na familiarização com a API do SGX SDK, delegando as funcionalidades mais avançadas para fases posteriores do desenvolvimento.
