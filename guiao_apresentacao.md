# Guião da Apresentação — Slides 14 a 18

## SLIDE 14 — Implementation: 4 Phases (~1 min)

A implementação está organizada em quatro fases progressivas. O protótipo funcional corresponde à Fase 1.

Usámos diretamente o Intel SGX SDK, sem library OS, para ter controlo total sobre o código dentro do enclave e compreender claramente a fronteira de confiança.

A Fase 1 implementa quatro ECALLs. O `ecall_generate_report` faz attestation DCAP simulada: o enclave constrói um quote com o MRENCLAVE e o MRSIGNER, e o Quoting Enclave assina-o com ECDSA. O `ecall_finish_key_exchange` gera uma session key AES-128 aleatória por hospital usando `sgx_read_rand`. O `ecall_upload_data` recebe dados cifrados com AES-128-GCM, desencripta-os dentro do enclave com verificação do tag de autenticação, e armazena-os em memória protegida. O `ecall_run_query` executa agregações (média, mínimo, máximo, contagem) sobre o dataset combinado, com filtragem opcional por diagnóstico. Tudo corre em modo de simulação.

As fases seguintes são o roadmap. A Fase 2 adiciona sessões independentes por hospital e persistência via sealing key. A Fase 3 integra DuckDB via Gramine para SQL completo e mitigações de timing side-channels. A Fase 4 substitui a attestation simulada por DCAP real com PCCS local. Apenas a Fase 1 está implementada.

---

## SLIDE 15a — POC - Architecture Diagram (~1 min)

Este diagrama mostra a separação entre o lado não confiável, à esquerda, e o enclave SGX, à direita. A linha entre eles é a fronteira de confiança definida pelo ficheiro EDL.

O fluxo tem quatro passos. Primeiro, o CSV Loader carrega dados de três hospitais, cada um com registos de pacientes contendo ID, idade, temperatura, glicemia e diagnóstico.

Segundo, cada hospital faz attestation simulada: o host gera um nonce aleatório, o enclave devolve um quote assinado com ECDSA contendo o MRENCLAVE, e o host verifica que o nonce corresponde e o MRENCLAVE é o esperado. Após verificação, o enclave gera uma session key e devolve-a.

Terceiro, os dados são cifrados no host com AES-128-GCM via OpenSSL, usando um IV aleatório de 12 bytes gerado para cada upload. O ciphertext, o IV e o tag de 16 bytes são enviados ao enclave, que desencripta com `sgx_rijndael128GCM_decrypt` e verifica a integridade via GCM tag.

Quarto, as queries são executadas dentro do enclave sobre o dataset agregado dos três hospitais. Apenas o valor agregado sai do enclave. Os registos individuais nunca são expostos, nem ao host, nem ao sistema operativo, nem ao operador cloud.

De notar que as bibliotecas criptográficas são diferentes em cada lado: OpenSSL no host porque tem acesso ao OS, `sgx_tcrypto` do SDK dentro do enclave porque não depende de system calls.

---

## SLIDE 15b — POC - Demo (~30 seg)

*[Ter o terminal preparado com o `./app` pronto a correr. Correr opção 6 — processo completo.]*

Vou correr o processo completo para os três hospitais. Podem ver os dados a ser carregados, a attestation a ser feita para cada hospital com verificação do nonce e do MRENCLAVE, a negociação da session key, e o upload cifrado.

*[Quando terminar, correr opção 5 com: campo 2 (blood sugar), agregação 0 (média), filtro 1 (diabetes).]*

Agora vou executar uma query: a média de glicemia dos pacientes com diabetes, agregando dados dos três hospitais. O resultado é calculado inteiramente dentro do enclave. Os dados individuais nunca saíram.

---

## SLIDE 16 — Security Analysis (~45 seg)

Do lado esquerdo temos as garantias formais do sistema. Confidencialidade: registos individuais nunca são revelados fora do enclave, incluindo ao operador cloud. Integridade: o GCM tag garante que dados adulterados em trânsito são rejeitados. Autenticidade: a attestation remota permite verificar criptograficamente que o enclave executa o código correto. Freshness é parcial: o nonce previne replay de quotes antigos, mas proteção completa contra rollback requer contadores monotónicos persistentes num TPM.

Do lado direito, as ameaças conhecidas.

Os ataques clássicos de cache side-channel, como Flush+Reload, são mitigados com algoritmos constant-time. Os page fault attacks, em que um OS malicioso observa acessos à memória com granularidade de 4 KB, são parcialmente mitigados pelo SGX2.

Mais graves são os ataques de execução especulativa. O SgxPectre é uma variante do Spectre aplicada a enclaves: o atacante manipula o preditor de saltos do processador para forçar o enclave a executar especulativamente instruções que tocam em dados secretos, e depois recupera esses dados observando o estado da cache. A mitigação é compilar o enclave com retpoline, que bloqueia esta manipulação do preditor.

Ainda mais preocupante é o Foreshadow. Este ataque explora uma falha no hardware da cache L1 que permite ler memória protegida do enclave sem sequer precisar de código da vítima nem de privilégios de kernel. O resultado é que derrota por completo o isolamento do SGX e chegou a permitir extrair as chaves de attestation da Intel, o que comprometeria a confiança em todos os processadores afetados. A mitigação não é software, exige microcode updates da Intel e, em cenários de alto risco, desativar hyperthreading.

A inferência estatística sobre resultados agregados é controlada por k-anonymity com threshold K=5. O EPC de 92 MB pre-Ice Lake é suficiente para datasets médicos moderados, com Ice Lake+ a expandir até 512 GB.

A conclusão é que o SGX oferece garantias fortes contra operadores cloud honestos-mas-curiosos, mas depende de boas práticas constant-time e de microcode atualizado para resistir a ataques microarquiteturais.

---

## SLIDE 17 — Limitations & Future Work (~30 seg)

Quatro limitações identificadas, todas com caminhos claros de resolução.

Não temos full obliviousness: padrões de acesso à memória continuam visíveis via page faults em SGX1. Oblivious RAM resolve mas com overhead de 10 a 100x.

Freshness é parcial: sem TPM, contadores monotónicos não sobrevivem a reboots.

k-Anonymity sozinho não defende contra adversários adaptativos que combinem múltiplas queries. Differential privacy é a extensão natural.

E o EPC pre-Ice Lake limita o tamanho do dataset em memória, resolvido por chunk processing ou hardware moderno.

Como nota na base do slide: sem hardware DCAP, a attestation é testada apenas em simulação. Um deployment em produção requer hardware SGX real.

---

## SLIDE 18 — Conclusion (~30 seg)

Para concluir.

Implementámos um protótipo funcional de data lake seguro para análise colaborativa de dados médicos entre múltiplos hospitais, usando Intel SGX. Dados individuais nunca saem do enclave.

Validámos o fluxo end-to-end: attestation simulada, session keys por hospital, upload cifrado com AES-128-GCM, desencriptação dentro do enclave, e queries agregadas com filtragem.

O modelo split-trust funciona: a separação entre código confiável e não confiável garante que dados sensíveis podem ser processados sem que o operador da infraestrutura tenha acesso ao plaintext.

As limitações são deliberadas para a Fase 1. O próximo passo é migrar para hardware real com attestation DCAP completa via PCCS, ECDH para troca de chaves mútua, sealing para persistência cifrada, e thresholds de k-anonymity nos resultados.

Obrigado.
