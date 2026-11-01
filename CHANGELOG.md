# Changelog

Este projeto segue um versionamento simples (MAJOR.MINOR.PATCH). Mudancas
relevantes de cada versao sao documentadas aqui.

## [5.0.0] - 2026

### Visao geral

A v5 e uma revisao profunda focada em tres eixos: **cobertura** (novos
vetores de ataque cobertos), **qualidade de sinal** (correlacao entre
achados, reducao de falso positivo) e **engenharia** (testes automatizados,
timeout, paralelismo, integracoes de CI/CD). O principio fundamental do
projeto permanece inalterado: **somente leitura, nunca exploits, nunca
modificacoes no sistema, nunca exfiltracao de dados**.

### Adicionado

- **Novo modulo: Container Escape Audit** (`modules/container_escape.sh`)
  - Socket do Docker gravavel, pertenca ao grupo `docker`.
  - Capabilities efetivas do processo atual dentro de containers.
  - `/sys/fs/cgroup` gravavel (indicio de vetor `release_agent`).
  - NFS exports com `no_root_squash`.
  - `/etc/ld.so.preload` e `/etc/ld.so.conf.d` graviaveis (hijacking global
    de bibliotecas dinamicas).
- **Novo modulo: Credential Hunting** (`modules/credential_hunting.sh`)
  - Varre historico de shell, `.netrc`, `.git-credentials`,
    `.aws/credentials`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.env`
    em busca de padroes textuais de credenciais.
  - **Nunca** exibe o valor real encontrado; apenas arquivo, linha e um
    trecho redigido via `redact_secret()`.
- **Motor de correlacao** (`modules/correlate.sh`, roda sempre por ultimo)
  - Combina sinais independentes (variaveis `PCSEC_CTX_*` exportadas pelos
    demais modulos) em "cadeias de ataque" (attack paths), elevando a
    severidade/prioridade quando dois ou mais vetores fracos, juntos,
    formam um caminho forte (ex.: grupo docker + binario docker presente).
- **Execucao isolada por subprocesso, com timeout** (`--timeout SEGUNDOS`,
  padrao 60s) - um modulo que trava ou demora demais e interrompido e
  reportado como INFO, sem derrubar a auditoria inteira.
- **Paralelismo opcional** (`--jobs N`) - ate N modulos rodando ao mesmo
  tempo, cada um em seu proprio subprocesso (sem risco de corrupcao de
  estado compartilhado, pois cada subprocesso escreve seus achados em
  arquivos proprios, mesclados pelo processo pai ao final).
- **Risk score agregado do host** - soma ponderada de severidades
  (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0), exibido no resumo e
  incluido em todos os formatos de saida.
- **`--fail-on-risk N`** - encerra com exit code 1 se o risk score for
  maior ou igual a N. Pensado para gates de CI/CD (ex.: bloquear build de
  uma imagem Docker insegura).
- **Saida SARIF 2.1.0** (`--sarif`) - compativel com GitHub Code Scanning,
  SonarQube e outras ferramentas de pipeline.
- **Relatorio HTML standalone** (`--html`) - um unico arquivo, sem
  dependencias externas, com os achados navegaveis e filtraveis por
  severidade, adaptado a tema claro/escuro do sistema.
- **Comparacao entre execucoes** (`--compare relatorio-anterior.json`) -
  mostra achados novos e achados resolvidos desde a execucao anterior,
  util para acompanhar hardening ao longo do tempo.
- **Capabilities do processo atual** (alem de arquivos) verificadas via
  `/proc/self/status` no modulo `capabilities.sh`.
- **Deteccao de chaves privadas SSH com permissao incorreta** em
  `permission_audit.sh` (apenas cabecalho do arquivo e inspecionado;
  conteudo nunca e lido).
- **Correlacao offline com CVEs de kernel conhecidas** (tabela estatica,
  nao exaustiva, em `kernel_audit.sh`) e deteccao de `pkexec`/polkit
  (contexto PwnKit / CVE-2021-4034).
- **Deteccao de `env_keep += LD_PRELOAD/LD_LIBRARY_PATH`** em regras sudo
  (`sudo_audit.sh`).
- **Deteccao de wildcard injection** em scripts cron que invocam
  `tar`/`rsync`/`7z` com curinga (`cron_audit.sh`).
- **Cache de `has_cmd`** - evita chamadas repetidas a `command -v` dentro
  do mesmo processo.
- **Baseline de SUID legitimos conhecidos** (`suid_sgid.sh`) - reduz ruido
  distinguindo um SUID esperado (ex. `/usr/bin/passwd`) de um binario da
  watchlist em caminho atipico (sinal mais forte de problema real).
- **Suite de testes automatizados** com Bats (`tests/test_core.bats`),
  cobrindo utilitarios puros e o fluxo de CLI de ponta a ponta.
- **Workflow de CI** (`.github/workflows/lint.yml`) rodando ShellCheck,
  a suite Bats, e um smoke test que executa a propria ferramenta no runner.

### Corrigido

- `suid_sgid.sh`: removido trecho de codigo morto (`case "$perms" in
  *s??------)`) que nunca era efetivamente usado para a deteccao de bits.
- Arrays associativos (`declare -A`) e contadores globais agora sao
  reinicializados corretamente dentro de cada subprocesso de modulo -
  bash nao exporta arrays associativos para processos filhos, o que
  quebrava `has_cmd()` sob `set -u` nas primeiras versoes internas da v5.

### Alterado

- `MODULE_LIST` agora inclui os 3 novos modulos; `--checks` reflete a
  lista atualizada.
- `report_finding()` passou a gravar cada achado em um arquivo
  chave=valor (alem de imprimir no terminal), para suportar o novo motor
  de execucao por subprocesso. Comportamento observavel para o usuario
  final (saida no terminal, texto, JSON) permanece o mesmo.
- O relatorio JSON agora e sempre persistido em disco (necessario como
  base para `--compare` em execucoes futuras), mas so e anunciado no
  terminal como "salvo" quando `--json` e passado explicitamente.

### Compatibilidade

- Todas as flags da v1 (`--quick`, `--full`, `--no-color`, `--output`,
  `--json`, `--checks`, `--help`, `--version`) continuam funcionando
  exatamente como antes. Nenhuma flag foi removida ou teve seu
  comportamento alterado de forma incompativel.
- Formato do relatorio texto e do JSON permanece retrocompativel (apenas
  campos novos foram adicionados, como `risk_score` e `id` por achado).
