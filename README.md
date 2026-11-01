# PabloCyberSec Linux Privilege Escalation (PCSEC-PRIVESC) v5

```
  ____   ____ ____  _____ ____
 |  _ \ / ___/ ___|| ____/ ___|
 | |_) | |   \___ \|  _|| |
 |  __/| |___ ___) | |__| |___
 |_|    \____|____/|_____\____|

  PABLOCYBERSEC
  LINUX PRIVILEGE ESCALATION
  Security Auditing & Misconfiguration Analysis
  Developed by PabloCyberSec
  Version 5.0.0
```

> Auditoria local de seguranca em sistemas Linux, com foco em identificar
> configuracoes inseguras e possiveis vetores de escalacao de privilegios —
> **sem executar exploits, sem alterar o sistema e sem enviar dados para
> servidores externos.**

---

## Sumario

- [Sobre o projeto](#sobre-o-projeto)
- [Novidades da v5](#novidades-da-v5)
- [Objetivos](#objetivos)
- [Funcionalidades](#funcionalidades)
- [Requisitos](#requisitos)
- [Instalacao](#instalacao)
- [Uso](#uso)
- [Argumentos disponiveis](#argumentos-disponiveis)
- [Niveis de severidade](#niveis-de-severidade)
- [Risk score e uso em CI/CD](#risk-score-e-uso-em-cicd)
- [Exemplo de relatorio](#exemplo-de-relatorio)
- [Estrutura do repositorio](#estrutura-do-repositorio)
- [Testes automatizados](#testes-automatizados)
- [Limitacoes conhecidas](#limitacoes-conhecidas)
- [Avisos de seguranca e uso responsavel](#avisos-de-seguranca-e-uso-responsavel)
- [Licenca](#licenca)
- [Creditos](#creditos)

---

## Sobre o projeto

**PabloCyberSec Linux Privilege Escalation** (nome curto: **PCSEC-PRIVESC**) e
uma ferramenta de linha de comando, escrita em Bash, que realiza verificacoes
locais de seguranca em sistemas Linux e aponta configuracoes que podem
representar vetores de escalacao de privilegios — como regras `sudo`
excessivas, binarios com `SUID`/`SGID` ou *capabilities* perigosas,
permissoes incorretas em arquivos criticos, tarefas `cron` inseguras,
vetores de escape de containers, credenciais expostas em arquivos comuns,
entre outros.

O projeto foi desenhado para profissionais de seguranca ofensiva e defensiva,
equipes de *red team*/*blue team*, administradores de sistemas e estudantes
que precisam avaliar, de forma rapida e organizada, a postura de seguranca de
um host Linux **em ambientes autorizados**.

## Novidades da v5

A v5 e uma revisao profunda focada em cobertura, qualidade de sinal e
engenharia de software. Resumo rapido (detalhes completos em
[`CHANGELOG.md`](CHANGELOG.md)):

- **2 novos modulos**: `Container Escape Audit` e `Credential Hunting`.
- **Motor de correlacao**: combina achados independentes em "cadeias de
  ataque" (ex.: grupo `docker` + binario `docker` presente = CRITICAL).
- **Execucao isolada por subprocesso**, com **timeout configuravel**
  (`--timeout`) e **paralelismo opcional** (`--jobs N`).
- **Risk score agregado** do host, com **`--fail-on-risk`** para gates de
  CI/CD.
- **Saida em SARIF** (`--sarif`) e **relatorio HTML standalone**
  (`--html`), alem de texto e JSON.
- **`--compare`**: diff entre execucoes para acompanhar hardening ao longo
  do tempo.
- **Suite de testes automatizados** (Bats) e **workflow de CI** (GitHub
  Actions com ShellCheck + testes + smoke test).

O principio fundamental permanece: **somente leitura, zero exploits, zero
modificacoes no sistema, zero exfiltracao de dados.**

## Objetivos

- Identificar **configuracoes inseguras** e **permissoes excessivas**.
- Apontar **possiveis vetores** de escalacao de privilegios que exigem
  validacao manual.
- Correlacionar achados individuais em **cadeias de ataque** mais realistas.
- Gerar **relatorios claros**, classificados por severidade, com recomendacao
  de correcao para cada achado, em multiplos formatos (texto, JSON, SARIF,
  HTML).
- Funcionar de forma **segura por padrao**: somente leitura, sem exploits, sem
  modificar o sistema e sem exfiltrar dados.
- Integrar-se naturalmente a **pipelines de CI/CD** (SARIF para code
  scanning, `--fail-on-risk` para gates de seguranca).

## Funcionalidades

A ferramenta executa os seguintes modulos de auditoria:

| Modulo | O que verifica |
|---|---|
| **System Enumeration** | Distro, kernel, arquitetura, usuario/UID, grupos, uptime, hostname, indicios de container, variaveis de ambiente sensiveis (sem expor valores) e ferramentas administrativas disponiveis. |
| **Sudo Configuration Audit** | Regras `sudo` acessiveis ao usuario atual (via `sudo -n -l`, nunca solicita senha), binarios classicamente associados a escalacao via `sudo`, e `env_keep` perigoso (`LD_PRELOAD`/`LD_LIBRARY_PATH`). |
| **SUID / SGID Audit** | Arquivos com bit `SUID`/`SGID` em diretorios padrao de binarios, com baseline de instalacoes legitimas conhecidas para reduzir falso positivo, destacando programas frequentemente citados em tecnicas publicas de escalacao. |
| **Linux Capabilities** | *Capabilities* do processo atual (`/proc/self/status`) e de arquivos (via `getcap`), destacando as de maior impacto (ex. `cap_setuid`, `cap_sys_admin`). |
| **Process & Service Audit** | Processos rodando como root visiveis ao usuario, binarios de processos graviaveis pelo usuario atual, e permissao de escrita em diretorios de unidades `systemd`. |
| **Scheduled Tasks (Cron) Audit** | Crontab do usuario, permissao de escrita em `/etc/crontab` e em `/etc/cron.*`, scripts cron graviaveis por terceiros, e padroes de *wildcard injection* em scripts que usam `tar`/`rsync`/`7z`. |
| **File Permission Analysis** | Variavel `PATH`, permissao de arquivos sensiveis (`/etc/passwd`, `/etc/shadow`, etc. — **sem ler o conteudo**), diretorios home e arquivos de inicializacao de shell graviaveis por outros, e chaves privadas SSH com permissao incorreta (apenas cabecalho inspecionado, conteudo nunca lido). |
| **Kernel & Update Audit** | Versao do kernel e do SO para correlacao manual com bases de CVE (com tabela offline nao exaustiva de referencia), indicios de reboot pendente, gerenciador de pacotes disponivel, e presenca de `pkexec`/polkit (contexto PwnKit). |
| **Container Escape Audit** *(novo na v5)* | Socket do Docker gravavel, pertenca ao grupo `docker`, capabilities efetivas dentro de containers, `/sys/fs/cgroup` gravavel, NFS `no_root_squash`, `/etc/ld.so.preload` e `/etc/ld.so.conf.d` graviaveis. |
| **Credential Hunting** *(novo na v5)* | Padroes textuais de credenciais em historico de shell, `.netrc`, `.git-credentials`, `.aws/credentials`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.env` — **nunca exibe o valor real**, apenas arquivo, linha e trecho redigido. |
| **Correlation Engine** *(novo na v5)* | Roda sempre por ultimo; combina sinais de todos os demais modulos em cadeias de ataque (ex.: sudo NOPASSWD arriscado + SUID suspeito = prioridade maxima). |

> A ferramenta **nunca** executa exploits, **nunca** tenta obter root
> automaticamente e **nunca** imprime conteudo de arquivos sensiveis, tokens,
> senhas ou chaves privadas — valores desse tipo sao sempre redigidos
> (`[REDACTED]`) quando sua simples existencia precisa ser reportada.

## Requisitos

- Bash 4.3+ (usa `wait -n`; presente por padrao na maioria das distribuicoes
  Linux modernas).
- Utilitarios padrao do sistema: `find`, `stat`, `ps`, `uname`, `id`, `grep`,
  `awk`, `timeout`, `md5sum` (ou `cksum` como fallback).
- Opcionais (a ferramenta detecta e avisa quando ausentes, sem travar a
  execucao):
  - `getcap` (pacote `libcap2-bin` no Debian/Ubuntu) — para o modulo de
    *capabilities* em arquivos.
  - `systemctl` — para a analise de servicos `systemd`.
  - `sudo` — para a auditoria de regras sudo.
  - `python3` — usado apenas pelos testes automatizados para validar JSON.
- **Nao requer privilegios root** para as verificacoes basicas. Quando
  executada como root, a ferramenta exibe um aviso informando que a analise
  tera maior visibilidade — essa condicao nunca e usada para alterar o
  sistema.

## Instalacao

### Opcao 1 — Download do script (recomendado)

```bash
git clone https://github.com/Deepaudit/linux-privesc.git
cd linux-privesc
chmod +x pcsec-privesc.sh
./pcsec-privesc.sh --help
```

### Verificando o conteudo antes de executar

Antes de rodar qualquer script baixado da internet — inclusive este — é uma
boa pratica de seguranca **inspecionar o conteudo**:

```bash
less pcsec-privesc.sh          # leia o script antes de executar
sha256sum pcsec-privesc.sh     # compare com um hash publicado, se disponivel
```

⚠️ **Executar codigo baixado diretamente via pipe para o Bash, sem inspecionar
o conteudo antes, nao e a opcao mais segura.** Prefira sempre baixar o
repositorio, lê-lo (ou ao menos conferir o hash) e só então executá-lo.

Veja mais detalhes em [`docs/INSTALL.md`](docs/INSTALL.md).

## Uso

```bash
# Execucao padrao
./pcsec-privesc.sh --full

# Rapida, sem cor
./pcsec-privesc.sh --quick --no-color

# Todas as saidas (texto + JSON + SARIF + HTML)
./pcsec-privesc.sh --full --json --sarif --html --output /tmp/auditoria-$(hostname)

# Paralelismo e timeout por modulo
./pcsec-privesc.sh --full --jobs 4 --timeout 30

# Comparar com uma execucao anterior (tracking de hardening)
./pcsec-privesc.sh --full --json --compare ./pcsec-reports/relatorio-anterior.json

# Uso tipico em pipeline de CI: falha o build se o risk score for alto
./pcsec-privesc.sh --full --sarif --fail-on-risk 50

# Lista os modulos disponiveis
./pcsec-privesc.sh --checks
```

Mais exemplos em [`docs/USAGE.md`](docs/USAGE.md).

### Saida de exemplo (ilustrativa)

```
PABLOCYBERSEC LINUX PRIVILEGE ESCALATION

[+] System Enumeration
[+] Sudo Configuration Audit
[+] SUID / SGID Audit
[+] Linux Capabilities
[+] Process & Service Audit
[+] Scheduled Tasks (Cron) Audit
[+] File Permission Analysis
[+] Kernel & Update Audit
[+] Container Escape Audit
[+] Credential Hunting
[+] Correlation Engine - Attack Path

Audit completed.

Findings totais : 43
Critical        : 10
High            : 8
Medium          : 1
Low             : 13
Informational   : 11

Risk score agregado do host: 155
```

> Os numeros acima sao apenas ilustrativos. Os resultados reais dependem
> inteiramente do sistema auditado e das verificacoes executadas naquela
> sessao.

## Argumentos disponiveis

| Argumento | Descricao |
|---|---|
| `--help` | Mostra a ajuda e encerra. |
| `--version` | Mostra a versao da ferramenta e encerra. |
| `--quick` | Executa apenas as verificacoes basicas (subconjunto mais rapido). |
| `--full` | Executa **todas** as verificacoes implementadas (padrao). |
| `--no-color` | Desativa cores ANSI na saida do terminal. |
| `--output DIR` | Define o diretorio onde os relatorios serao salvos (padrao: `./pcsec-reports`). |
| `--json` | Anuncia e confirma a geracao do relatorio em JSON (o JSON e sempre escrito em disco internamente, para suportar `--compare`). |
| `--sarif` | Gera um relatorio em formato SARIF 2.1.0 (CI/CD, GitHub Code Scanning). |
| `--html` | Gera um relatorio HTML standalone, navegavel e filtravel por severidade. |
| `--jobs N` | Executa ate N modulos em paralelo (padrao: 1 = sequencial). |
| `--timeout SEGUNDOS` | Tempo maximo por modulo antes de ser interrompido (padrao: 60). |
| `--compare ARQUIVO.json` | Compara com um relatorio JSON de execucao anterior; mostra achados novos/resolvidos. |
| `--fail-on-risk N` | Encerra com exit code 1 se o risk score agregado for >= N. |
| `--checks` | Lista todos os modulos/verificacoes disponiveis e encerra. |

## Niveis de severidade

Cada achado recebe uma classificacao de severidade e um nivel de confianca:

| Severidade | Significado | Peso no risk score |
|---|---|---|
| **Informativo** | Dado de contexto; nao representa, por si so, um risco de seguranca. | 0 |
| **Baixo** | Configuracao que merece atencao, mas com baixa probabilidade/impacto de exploracao. | 1 |
| **Medio** | Configuracao que pode facilitar um ataque, mas normalmente exige condicoes adicionais. | 2 |
| **Alto** | Configuracao fortemente associada a tecnicas conhecidas de escalacao de privilegios. | 5 |
| **Critico** | Configuracao que, isoladamente, ja representa um caminho direto e de alta confianca para comprometimento do sistema. | 10 |

Alem da severidade, cada achado traz um **nivel de confianca**:

- **Configuracao confirmadamente insegura** — a condicao foi verificada
  diretamente (ex.: teste de permissao de escrita bem-sucedido).
- **Possivel vetor — requer validacao manual** — o indicio foi encontrado,
  mas a exploracao real depende de fatores que a ferramenta nao confirma
  automaticamente.
- **Informativo — requer investigacao manual** — dado de contexto que o
  profissional deve analisar por conta propria.

A ferramenta **nunca afirma que e possivel obter root** apenas com base em um
unico achado isolado, sem evidencia suficiente — para isso existe o motor de
correlacao, que so eleva a prioridade quando ha sinais independentes
combinados.

## Risk score e uso em CI/CD

Cada execucao calcula um **risk score agregado** do host (soma ponderada das
severidades, ver tabela acima). Esse numero aparece no resumo do terminal,
no relatorio texto, no JSON (`summary.risk_score`) e no relatorio HTML.

Use `--fail-on-risk N` para transformar a auditoria em um *gate* de
pipeline:

```bash
./pcsec-privesc.sh --full --sarif --fail-on-risk 50
echo "exit code: $?"   # 1 se risk_score >= 50, senao 0
```

Combine com `--sarif` e o `github/codeql-action/upload-sarif` (ver
`.github/workflows/lint.yml` para um exemplo completo) para que os achados
apareçam diretamente na aba *Security* do GitHub.

## Exemplo de relatorio

Cada achado no relatorio (texto ou JSON) segue esta estrutura:

```
------------------------------------------------------------
Verificacao     : Scheduled Tasks (Cron) Audit
Alvo            : /etc/cron.d
Severidade      : CRITICAL (Configuracao confirmadamente insegura)
Descricao       : Diretorio de tarefas agendadas do sistema e gravavel
                  pelo usuario atual.
Evidencia       : Teste de permissao: diretorio gravavel = sim
Motivo          : Scripts colocados neste diretorio sao tipicamente
                  executados pelo cron do sistema com privilegios de root.
Recomendacao    : Corrija a permissao do diretorio imediatamente para
                  restringir escrita apenas a root.
Limitacoes      : Nenhum arquivo foi criado neste diretorio por esta
                  ferramenta.
```

No modo `--json`, o mesmo achado e emitido como um objeto estruturado
(com um campo `id` adicional, um hash estavel de `check`+`target`, usado
pelo `--compare`) dentro de um array `findings`. `--sarif` e `--html`
reaproveitam exatamente os mesmos dados.

## Estrutura do repositorio

```
linux-privesc/
├── pcsec-privesc.sh          # script principal (motor, banner, CLI, relatorios)
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── INSTALL.md
│   ├── USAGE.md
│   ├── FINDINGS.md
│   └── SECURITY.md
├── modules/
│   ├── system_info.sh
│   ├── sudo_audit.sh
│   ├── suid_sgid.sh
│   ├── capabilities.sh
│   ├── process_audit.sh
│   ├── cron_audit.sh
│   ├── permission_audit.sh
│   ├── kernel_audit.sh
│   ├── container_escape.sh      # novo na v5
│   ├── credential_hunting.sh    # novo na v5
│   └── correlate.sh             # novo na v5 (motor de correlacao)
├── tests/
│   └── test_core.bats
└── .github/
    └── workflows/
        └── lint.yml
```

O script principal verifica a existencia de cada modulo antes de carrega-lo
(dentro do subprocesso que o executa); se um modulo estiver ausente, a
auditoria continua com um aviso, sem interromper os demais.

## Testes automatizados

O projeto usa [Bats](https://github.com/bats-core/bats-core) para testes de
unidade (utilitarios puros) e de ponta a ponta (CLI real).

```bash
# Instalar o bats-core (uma vez)
git clone https://github.com/bats-core/bats-core.git /tmp/bats-core
sudo /tmp/bats-core/install.sh /usr/local

# Rodar a suite
bats tests/test_core.bats
```

O workflow `.github/workflows/lint.yml` roda, a cada push/PR:
1. **ShellCheck** no script principal e em todos os modulos.
2. A **suite Bats** completa.
3. Um **smoke test** que executa a ferramenta de verdade no runner do CI,
   com todas as saidas habilitadas, e valida que os 4 formatos de relatorio
   foram gerados corretamente.

## Limitacoes conhecidas

- As listas de binarios/*capabilities*/CVEs de referencia usadas para
  priorizar achados **nao sao exaustivas** e podem gerar falsos positivos
  ou negativos. A tabela de correlacao offline de CVEs de kernel em
  particular **nao considera backports de seguranca** aplicados pela
  distribuicao, que sao extremamente comuns — trate-a apenas como ponto de
  partida para consulta manual, nunca como confirmacao.
- A ferramenta **nao consulta bases de CVE automaticamente online**; a
  correlacao entre versao de kernel/SO e vulnerabilidades conhecidas e
  sempre majoritariamente manual.
- Verificacoes que dependem de ferramentas opcionais (`getcap`, `systemctl`,
  `sudo`, `crontab`) sao puladas de forma segura quando essas ferramentas
  nao estao disponiveis.
- A visibilidade de processos, regras `sudo` e arquivos depende diretamente
  do usuario com o qual a ferramenta e executada; rodar como usuario comum
  trara uma visao mais limitada do que rodar como root.
- O **motor de correlacao** cobre um numero limitado de cadeias de ataque
  pre-programadas; nao realiza analise de grafo generica como ferramentas
  dedicadas (ex. BloodHound para Active Directory).
- O modulo **Credential Hunting** usa deteccao puramente baseada em
  expressao regular sobre texto; gera falsos positivos (comentarios,
  placeholders) e nao detecta segredos codificados/ofuscados. Nao substitui
  scanners dedicados de secrets (gitleaks, trufflehog) para repositorios de
  codigo.
- Esta ferramenta **nao substitui** uma avaliacao manual aprofundada feita
  por um profissional de seguranca qualificado.

## Avisos de seguranca e uso responsavel

- Use esta ferramenta **apenas em sistemas para os quais voce possui
  autorizacao explicita** (ambiente proprio, laboratorio, ou contrato formal
  de pentest/auditoria).
- A ferramenta **nao executa exploits**, **nao escala privilegios
  automaticamente**, **nao modifica arquivos do sistema** e **nao desativa
  mecanismos de seguranca**.
- A ferramenta **nao transmite nenhum dado para servidores externos** — toda
  a analise e local, e os relatorios gerados ficam apenas no diretorio de
  saida escolhido por voce.
- Segredos, tokens, senhas e chaves privadas eventualmente encontrados
  **nunca sao impressos integralmente**; apenas sua presenca e sinalizada,
  com o valor redigido.
- Consulte [`docs/SECURITY.md`](docs/SECURITY.md) para a politica completa de
  divulgacao de problemas de seguranca no proprio projeto.

## Licenca

Este projeto esta licenciado sob a [Licenca MIT](LICENSE), que inclui um aviso
adicional de uso responsavel.

## Creditos

**Developed by PabloCyberSec.**
