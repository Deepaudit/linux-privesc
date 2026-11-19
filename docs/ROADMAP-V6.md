# PCSEC-PRIVESC v6.0 — Roadmap tecnico

Este documento registra a proposta de arquitetura para a v6.0, a partir do
feedback de auditoria da v5. Cada item abaixo e tratado como uma mudanca de
engenharia isolada, com objetivo de manter o principio da v5: **somente
leitura, zero exploits, zero exfiltracao**.

---

## [FEITO] Diferenciacao de impacto: rede vs escalacao de privilegios

**Problema identificado:** `modules/capabilities.sh` classificava `cap_net_raw`
na mesma lista de alto impacto que `cap_setuid`, `cap_sys_admin` e
`cap_dac_override`, resultando em HIGH para binarios como `ping` e
`mtr-packet` que usam a capability de forma legitima e esperada.

**Correcao aplicada (v6.0-dev):**
- Lista unica substituida por 3 tiers reais de potencial de escalacao:
  - `CRITICAL`: `cap_setuid`, `cap_setgid`, `cap_sys_module`, `cap_sys_admin`
    (trocam UID/GID efetivo ou carregam codigo no kernel — equivalente a
    root).
  - `HIGH`: `cap_dac_override`, `cap_dac_read_search`, `cap_sys_ptrace`,
    `cap_sys_rawio`, `cap_chown`, `cap_fowner` (contornam DAC ou interferem
    em outros processos — passo intermediario de uma cadeia).
  - `MEDIUM`/`LOW` (rede): `cap_net_raw`, `cap_net_admin`,
    `cap_net_bind_service` — impacto de rede real (sniffing, spoofing
    local), mas **nao** e vetor de escalacao de privilegios local.
- Baseline de binarios de rede conhecidos (`ping`, `mtr-packet`, `arping`,
  `dumpcap`, etc.) rebaixa para `LOW`/`info` com recomendacao de confirmar o
  pacote via `dpkg -S` / `rpm -qf` em vez de assumir malicioso.
- `PCSEC_CTX_HIGH_IMPACT_CAP_FILES` (consumido pelo Correlation Engine) agora
  so recebe arquivos CRITICAL/HIGH — capabilities de rede nao alimentam mais
  cadeias de ataque de escalacao local, o que tambem melhora a precisao do
  item "Falsos positivos" abaixo.

---

## 1. Deteccao inteligente de falsos positivos

**Abordagem:** um modulo transversal (`modules/baseline.sh`), carregado antes
dos demais e consultado por eles (nao um modulo que roda sozinho), com duas
camadas:

1. **Baselines por verificacao.** Hoje so `suid_sgid.sh` tem uma lista de
   "binarios SUID legitimos conhecidos". Padronizar isso em um formato
   comum (`check_id|caminho_ou_padrao|distro_opcional`) reutilizavel por
   `capabilities.sh` (ja feito acima), `sudo_audit.sh` (regras sudo padrao
   de pacotes conhecidos, ex. `(ALL) NOPASSWD: /usr/bin/apt` em certas
   imagens cloud-init) e `process_audit.sh`.
2. **Confianca ajustada, nao supressao.** Falso-positivo suspeito nunca
   desaparece do relatorio — ele e **reclassificado para severidade menor
   com confidence="info"** e ganha um campo novo `baseline_match` no JSON
   (`true`/`false`/`unchecked`). Isso preserva o principio de nunca omitir
   um achado, so evita inflar o risk score com ruido conhecido.
3. **Deteccao por contexto, nao so por caminho.** Além do path, cruzar com:
   dono do arquivo (root vs nao-root), se o caminho pertence a um pacote
   instalado (`dpkg -S`/`rpm -qf` quando disponivel, best-effort, nunca
   bloqueante) e se o binario foi modificado depois da instalacao do pacote
   (mtime do arquivo vs mtime do pacote, quando o gerenciador expoe isso).

**Formato de saida sugerido (novo campo no JSON de finding):**
```json
"baseline": { "matched": true, "source": "dpkg", "package": "iputils-ping" }
```

---

## 2. Correlacao de caminhos de escalacao (expandir `correlate.sh`)

Hoje `correlate.sh` tem 5 regras fixas (`if/then` direto). Para v6, propor
evoluir para um **motor de regras declarativas** sem reescrever a logica
toda vez:

```bash
# modules/correlate_rules.sh — cada regra e uma funcao pura que le PCSEC_CTX_*
# e retorna 0/1; o motor (correlate.sh) so orquestra e reporta.
_rule_docker_escape()   { ...; }
_rule_writable_systemd(){ ...; }
_rule_suid_plus_nopasswd(){ ...; }
```

Isso permite:
- Adicionar cadeias novas sem tocar no motor (ex.: `cap_setuid` CRITICAL em
  binario fora do baseline + usuario no grupo que pode executa-lo).
- Dar um **peso de confianca por cadeia** (nem toda combinacao e
  `confirmed`) em vez de só severidade fixa.
- Gerar um **grafo simples de caminho** no JSON (`attack_path: [stepA_id,
  stepB_id]`) referenciando os `id`s dos findings individuais que compõem a
  cadeia — isso é o que habilita o relatorio HTML a desenhar o caminho
  visualmente (item 5).

Cadeias novas que fazem sentido incluir dado o que os outros modulos ja
coletam: `cap_setuid`/`cap_sys_module` CRITICAL fora do baseline +
visibilidade do binario por outros usuarios; SSH key com permissao incorreta
+ `.ssh/authorized_keys` gravavel; credencial encontrada (Credential
Hunting) que corresponde a um servico com binario SUID relacionado.

---

## 3. CVEs por versao de pacote (alem do kernel)

`kernel_audit.sh` já faz isso só para o kernel. Propor um módulo novo,
`modules/package_cve.sh`, que:

1. Lista pacotes instalados via o gerenciador disponível (`dpkg -l`,
   `rpm -qa`), somente leitura.
2. Cruza contra uma **tabela offline local** (`data/cve-reference.tsv`,
   versionada no repo, não consulta online — mantém o princípio "zero rede"
   da ferramenta) no formato `pacote|versao_maxima_afetada|cve|descricao`,
   focada em pacotes classicamente relevantes para privesc local (sudo,
   polkit/policykit-1, util-linux, systemd, openssh, containerd/docker,
   shadow-utils) — não um clone do NVD inteiro.
3. Reporta sempre como `MEDIUM`/`potential`, nunca `CRITICAL`, com a mesma
   ressalva já presente em `kernel_audit.sh`: comparação textual de versão
   não detecta backport de segurança da distro.
4. Documentar explicitamente em `docs/FINDINGS.md` e no README que a tabela
   é curada manualmente e tem data de última atualização — isso é mais
   honesto do que fingir cobertura ampla, e evita o mesmo problema que o
   CHANGELOG já reconhece para a tabela de kernel.

---

## 4. Comparação de permissões com padrão esperado da distro

Estender `permission_audit.sh` com uma tabela de referência
`modo_esperado|dono_esperado|caminho` para arquivos críticos
(`/etc/passwd 644 root`, `/etc/shadow 640 root:shadow` ou `000 root` a
depender da distro, `/etc/sudoers 440 root:root`, etc.), com **variantes por
família de distro** (Debian/RHEL/Arch divergem em alguns casos, ex. grupo
`shadow` não existe em todo lugar). Detecção de família via `/etc/os-release`
(`ID`/`ID_LIKE`), já lido em `system_info.sh` — reaproveitar o contexto em
vez de ler de novo.

Saída: além do "é gravável por outros" (já existe), reportar
`"desvio_do_padrao": "modo atual 666, esperado 640 (Debian)"` quando o modo
real diverge do esperado mesmo sem ser trivialmente explorável — isso
cobre hardening incompleto que hoje passa batido se não for literalmente
world-writable.

---

## 5. Relatório HTML com identidade visual PabloCyberSec

O `--html` atual (linha ~683 de `pcsec-privesc.sh`) já gera HTML standalone
filtrável por severidade. Para v6, proposta de evolução sem reescrever o
motor de dados:

- Extrair o CSS/branding para um bloco único no topo do heredoc, com
  variáveis de marca (paleta, logo em SVG inline do ASCII art do banner,
  tipografia) fáceis de versionar e reaproveitar caso vocês criem outras
  ferramentas sob o mesmo selo PabloCyberSec.
- Seção de resumo executivo no topo (risk score, contagem por severidade,
  já calculados) com destaque visual maior do que hoje.
- Se o item 2 (correlação) ganhar `attack_path` no JSON, renderizar esses
  findings agrupados visualmente como uma cadeia (lista ordenada com seta),
  não misturados no grid geral.
- Marca d'água/rodapé "Gerado por PCSEC-PRIVESC · PabloCyberSec" + timestamp
  e hash do host (já existe hash de finding, reaproveitar padrão).

---

## Ordem sugerida de implementação

1. ~~Capabilities tiers (rede vs privesc)~~ — feito.
2. Baseline/falsos-positivos (item 1) — é pré-requisito de qualidade de
   sinal para os itens 2–4, então faz sentido vir antes.
3. Correlação declarativa (item 2) — depende de baseline para não gerar
   cadeias a partir de falso-positivo.
4. CVE por pacote (item 3) e permissões por distro (item 4) — independentes
   entre si, podem ser paralelos.
5. HTML com identidade visual (item 5) — por último, pois consome os campos
   novos (`baseline`, `attack_path`) dos itens anteriores.
