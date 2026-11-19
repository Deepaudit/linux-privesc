#!/usr/bin/env bash
#
# modules/correlate.sh
# Motor de CORRELACAO. Executa por ultimo, depois de todos os demais modulos.
# Nao coleta dados novos: apenas combina sinais (variaveis PCSEC_CTX_*)
# exportados pelos outros modulos durante a mesma execucao para montar
# "cadeias de ataque" (attack paths) quando duas ou mais condicoes isoladas,
# juntas, formam um caminho de escalacao muito mais forte do que cada
# achado individual sugere sozinho.
#
# Este modulo NUNCA executa nada privilegiado; apenas le variaveis em
# memoria definidas por module_* anteriores nesta mesma execucao do script.

module_correlate() {
  local chains_found=0

  # --- Cadeia 1: grupo docker/socket gravavel + binario docker presente ---
  if { [ "${PCSEC_CTX_DOCKER_SOCK_WRITABLE:-0}" -eq 1 ] || [ "${PCSEC_CTX_IN_DOCKER_GROUP:-0}" -eq 1 ]; } && has_cmd docker; then
    chains_found=$((chains_found + 1))
    report_finding \
      "Correlation Engine - Attack Path" \
      "Escalacao via Docker (grupo/socket + binario presente)" \
      "Combinacao de acesso ao socket/grupo Docker e presenca do binario 'docker' no PATH do usuario atual." \
      "Sinais combinados: acesso docker=sim (grupo ou socket) | binario docker no PATH=sim" \
      "CRITICAL" \
      "Isoladamente, pertencer ao grupo docker ou ter o binario instalado sao achados de risco moderado a alto. Combinados, eles formam um caminho PRATICO e de alta confianca para obtencao de privilegios de root no host, pois o usuario pode efetivamente montar o filesystem raiz do host dentro de um container que ele mesmo controla." \
      "Trate esta combinacao com prioridade maxima: remova o usuario do grupo docker caso nao seja estritamente necessario, ou migre para uma solucao rootless." \
      "Esta ferramenta NAO tenta criar ou rodar nenhum container para confirmar; a cadeia e inferida a partir de achados de leitura/permissao obtidos nesta mesma execucao." \
      "confirmed"
  fi

  # --- Cadeia 2: systemd dir gravavel + systemctl disponivel (controle real do servico) ---
  if [ "${PCSEC_CTX_WRITABLE_SYSTEMD_DIR:-0}" -eq 1 ] && has_cmd systemctl; then
    chains_found=$((chains_found + 1))
    report_finding \
      "Correlation Engine - Attack Path" \
      "Escalacao via unit file systemd + systemctl disponivel" \
      "Diretorio de unidades systemd gravavel combinado com a ferramenta systemctl disponivel ao usuario." \
      "Sinais combinados: diretorio de unit files gravavel=sim | systemctl no PATH=sim" \
      "HIGH" \
      "A capacidade de escrever um unit file sozinha ja e grave; com 'systemctl' tambem disponivel, o caminho para registrar e (se houver permissao adicional) iniciar um servico malicioso fica mais direto, dependendo apenas de permissao de start/reload." \
      "Corrija a permissao do diretorio de unidades imediatamente; audite tambem quais acoes systemctl o usuario pode executar (via sudo -l, ja auditado separadamente)." \
      "Nao confirma que o usuario tem permissao para efetivamente iniciar/recarregar o servico malicioso; essa etapa requer validacao manual adicional." \
      "potential"
  fi

  # --- Cadeia 3: sudo NOPASSWD arriscado + SUID watchlist hit fora de local legitimo ---
  if [ "${PCSEC_CTX_SUDO_NOPASSWD_RISKY:-0}" -eq 1 ] && [ -n "${PCSEC_CTX_SUID_WATCH_HITS:-}" ]; then
    chains_found=$((chains_found + 1))
    report_finding \
      "Correlation Engine - Attack Path" \
      "Multiplos vetores independentes de escalacao local disponiveis" \
      "O sistema apresenta simultaneamente uma regra sudo NOPASSWD de alto risco E ao menos um binario SUID fora de localizacao padrao conhecida." \
      "Sinais combinados: sudo NOPASSWD arriscado=sim | binarios SUID suspeitos: ${PCSEC_CTX_SUID_WATCH_HITS}" \
      "HIGH" \
      "A presenca de MULTIPLOS vetores de escalacao independentes no mesmo host aumenta significativamente a probabilidade de que pelo menos um seja explorável, alem de sugerir uma postura geral de hardening fraca que provavelmente afeta outras areas nao cobertas por esta ferramenta." \
      "Priorize a remediacao de ambos os achados individuais (ja detalhados em suas secoes especificas) e considere uma revisao de hardening mais ampla do host." \
      "Esta e uma inferencia de prioridade com base em dois achados distintos ja reportados individualmente; nao implica que os dois vetores estao tecnicamente relacionados entre si." \
      "potential"
  fi

  # --- Cadeia 4: /etc/passwd ou /etc/shadow gravavel (ja CRITICAL isolado, mas reforça prioridade maxima) ---
  if [ "${PCSEC_CTX_SHADOW_WRITABLE:-0}" -eq 1 ] || [ "${PCSEC_CTX_PASSWD_WRITABLE:-0}" -eq 1 ]; then
    chains_found=$((chains_found + 1))
    report_finding \
      "Correlation Engine - Attack Path" \
      "Caminho direto de root confirmado" \
      "Arquivo /etc/passwd e/ou /etc/shadow gravavel pelo usuario atual, representando o caminho de escalacao de privilegios mais direto possivel em um sistema Linux." \
      "Sinais: passwd gravavel=${PCSEC_CTX_PASSWD_WRITABLE:-0} | shadow gravavel=${PCSEC_CTX_SHADOW_WRITABLE:-0}" \
      "CRITICAL" \
      "Com escrita em /etc/passwd e possivel adicionar uma entrada de usuario com UID 0 (root) sem senha. Esta e a prioridade numero 1 de remediacao em qualquer auditoria." \
      "Corrija a permissao do(s) arquivo(s) AGORA, antes de qualquer outra remediacao desta auditoria. Revise tambem como a permissao incorreta foi introduzida (configuracao manual, script de deploy, etc.)." \
      "Ja reportado individualmente na secao File Permission Analysis; este achado apenas eleva a prioridade de remediacao no resumo executivo." \
      "confirmed"
  fi

  # --- Cadeia 5: cron gravavel (sistema) + ambiente de container ---
  if [ "${PCSEC_CTX_CRON_WRITABLE:-0}" -eq 1 ] && [ -f /.dockerenv ]; then
    chains_found=$((chains_found + 1))
    report_finding \
      "Correlation Engine - Attack Path" \
      "Cron gravavel dentro de ambiente containerizado" \
      "Diretorio/arquivo de cron do sistema gravavel detectado dentro de um ambiente identificado como container." \
      "Sinais combinados: cron do sistema gravavel=sim | ambiente=container (/.dockerenv presente)" \
      "MEDIUM" \
      "Dentro de um container, escrever em cron do sistema geralmente compromete apenas o container (nao o host diretamente), a menos que haja um vetor adicional de escape de container tambem presente (ver secao Container Escape Audit)." \
      "Corrija a permissao do cron mesmo dentro do container, como boa pratica de defesa em profundidade, e correlacione com os achados da secao Container Escape Audit." \
      "A severidade real depende de outros achados de escape de container presentes nesta mesma execucao." \
      "potential"
  fi

  if [ "$chains_found" -eq 0 ]; then
    report_finding \
      "Correlation Engine - Attack Path" \
      "Analise de cadeias de ataque" \
      "Nenhuma combinacao conhecida de sinais independentes foi identificada nesta execucao." \
      "Regras de correlacao avaliadas: Docker (grupo/socket+binario), systemd gravavel+systemctl, sudo NOPASSWD+SUID suspeito, passwd/shadow gravavel, cron gravavel+container" \
      "INFO" \
      "Ausencia de cadeias conhecidas reduz a chance de um caminho trivial de escalacao, mas nao elimina riscos individuais ja listados nas demais secoes." \
      "Revise os achados individuais de cada modulo normalmente; este resumo cobre apenas combinacoes pre-definidas." \
      "O motor de correlacao cobre um numero limitado de cadeias conhecidas e pre-programadas; nao realiza analise de grafo generica como ferramentas dedicadas (ex. BloodHound para Active Directory)." \
      "info"
  fi
}
