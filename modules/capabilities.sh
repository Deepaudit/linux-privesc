#!/usr/bin/env bash
#
# modules/capabilities.sh
# Modulo: Verificacao de Linux capabilities em arquivos.
# Apenas leitura via 'getcap'. Nenhuma capability e adicionada ou removida.

# Capabilities consideradas de alto impacto quando atribuidas a um binario
# de usuario comum (lista nao exaustiva, apenas para priorizacao).
_PCSEC_HIGH_IMPACT_CAPS=(
  "cap_setuid" "cap_setgid" "cap_sys_admin" "cap_dac_override"
  "cap_dac_read_search" "cap_sys_ptrace" "cap_sys_module" "cap_net_raw"
  "cap_sys_rawio" "cap_chown" "cap_fowner"
)

# Contexto exportado para o motor de correlacao
PCSEC_CTX_HIGH_IMPACT_CAP_FILES=""

_pcsec_cap_is_high_impact() {
  local line_lower
  line_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  local cap
  for cap in "${_PCSEC_HIGH_IMPACT_CAPS[@]}"; do
    if echo "$line_lower" | grep -q "$cap"; then
      return 0
    fi
  done
  return 1
}

module_capabilities() {
  # Capabilities do PROCESSO ATUAL (nao de arquivos): util para saber se o
  # proprio shell da auditoria ja herda alguma capability incomum (ex. dentro
  # de um container mal configurado). Somente leitura de /proc/self/status.
  if [ -r /proc/self/status ]; then
    local cap_eff
    cap_eff="$(grep -i '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')"
    if [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ]; then
      report_finding \
        "Linux Capabilities" \
        "Processo atual (CapEff)" \
        "O processo atual (shell da auditoria) possui capabilities efetivas diferentes de zero, o que e incomum para um processo de usuario comum fora de containers." \
        "CapEff (bitmask hexadecimal): $cap_eff | Fonte: /proc/self/status" \
        "MEDIUM" \
        "Capabilities efetivas no proprio processo podem indicar execucao dentro de um container com --privileged, um namespace mal configurado, ou um binario SUID/capability-aware no caminho de execucao do shell." \
        "Decodifique o bitmask (ex. com 'capsh --decode=$cap_eff') e avalie se o ambiente de execucao e o esperado." \
        "Esta ferramenta nao decodifica automaticamente o bitmask para nomes de capability; interpretacao manual e necessaria." \
        "potential"
    else
      report_finding \
        "Linux Capabilities" \
        "Processo atual (CapEff)" \
        "O processo atual nao possui capabilities efetivas alem do padrao esperado para um processo de usuario comum." \
        "CapEff: $cap_eff | Fonte: /proc/self/status" \
        "INFO" \
        "Resultado esperado fora de containers privilegiados." \
        "Nenhuma acao necessaria." \
        "N/A" \
        "info"
    fi
  fi

  if ! has_cmd getcap; then
    report_finding \
      "Linux Capabilities" \
      "getcap (binario)" \
      "A ferramenta 'getcap' nao foi encontrada; a verificacao de capabilities em arquivos foi pulada." \
      "command -v getcap -> nao encontrado" \
      "INFO" \
      "Sem 'getcap' (pacote libcap2-bin / libcap), esta verificacao nao pode ser executada." \
      "Instale o pacote que fornece 'getcap' (ex.: libcap2-bin no Debian/Ubuntu) para habilitar esta checagem futuramente." \
      "Nenhum dado coletado nesta execucao." \
      "info"
    return 0
  fi

  local dirs="/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin /opt"
  local results
  # getcap -r pode ser lento/ruidoso em arvores muito grandes; limitamos aos
  # diretorios tipicos de binarios para manter a execucao rapida e previsivel.
  results="$(getcap -r $dirs 2>/dev/null)"

  if [ -z "$results" ]; then
    report_finding \
      "Linux Capabilities" \
      "Diretorios padrao de binarios" \
      "Nenhum arquivo com capabilities explicitas foi encontrado nos diretorios verificados." \
      "Diretorios pesquisados: $dirs" \
      "INFO" \
      "Ausencia de resultados e o cenario mais comum em sistemas sem configuracoes customizadas." \
      "Nenhuma acao necessaria." \
      "Busca limitada a diretorios comuns; capabilities em outros caminhos nao foram verificadas." \
      "info"
    return 0
  fi

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local filepath
    filepath="$(echo "$line" | awk -F' = ' '{print $1}' | sed 's/[[:space:]]*$//')"

    if _pcsec_cap_is_high_impact "$line"; then
      PCSEC_CTX_HIGH_IMPACT_CAP_FILES="${PCSEC_CTX_HIGH_IMPACT_CAP_FILES}${filepath};"
      report_finding \
        "Linux Capabilities" \
        "$filepath" \
        "Arquivo possui capability(ies) de alto impacto que podem conceder acesso privilegiado a recursos do kernel." \
        "$(echo "$line" | cut -c1-300)" \
        "HIGH" \
        "Capabilities como cap_setuid, cap_sys_admin ou cap_dac_override podem permitir, em certas condicoes, elevar privilegios efetivos do processo." \
        "Avalie se a capability e estritamente necessaria; remova com 'setcap -r' apos validacao e testes." \
        "A presenca da capability nao confirma exploracao automatica; depende de como o binario a utiliza internamente." \
        "potential"
    else
      report_finding \
        "Linux Capabilities" \
        "$filepath" \
        "Arquivo possui capabilities configuradas, de impacto considerado mais limitado pela lista de referencia utilizada." \
        "$(echo "$line" | cut -c1-300)" \
        "LOW" \
        "Capabilities especificas (ex. cap_net_bind_service) costumam ter escopo restrito, mas ainda merecem revisao." \
        "Confirme se a capability corresponde ao uso legitimo esperado do binario." \
        "Classificacao baseada em lista de referencia nao exaustiva." \
        "info"
    fi
  done <<< "$results"
}
