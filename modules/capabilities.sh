#!/usr/bin/env bash
#
# modules/capabilities.sh
# Modulo: Verificacao de Linux capabilities em arquivos.
# Apenas leitura via 'getcap'. Nenhuma capability e adicionada ou removida.

# Capabilities classificadas por POTENCIAL REAL DE ESCALACAO DE PRIVILEGIOS,
# nao apenas por "parecer perigosa". Uma capability so entra em CRITICAL/HIGH
# quando ha uma tecnica publica conhecida de usa-la para virar root ou
# contornar controles de acesso do kernel. cap_net_raw e similares concedem
# acesso privilegiado de REDE, nao de escalacao de privilegios local, e por
# isso NUNCA devem herdar a mesma severidade de cap_setuid/cap_sys_admin.
#
# CRITICAL: concede controle quase equivalente a root (consegue trocar
#           UID/GID efetivo diretamente ou carregar codigo no kernel).
_PCSEC_CRITICAL_PRIVESC_CAPS=(
  "cap_setuid" "cap_setgid" "cap_sys_module" "cap_sys_admin"
)
# HIGH: nao troca UID por si so, mas permite contornar controles de acesso
#       a arquivos (DAC) ou interferir em outros processos - tipicamente o
#       passo seguinte de uma cadeia de escalacao (ex: ler /etc/shadow,
#       sobrescrever binario de outro usuario, ptrace em processo root).
_PCSEC_HIGH_PRIVESC_CAPS=(
  "cap_dac_override" "cap_dac_read_search" "cap_sys_ptrace"
  "cap_sys_rawio" "cap_chown" "cap_fowner"
)
# MEDIUM: capabilities de REDE. Permitem forjar/capturar pacotes brutos ou
#         bind em portas privilegiadas - impacto real existe (sniffing,
#         spoofing, MITM local), mas NAO e um vetor de escalacao de
#         privilegios local por si so. ping, mtr-packet, traceroute e
#         similares usam cap_net_raw de forma legitima e esperada.
_PCSEC_NETWORK_IMPACT_CAPS=(
  "cap_net_raw" "cap_net_admin" "cap_net_bind_service"
)

# Contexto exportado para o motor de correlacao (apenas caps com potencial
# real de escalacao local; capabilities de rede ficam de fora de propósito).
PCSEC_CTX_HIGH_IMPACT_CAP_FILES=""

# Binarios conhecidos que legitimamente recebem cap_net_raw via pacote da
# distro (lista nao exaustiva, apenas para reduzir ruido/falso positivo).
_PCSEC_NET_RAW_BASELINE=(
  "/bin/ping" "/usr/bin/ping" "/bin/ping6" "/usr/bin/ping6"
  "/usr/bin/mtr-packet" "/usr/lib/mtr/mtr-packet" "/usr/sbin/arping"
  "/usr/bin/dumpcap" "/usr/bin/traceroute6.iputils"
)

_pcsec_match_cap_list() {
  local line_lower="$1"; shift
  local cap
  for cap in "$@"; do
    if echo "$line_lower" | grep -q "$cap"; then
      return 0
    fi
  done
  return 1
}

_pcsec_cap_tier() {
  # Ecoa uma de: critical | high | medium(net) | low
  local line_lower
  line_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
  if _pcsec_match_cap_list "$line_lower" "${_PCSEC_CRITICAL_PRIVESC_CAPS[@]}"; then
    echo "critical"; return 0
  fi
  if _pcsec_match_cap_list "$line_lower" "${_PCSEC_HIGH_PRIVESC_CAPS[@]}"; then
    echo "high"; return 0
  fi
  if _pcsec_match_cap_list "$line_lower" "${_PCSEC_NETWORK_IMPACT_CAPS[@]}"; then
    echo "network"; return 0
  fi
  echo "low"
}

_pcsec_is_net_raw_baseline() {
  local path="$1" known
  for known in "${_PCSEC_NET_RAW_BASELINE[@]}"; do
    [ "$path" = "$known" ] && return 0
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
    local filepath tier
    filepath="$(echo "$line" | awk -F' = ' '{print $1}' | sed 's/[[:space:]]*$//')"
    tier="$(_pcsec_cap_tier "$line")"

    case "$tier" in
      critical)
        PCSEC_CTX_HIGH_IMPACT_CAP_FILES="${PCSEC_CTX_HIGH_IMPACT_CAP_FILES}${filepath};"
        report_finding \
          "Linux Capabilities" \
          "$filepath" \
          "Arquivo possui capability que permite trocar UID/GID efetivo ou carregar modulos de kernel - equivalente, na pratica, a um caminho direto para root." \
          "$(echo "$line" | cut -c1-300)" \
          "CRITICAL" \
          "cap_setuid/cap_setgid permitem ao processo assumir qualquer UID/GID; cap_sys_module permite carregar codigo arbitrario no kernel; cap_sys_admin e um superconjunto que cobre diversas operacoes privilegiadas. Em qualquer um desses casos, controlar a execucao do binario tende a equivaler a controlar root." \
          "Remova a capability com 'setcap -r' imediatamente, a menos que haja uma justificativa documentada e o binario seja estritamente controlado (sem interface exposta a input de usuario nao confiavel)." \
          "A presenca da capability nao confirma exploracao automatica; depende de como o binario a utiliza internamente e de quem pode executa-lo/fornecer-lhe input." \
          "potential"
        ;;
      high)
        PCSEC_CTX_HIGH_IMPACT_CAP_FILES="${PCSEC_CTX_HIGH_IMPACT_CAP_FILES}${filepath};"
        report_finding \
          "Linux Capabilities" \
          "$filepath" \
          "Arquivo possui capability que contorna controles de acesso a arquivos (DAC) ou permite interferir em outros processos - tipicamente usada como passo intermediario em uma cadeia de escalacao." \
          "$(echo "$line" | cut -c1-300)" \
          "HIGH" \
          "cap_dac_override/cap_dac_read_search ignoram permissoes de leitura/escrita de arquivo; cap_sys_ptrace permite anexar a processos de outros usuarios (incluindo root, se visivel); cap_chown/cap_fowner alteram dono/permissoes arbitrariamente. Nenhuma delas troca o UID diretamente, mas todas facilitam o proximo passo de uma escalacao." \
          "Avalie se a capability e estritamente necessaria para a funcao do binario; remova com 'setcap -r' apos validacao e testes." \
          "A presenca da capability nao confirma exploracao automatica; depende de como o binario a utiliza internamente." \
          "potential"
        ;;
      network)
        if _pcsec_is_net_raw_baseline "$filepath"; then
          report_finding \
            "Linux Capabilities" \
            "$filepath" \
            "Capability de rede (ex. cap_net_raw/cap_net_admin) presente em binario que corresponde a um utilitario de rede conhecido e amplamente distribuido com essa capability por padrao." \
            "$(echo "$line" | cut -c1-300) | Baseline: caminho reconhecido como uso legitimo tipico de distro" \
            "LOW" \
            "cap_net_raw concede acesso a sockets raw (criar/forjar pacotes, usado por ping/traceroute/ferramentas de diagnostico) e cap_net_admin a configuracao de rede. Isso NAO equivale a cap_setuid/cap_sys_admin/cap_dac_override: nao concede troca de UID nem bypass de permissao de arquivo, logo nao e por si so um vetor de escalacao de privilegios local." \
            "Confirme que o binario corresponde mesmo ao pacote oficial da distro (ex.: 'dpkg -S $filepath' ou 'rpm -qf $filepath') e que nao foi substituido por algo malicioso com o mesmo nome/capability." \
            "Classificacao de baseline por caminho de arquivo, nao por hash/assinatura; um binario malicioso colocado no mesmo caminho nao seria diferenciado por esta checagem." \
            "info"
        else
          report_finding \
            "Linux Capabilities" \
            "$filepath" \
            "Capability de rede (ex. cap_net_raw/cap_net_admin) presente em um binario fora da lista de referencia de utilitarios de rede conhecidos - vale revisar o motivo." \
            "$(echo "$line" | cut -c1-300)" \
            "MEDIUM" \
            "Capabilities de rede permitem sniffing/spoofing/MITM local e configuracao de interfaces, o que e um risco real de rede, mas distinto de escalacao de privilegios local: nao concedem troca de UID nem bypass de permissao de arquivo (ao contrario de cap_setuid/cap_sys_admin/cap_dac_override, reportadas separadamente como CRITICAL/HIGH)." \
            "Confirme se o binario realmente precisa de acesso a sockets raw/configuracao de rede; remova a capability com 'setcap -r' se nao for o caso." \
            "Classificacao baseada em lista de referencia nao exaustiva de binarios de rede legitimos conhecidos." \
            "potential"
        fi
        ;;
      *)
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
        ;;
    esac
  done <<< "$results"
}
