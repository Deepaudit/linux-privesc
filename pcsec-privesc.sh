#!/usr/bin/env bash
#
# pcsec-privesc.sh
#
# PabloCyberSec Linux Privilege Escalation (PCSEC-PRIVESC) - v5
# Ferramenta de auditoria de seguranca para identificar configuracoes
# inseguras e possiveis vetores de escalacao de privilegios em sistemas
# Linux AUTORIZADOS para auditoria.
#
# Desenvolvido por: PabloCyberSec
# Licenca: MIT (ver arquivo LICENSE)
#
# AVISO: esta ferramenta executa SOMENTE verificacoes locais de leitura.
# Ela NAO explora vulnerabilidades, NAO escala privilegios automaticamente,
# NAO modifica o sistema e NAO envia dados para servidores externos.
# Use apenas em sistemas para os quais voce tem autorizacao explicita.
#
# -----------------------------------------------------------------------------
# NOVIDADES DA v5 (resumo - ver CHANGELOG.md para detalhes completos):
#   - Cada modulo roda como subprocesso isolado, com timeout configuravel
#     (--timeout) e execucao opcionalmente paralela (--jobs N).
#   - Novos modulos: Container Escape Audit e Credential Hunting.
#   - Motor de correlacao (Correlation Engine) que combina achados
#     independentes em "cadeias de ataque" (attack paths).
#   - Risk score agregado do host (--fail-on-risk para uso em CI/CD).
#   - Saida adicional em SARIF (--sarif) e relatorio HTML standalone (--html).
#   - Comparacao entre execucoes (--compare arquivo.json) para tracking de
#     hardening ao longo do tempo.
# -----------------------------------------------------------------------------
set -u
# Nao usamos "set -e" de proposito: uma verificacao que falha nao deve
# interromper a auditoria completa. Erros sao tratados localmente.

# -----------------------------------------------------------------------------
# Metadados do projeto
# -----------------------------------------------------------------------------
PCSEC_NAME="PabloCyberSec Linux Privilege Escalation"
PCSEC_SHORTNAME="PCSEC-PRIVESC"
PCSEC_VERSION="5.0.0"
PCSEC_AUTHOR="PabloCyberSec"

# Diretorio onde o script esta localizado (para localizar modules/)
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do
  SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

# -----------------------------------------------------------------------------
# Estado global / configuracao de execucao
# -----------------------------------------------------------------------------
USE_COLOR=1
JSON_OUTPUT=0
SARIF_OUTPUT=0
HTML_OUTPUT=0
OUTPUT_DIR=""
SCAN_MODE="full"      # "quick" ou "full"
LIST_CHECKS_ONLY=0
PARALLEL_JOBS=1
MODULE_TIMEOUT=60
COMPARE_FILE=""
FAIL_ON_RISK=""        # vazio = nao avalia exit code por risco

# Contadores de severidade (associativo)
declare -A SEV_COUNT=( [INFO]=0 [LOW]=0 [MEDIUM]=0 [HIGH]=0 [CRITICAL]=0 )
TOTAL_FINDINGS=0
RISK_SCORE=0

# Buffers de relatorio (preenchidos pelo motor de merge apos cada modulo)
REPORT_LINES=()        # relatorio humano (texto)
JSON_FINDINGS=()       # objetos JSON (um por achado) - sempre construido em memoria

# Timestamp da execucao (usado em nomes de arquivos de saida)
RUN_TIMESTAMP="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "run")"

# Cache de resolucao de comandos (evita repetir 'command -v' varias vezes)
declare -A _PCSEC_CMD_CACHE=()

# Diretorio temporario onde os subprocessos de modulo escrevem seus achados
# e variaveis de contexto. Criado em main(), removido ao final.
PCSEC_PARALLEL_DIR=""

# Contador de achados DENTRO do processo atual (modulo ou motor principal).
# Reiniciado automaticamente em cada novo processo (subshell/subprocess).
PCSEC_FINDING_SEQ=0

# Lista de modulos disponiveis (nome_funcao:descricao:arquivo)
# Mantida centralmente para suportar --checks e carregamento ordenado.
# module_correlate e tratado de forma especial: roda sempre por ULTIMO,
# depois de todos os demais modulos selecionados terminarem, pois depende
# do contexto (PCSEC_CTX_*) exportado pelos outros.
MODULE_LIST=(
  "module_system_info|System Enumeration|system_info.sh"
  "module_sudo_audit|Sudo Configuration Audit|sudo_audit.sh"
  "module_suid_sgid|SUID / SGID Audit|suid_sgid.sh"
  "module_capabilities|Linux Capabilities|capabilities.sh"
  "module_process_audit|Process & Service Audit|process_audit.sh"
  "module_cron_audit|Scheduled Tasks (Cron) Audit|cron_audit.sh"
  "module_permission_audit|File Permission Analysis|permission_audit.sh"
  "module_kernel_audit|Kernel & Update Audit|kernel_audit.sh"
  "module_container_escape|Container Escape Audit|container_escape.sh"
  "module_credential_hunting|Credential Hunting|credential_hunting.sh"
  "module_correlate|Correlation Engine - Attack Path|correlate.sh"
)

# Modulos considerados "basicos" para --quick (mais rapidos / menor custo).
# module_correlate e adicionado automaticamente ao final em ambos os modos.
QUICK_MODULES=("module_system_info" "module_sudo_audit" "module_kernel_audit" "module_suid_sgid")

# -----------------------------------------------------------------------------
# Cores ANSI (definidas apos deteccao de suporte do terminal)
# -----------------------------------------------------------------------------
setup_colors() {
  if [ "$USE_COLOR" -eq 1 ] && [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    C_RED="\033[0;31m"
    C_RED_BOLD="\033[1;31m"
    C_RED_INTENSE="\033[1;91m"
    C_GREEN="\033[0;32m"
    C_YELLOW="\033[0;33m"
    C_WHITE="\033[1;37m"
    C_GRAY="\033[0;90m"
    C_CYAN="\033[0;36m"
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
  else
    C_RED=""; C_RED_BOLD=""; C_RED_INTENSE=""; C_GREEN=""; C_YELLOW=""
    C_WHITE=""; C_GRAY=""; C_CYAN=""; C_RESET=""; C_BOLD=""
  fi
  export C_RED C_RED_BOLD C_RED_INTENSE C_GREEN C_YELLOW C_WHITE C_GRAY C_CYAN C_RESET C_BOLD
}

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
print_banner() {
  printf "\n"
  printf "${C_RED_BOLD}  ____   ____ ____  _____ ____ ${C_RESET}\n"
  printf "${C_RED_BOLD} |  _ \\ / ___/ ___|| ____/ ___|${C_RESET}\n"
  printf "${C_RED_BOLD} | |_) | |   \\___ \\|  _|| |    ${C_RESET}\n"
  printf "${C_RED_BOLD} |  __/| |___ ___) | |__| |___ ${C_RESET}\n"
  printf "${C_RED_BOLD} |_|    \\____|____/|_____\\____|${C_RESET}\n"
  printf "\n"
  printf "${C_WHITE}  PABLOCYBERSEC${C_RESET}\n"
  printf "${C_WHITE}  LINUX PRIVILEGE ESCALATION${C_RESET}\n"
  printf "${C_GRAY}  Security Auditing & Misconfiguration Analysis${C_RESET}\n"
  printf "${C_GRAY}  Developed by %s${C_RESET}\n" "$PCSEC_AUTHOR"
  printf "${C_GRAY}  Version %s${C_RESET}\n" "$PCSEC_VERSION"
  printf "\n"
  printf "${C_YELLOW}  AVISO: use apenas em sistemas com autorizacao explicita.${C_RESET}\n"
  printf "${C_YELLOW}  Nenhum exploit e executado. Nenhuma alteracao e feita.${C_RESET}\n"
  printf "\n"
}

# -----------------------------------------------------------------------------
# Ajuda / versao
# -----------------------------------------------------------------------------
print_help() {
  cat <<EOF
$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION
Developed by $PCSEC_AUTHOR

Uso:
  ./pcsec-privesc.sh [opcoes]

Opcoes basicas:
  --help               Mostra esta ajuda e encerra.
  --version            Mostra a versao e encerra.
  --quick              Executa apenas as verificacoes basicas (mais rapidas).
  --full               Executa todas as verificacoes implementadas (padrao).
  --no-color           Desativa cores na saida do terminal.
  --output DIR         Define o diretorio onde os relatorios serao salvos.
                        (padrao: ./pcsec-reports)
  --checks             Lista todos os modulos/verificacoes disponiveis e sai.

Saidas adicionais:
  --json               Gera relatorio estruturado em JSON.
  --sarif               Gera relatorio em formato SARIF 2.1.0 (CI/CD, GitHub
                        Code Scanning, SonarQube, etc).
  --html                Gera um relatorio HTML standalone, navegavel por
                        severidade (nao requer servidor nem internet).

Execucao / performance:
  --jobs N              Executa ate N modulos em paralelo (padrao: 1 =
                        sequencial). Cada modulo roda isolado em subprocesso.
  --timeout SEGUNDOS     Tempo maximo por modulo antes de ser interrompido
                        (padrao: 60). Um modulo que estoura o timeout e
                        reportado como INFO e a auditoria continua.

Tracking / CI:
  --compare ARQUIVO.json Compara esta execucao com um relatorio JSON de uma
                        execucao anterior e mostra achados novos/resolvidos.
  --fail-on-risk N       Encerra com exit code 1 se o risk score agregado
                        desta execucao for >= N. Util em pipelines de CI
                        para bloquear merges em hosts/imagens inseguras.

Exemplos:
  ./pcsec-privesc.sh --full
  ./pcsec-privesc.sh --quick --no-color
  ./pcsec-privesc.sh --full --json --sarif --html --output /tmp/auditoria
  ./pcsec-privesc.sh --full --jobs 4 --timeout 30
  ./pcsec-privesc.sh --full --json --compare ./pcsec-reports/relatorio-anterior.json
  ./pcsec-privesc.sh --full --fail-on-risk 50   # uso tipico em CI

Importante:
  - Esta ferramenta realiza apenas verificacoes locais de leitura.
  - Nao executa exploits, nao escala privilegios e nao altera o sistema.
  - Nao requer privilegios root para as verificacoes basicas.
  - Nao transmite nenhum dado para servidores externos.

Use somente em sistemas para os quais voce possui autorizacao.
EOF
}

print_version() {
  echo "$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION - by $PCSEC_AUTHOR"
}

print_checks_list() {
  echo "$PCSEC_SHORTNAME - Verificacoes disponiveis:"
  echo ""
  local entry fn desc file
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    printf "  - %-26s %s  (modules/%s)\n" "$fn" "$desc" "$file"
  done
  echo ""
  echo "Use --quick para um subconjunto basico, ou --full para todas."
  echo "module_correlate roda sempre por ultimo, apos os demais modulos selecionados."
}

# -----------------------------------------------------------------------------
# Utilitarios gerais
# -----------------------------------------------------------------------------

# Verifica se um comando existe no PATH, com cache em memoria (processo atual).
has_cmd() {
  local c="$1"
  if [ "${_PCSEC_CMD_CACHE[$c]+set}" = "set" ]; then
    [ "${_PCSEC_CMD_CACHE[$c]}" = "1" ]
    return
  fi
  if command -v "$c" >/dev/null 2>&1; then
    _PCSEC_CMD_CACHE[$c]=1
    return 0
  else
    _PCSEC_CMD_CACHE[$c]=0
    return 1
  fi
}

# Escapa uma string para uso seguro dentro de JSON
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

# Redige valores potencialmente sensiveis antes de qualquer impressao/relatorio.
# Uso: redacted="$(redact_secret "$valor")"
redact_secret() {
  local v="$1"
  if [ -z "$v" ]; then
    printf '%s' "$v"
    return
  fi
  local len=${#v}
  if [ "$len" -le 6 ]; then
    printf '[REDACTED]'
  else
    printf '%s...[REDACTED]' "${v:0:3}"
  fi
}

# Mapeia severidade para cor
sev_color() {
  case "$1" in
    INFO) echo -ne "$C_CYAN" ;;
    LOW) echo -ne "$C_GREEN" ;;
    MEDIUM) echo -ne "$C_YELLOW" ;;
    HIGH) echo -ne "$C_RED" ;;
    CRITICAL) echo -ne "$C_RED_INTENSE" ;;
    *) echo -ne "$C_WHITE" ;;
  esac
}

# Peso numerico de severidade, usado no risk score agregado do host.
_pcsec_sev_weight() {
  case "$1" in
    CRITICAL) echo 10 ;;
    HIGH) echo 5 ;;
    MEDIUM) echo 2 ;;
    LOW) echo 1 ;;
    *) echo 0 ;;
  esac
}

# -----------------------------------------------------------------------------
# Motor de achados (findings)
#
# A partir da v5, TODO modulo roda em um subprocesso isolado (ver
# run_modules), para permitir timeout e paralelismo com seguranca. Por isso
# report_finding sempre grava o achado em um arquivo chave=valor dentro de
# PCSEC_PARALLEL_DIR (alem de imprimir a linha resumida no terminal
# imediatamente); o processo PAI (main) le esses arquivos depois que o
# modulo termina e reconstroi REPORT_LINES / JSON_FINDINGS / SEV_COUNT.
#
# report_finding assina a "ficha" padronizada exigida pelo projeto:
#   nome, caminho/config, descricao do risco, evidencia minima,
#   severidade, motivo da classificacao, recomendacao, limitacoes.
#
# A classificacao distingue (via campo CONFIDENCE):
#   confirmed   -> configuracao confirmadamente insegura
#   potential   -> possivel vetor que precisa de validacao manual
#   info        -> informacao que requer investigacao manual
# -----------------------------------------------------------------------------
report_finding() {
  local check_name="$1"
  local target="$2"
  local description="$3"
  local evidence="$4"
  local severity="$5"        # INFO|LOW|MEDIUM|HIGH|CRITICAL
  local reason="$6"
  local recommendation="$7"
  local limitations="$8"
  local confidence="${9:-potential}"   # confirmed|potential|info

  severity="$(echo "$severity" | tr '[:lower:]' '[:upper:]')"
  case "$severity" in
    INFO|LOW|MEDIUM|HIGH|CRITICAL) : ;;
    *) severity="INFO" ;;
  esac

  local color; color="$(sev_color "$severity")"

  # Saida imediata no terminal (linha resumida) - sempre acontece, mesmo
  # dentro de um subprocesso de modulo, pois herda o stdout do processo pai.
  printf "   ${color}[%s]${C_RESET} %s ${C_GRAY}-> %s${C_RESET}\n" "$severity" "$check_name" "$target"

  # Grava o achado em arquivo para o processo pai mesclar apos o modulo
  # terminar. %q garante uma representacao segura para reconstrucao via
  # 'eval' no merge (sem risco de injecao: %q escapa o literal exato).
  if [ -n "${PCSEC_PARALLEL_DIR:-}" ]; then
    PCSEC_FINDING_SEQ=$(( PCSEC_FINDING_SEQ + 1 ))
    local outfile
    outfile="${PCSEC_PARALLEL_DIR}/$(printf '%04d' "$PCSEC_FINDING_SEQ")_${PCSEC_CURRENT_MODULE:-unknown}_$$.kv"
    {
      printf 'CHECK=%q\n' "$check_name"
      printf 'TARGET=%q\n' "$target"
      printf 'DESC=%q\n' "$description"
      printf 'EVID=%q\n' "$evidence"
      printf 'SEV=%q\n' "$severity"
      printf 'REASON=%q\n' "$reason"
      printf 'RECO=%q\n' "$recommendation"
      printf 'LIMIT=%q\n' "$limitations"
      printf 'CONF=%q\n' "$confidence"
    } > "$outfile" 2>/dev/null
  fi
}
export -f report_finding has_cmd json_escape redact_secret sev_color

# -----------------------------------------------------------------------------
# Merge: le um arquivo .kv escrito por report_finding (em subprocesso) e
# reconstroi REPORT_LINES / JSON_FINDINGS / SEV_COUNT / TOTAL_FINDINGS no
# processo PAI. Nunca reimprime no terminal (ja impresso pelo worker).
# -----------------------------------------------------------------------------
_pcsec_merge_kv_file() {
  local f="$1"
  [ -f "$f" ] || return 0

  local CHECK="" TARGET="" DESC="" EVID="" SEV="" REASON="" RECO="" LIMIT="" CONF=""
  local k v
  while IFS='=' read -r k v; do
    [ -z "$k" ] && continue
    case "$k" in
      CHECK) eval "CHECK=$v" ;;
      TARGET) eval "TARGET=$v" ;;
      DESC) eval "DESC=$v" ;;
      EVID) eval "EVID=$v" ;;
      SEV) eval "SEV=$v" ;;
      REASON) eval "REASON=$v" ;;
      RECO) eval "RECO=$v" ;;
      LIMIT) eval "LIMIT=$v" ;;
      CONF) eval "CONF=$v" ;;
    esac
  done < "$f"

  [ -z "$SEV" ] && return 0
  case "$SEV" in
    INFO|LOW|MEDIUM|HIGH|CRITICAL) : ;;
    *) SEV="INFO" ;;
  esac

  SEV_COUNT[$SEV]=$(( ${SEV_COUNT[$SEV]:-0} + 1 ))
  TOTAL_FINDINGS=$(( TOTAL_FINDINGS + 1 ))
  RISK_SCORE=$(( RISK_SCORE + $(_pcsec_sev_weight "$SEV") ))

  local confidence_label
  case "$CONF" in
    confirmed) confidence_label="Configuracao confirmadamente insegura" ;;
    potential) confidence_label="Possivel vetor - requer validacao manual" ;;
    *) confidence_label="Informativo - requer investigacao manual" ;;
  esac

  REPORT_LINES+=("------------------------------------------------------------")
  REPORT_LINES+=("Verificacao     : $CHECK")
  REPORT_LINES+=("Alvo            : $TARGET")
  REPORT_LINES+=("Severidade      : $SEV ($confidence_label)")
  REPORT_LINES+=("Descricao       : $DESC")
  REPORT_LINES+=("Evidencia       : $EVID")
  REPORT_LINES+=("Motivo          : $REASON")
  REPORT_LINES+=("Recomendacao    : $RECO")
  REPORT_LINES+=("Limitacoes      : $LIMIT")

  local fp_id
  fp_id="$(printf '%s|%s' "$CHECK" "$TARGET" | { has_cmd md5sum && md5sum || cksum; } 2>/dev/null | awk '{print $1}')"

  local j
  j=$(cat <<JSONEOF
  {
    "id": "$(json_escape "$fp_id")",
    "check": "$(json_escape "$CHECK")",
    "target": "$(json_escape "$TARGET")",
    "severity": "$(json_escape "$SEV")",
    "confidence": "$(json_escape "$CONF")",
    "confidence_label": "$(json_escape "$confidence_label")",
    "description": "$(json_escape "$DESC")",
    "evidence": "$(json_escape "$EVID")",
    "reason": "$(json_escape "$REASON")",
    "recommendation": "$(json_escape "$RECO")",
    "limitations": "$(json_escape "$LIMIT")"
  }
JSONEOF
)
  JSON_FINDINGS+=("$j")
}

# -----------------------------------------------------------------------------
# Carregamento de modulos (apenas para validar presenca; o 'source' real
# de cada modulo acontece dentro do subprocesso que o executa).
# -----------------------------------------------------------------------------
check_modules_present() {
  local entry fn desc file path
  local missing=0
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    path="$MODULES_DIR/$file"
    if [ ! -f "$path" ]; then
      printf "${C_YELLOW}[!] Modulo ausente, sera ignorado: modules/%s${C_RESET}\n" "$file"
      missing=1
    fi
  done
  return $missing
}

# -----------------------------------------------------------------------------
# Execucao de UM modulo como subprocesso isolado, com timeout.
# Ao final, o subprocesso grava suas variaveis de contexto (PCSEC_CTX_*)
# em um arquivo .env proprio, para o processo pai exportar antes de rodar
# o motor de correlacao (module_correlate).
# -----------------------------------------------------------------------------
_pcsec_run_module_subprocess() {
  local fn="$1" file="$2"
  local module_path="$MODULES_DIR/$file"
  [ -f "$module_path" ] || return 0

  PCSEC_CURRENT_MODULE="$fn" \
  PCSEC_PARALLEL_DIR="$PCSEC_PARALLEL_DIR" \
  timeout "$MODULE_TIMEOUT" bash -c '
    set -u
    # Arrays associativos e contadores NAO sao herdados do processo pai via
    # export (limitacao do bash); precisam ser (re)declarados aqui dentro
    # do worker antes de sourcear o modulo, ou "set -u" quebra has_cmd()
    # e report_finding() neste subprocesso isolado.
    declare -A _PCSEC_CMD_CACHE=()
    PCSEC_FINDING_SEQ=0
    # shellcheck disable=SC1090
    source "$1"
    if declare -f "$2" >/dev/null 2>&1; then
      "$2"
    fi
    # Exporta variaveis de contexto (PCSEC_CTX_*) para o processo pai ler.
    {
      for v in $(compgen -v PCSEC_CTX_ 2>/dev/null); do
        printf "%s=%q\n" "$v" "${!v}"
      done
    } > "${PCSEC_PARALLEL_DIR}/ctx-${2}.env" 2>/dev/null
  ' _ "$module_path" "$fn"
  local rc=$?
  if [ $rc -eq 124 ]; then
    printf "   ${C_YELLOW}[INFO]${C_RESET} %s ${C_GRAY}-> timeout apos ${MODULE_TIMEOUT}s; modulo interrompido, auditoria prossegue${C_RESET}\n" "$fn"
  fi
  return 0
}

# -----------------------------------------------------------------------------
# Execucao dos modulos selecionados (sequencial ou paralela via --jobs)
# -----------------------------------------------------------------------------
run_modules() {
  local entry fn desc file
  local -a to_run=()

  if [ "$SCAN_MODE" = "quick" ]; then
    to_run=("${QUICK_MODULES[@]}")
  else
    for entry in "${MODULE_LIST[@]}"; do
      IFS='|' read -r fn desc file <<< "$entry"
      [ "$fn" = "module_correlate" ] && continue
      to_run+=("$fn")
    done
  fi

  PCSEC_PARALLEL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pcsec-run-XXXXXX" 2>/dev/null || mktemp -d)"
  export PCSEC_PARALLEL_DIR MODULE_TIMEOUT

  printf "${C_GRAY}Execucao: modulos isolados por subprocesso | timeout=%ss | paralelismo=%s job(s)${C_RESET}\n\n" "$MODULE_TIMEOUT" "$PARALLEL_JOBS"

  local -a running_pids=()
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    [ "$fn" = "module_correlate" ] && continue

    local run_it=0 item
    for item in "${to_run[@]}"; do
      [ "$item" = "$fn" ] && run_it=1 && break
    done
    [ "$run_it" -eq 0 ] && continue

    printf "\n${C_WHITE}[+] %s${C_RESET}\n" "$desc"

    if [ ! -f "$MODULES_DIR/$file" ]; then
      printf "${C_YELLOW}    [!] Arquivo modules/%s nao encontrado; modulo pulado.${C_RESET}\n" "$file"
      continue
    fi

    if [ "$PARALLEL_JOBS" -le 1 ]; then
      _pcsec_run_module_subprocess "$fn" "$file"
    else
      _pcsec_run_module_subprocess "$fn" "$file" &
      running_pids+=("$!")
      while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL_JOBS" ]; do
        wait -n 2>/dev/null || sleep 0.2
      done
    fi
  done

  # Aguarda quaisquer jobs paralelos restantes
  if [ "${#running_pids[@]}" -gt 0 ]; then
    wait 2>/dev/null
  fi

  # --- Merge: reconstroi REPORT_LINES / JSON_FINDINGS / SEV_COUNT em ordem
  #     de MODULE_LIST, e exporta o contexto (PCSEC_CTX_*) de cada modulo
  #     para o ambiente do processo pai, para o motor de correlacao usar.
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    [ "$fn" = "module_correlate" ] && continue
    local run_it=0 item
    for item in "${to_run[@]}"; do
      [ "$item" = "$fn" ] && run_it=1 && break
    done
    [ "$run_it" -eq 0 ] && continue

    local kv
    for kv in "$PCSEC_PARALLEL_DIR"/*_"${fn}"_*.kv; do
      [ -e "$kv" ] || continue
      _pcsec_merge_kv_file "$kv"
    done

    local ctxfile="$PCSEC_PARALLEL_DIR/ctx-${fn}.env"
    if [ -f "$ctxfile" ]; then
      set -a
      # shellcheck disable=SC1090
      source "$ctxfile"
      set +a
    fi
  done

  # --- Motor de correlacao: roda por ultimo, sempre sequencial, agora que
  #     o contexto de todos os demais modulos esta exportado no ambiente.
  printf "\n${C_WHITE}[+] Correlation Engine - Attack Path${C_RESET}\n"
  if [ -f "$MODULES_DIR/correlate.sh" ]; then
    _pcsec_run_module_subprocess "module_correlate" "correlate.sh"
    local kv
    for kv in "$PCSEC_PARALLEL_DIR"/*_module_correlate_*.kv; do
      [ -e "$kv" ] || continue
      _pcsec_merge_kv_file "$kv"
    done
  else
    printf "${C_YELLOW}    [!] modules/correlate.sh nao encontrado; correlacao pulada.${C_RESET}\n"
  fi
}

# -----------------------------------------------------------------------------
# Resumo final e persistencia de relatorios
# -----------------------------------------------------------------------------
print_summary() {
  printf "\n${C_WHITE}============================================================${C_RESET}\n"
  printf "${C_WHITE}  Audit completed.${C_RESET}\n"
  printf "${C_WHITE}============================================================${C_RESET}\n\n"
  printf "  Findings totais : %s\n" "$TOTAL_FINDINGS"
  printf "  ${C_RED_INTENSE}Critical${C_RESET}       : %s\n" "${SEV_COUNT[CRITICAL]}"
  printf "  ${C_RED}High${C_RESET}           : %s\n" "${SEV_COUNT[HIGH]}"
  printf "  ${C_YELLOW}Medium${C_RESET}         : %s\n" "${SEV_COUNT[MEDIUM]}"
  printf "  ${C_GREEN}Low${C_RESET}            : %s\n" "${SEV_COUNT[LOW]}"
  printf "  ${C_CYAN}Informational${C_RESET}  : %s\n" "${SEV_COUNT[INFO]}"
  printf "\n"
  printf "  ${C_BOLD}Risk score agregado do host: %s${C_RESET}\n" "$RISK_SCORE"
  printf "  ${C_GRAY}(CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0 por achado)${C_RESET}\n\n"
}

_pcsec_build_sarif() {
  local sarif_path="$1"
  {
    echo '{'
    echo '  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",'
    echo '  "version": "2.1.0",'
    echo '  "runs": ['
    echo '    {'
    echo '      "tool": {'
    echo '        "driver": {'
    echo "          \"name\": \"$PCSEC_SHORTNAME\","
    echo "          \"informationUri\": \"https://github.com/Deepaudit/linux-privesc\","
    echo "          \"version\": \"$PCSEC_VERSION\""
    echo '        }'
    echo '      },'
    echo '      "results": ['
    local count=${#JSON_FINDINGS[@]}
    local i level check target desc
    for i in "${!JSON_FINDINGS[@]}"; do
      local block="${JSON_FINDINGS[$i]}"
      check="$(echo "$block" | grep '"check":' | head -1 | sed -E 's/.*"check": "(.*)",?$/\1/')"
      target="$(echo "$block" | grep '"target":' | head -1 | sed -E 's/.*"target": "(.*)",?$/\1/')"
      desc="$(echo "$block" | grep '"description":' | head -1 | sed -E 's/.*"description": "(.*)",?$/\1/')"
      local sev
      sev="$(echo "$block" | grep '"severity":' | head -1 | sed -E 's/.*"severity": "(.*)",?$/\1/')"
      case "$sev" in
        CRITICAL|HIGH) level="error" ;;
        MEDIUM) level="warning" ;;
        *) level="note" ;;
      esac
      echo '        {'
      echo "          \"ruleId\": \"$(json_escape "$check")\","
      echo "          \"level\": \"$level\","
      echo '          "message": {'
      echo "            \"text\": \"$(json_escape "$desc")\""
      echo '          },'
      echo '          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "'"$(json_escape "$target")"'" } } } ]'
      if [ "$i" -lt $((count - 1)) ]; then
        echo '        },'
      else
        echo '        }'
      fi
    done
    echo '      ]'
    echo '    }'
    echo '  ]'
    echo '}'
  } > "$sarif_path" 2>/dev/null
}

_pcsec_build_html() {
  local html_path="$1"
  local hostname_now user_now
  hostname_now="$(hostname 2>/dev/null || echo desconhecido)"
  user_now="$(id -un 2>/dev/null)"

  # Monta o array JS de achados a partir de JSON_FINDINGS (ja em JSON valido)
  local findings_js="["
  local i count=${#JSON_FINDINGS[@]}
  for i in "${!JSON_FINDINGS[@]}"; do
    findings_js="${findings_js}${JSON_FINDINGS[$i]}"
    [ "$i" -lt $((count - 1)) ] && findings_js="${findings_js},"
  done
  findings_js="${findings_js}]"

  cat > "$html_path" <<HTMLEOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>${PCSEC_SHORTNAME} - Relatorio de Auditoria</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --panel2:#1d212b; --text:#e8e9ec; --muted:#9aa1ad;
    --border:#2a2f3a; --accent:#5aa9ff;
    --crit:#ff4d4f; --high:#ff8c42; --med:#f5c518; --low:#52c41a; --info:#5aa9ff;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f5f6f8; --panel:#ffffff; --panel2:#f0f1f4; --text:#1a1d23; --muted:#5b6270; --border:#dfe2e8; }
  }
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:24px;}
  h1{font-size:1.4rem;margin:0 0 4px}
  .sub{color:var(--muted);font-size:.9rem;margin-bottom:20px}
  .summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 18px;min-width:110px}
  .card .n{font-size:1.6rem;font-weight:700}
  .card .l{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
  .CRITICAL .n{color:var(--crit)} .HIGH .n{color:var(--high)} .MEDIUM .n{color:var(--med)}
  .LOW .n{color:var(--low)} .INFO .n{color:var(--info)}
  .filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
  .filters button{background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:.8rem;cursor:pointer}
  .filters button.active{border-color:var(--accent);color:var(--accent)}
  .finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--info);border-radius:8px;padding:14px 18px;margin-bottom:10px}
  .finding.CRITICAL{border-left-color:var(--crit)} .finding.HIGH{border-left-color:var(--high)}
  .finding.MEDIUM{border-left-color:var(--med)} .finding.LOW{border-left-color:var(--low)}
  .finding.INFO{border-left-color:var(--info)}
  .fhead{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}
  .fhead .check{font-weight:700}
  .badge{font-size:.7rem;padding:2px 8px;border-radius:10px;font-weight:700}
  .badge.CRITICAL{background:var(--crit);color:#1a0000} .badge.HIGH{background:var(--high);color:#2a1300}
  .badge.MEDIUM{background:var(--med);color:#2a2300} .badge.LOW{background:var(--low);color:#062b00}
  .badge.INFO{background:var(--info);color:#001533}
  .target{color:var(--muted);font-size:.85rem;margin:2px 0 8px;word-break:break-all}
  .field{font-size:.85rem;margin:4px 0}
  .field b{color:var(--muted);font-weight:600}
  .hidden{display:none}
</style>
</head>
<body>
<h1>${PCSEC_SHORTNAME} &mdash; Relatorio de Auditoria</h1>
<div class="sub">Host: ${hostname_now} | Usuario: ${user_now} | Gerado em: $(date 2>/dev/null) | Versao: ${PCSEC_VERSION} | Risk score: ${RISK_SCORE}</div>

<div class="summary" id="summary"></div>
<div class="filters" id="filters"></div>
<div id="findings"></div>

<script>
const DATA = ${findings_js};
const sevOrder = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
DATA.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

const summaryEl = document.getElementById('summary');
sevOrder.forEach(s => {
  const div = document.createElement('div');
  div.className = 'card ' + s;
  div.innerHTML = '<div class="n">' + counts[s] + '</div><div class="l">' + s + '</div>';
  summaryEl.appendChild(div);
});

let activeFilter = 'ALL';
const filtersEl = document.getElementById('filters');
['ALL', ...sevOrder].forEach(s => {
  const b = document.createElement('button');
  b.textContent = s + (s !== 'ALL' ? ' (' + counts[s] + ')' : ' (' + DATA.length + ')');
  if (s === 'ALL') b.classList.add('active');
  b.onclick = () => { activeFilter = s; render(); Array.from(filtersEl.children).forEach(c=>c.classList.remove('active')); b.classList.add('active'); };
  filtersEl.appendChild(b);
});

function esc(s){ return (s||'').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function render(){
  const root = document.getElementById('findings');
  root.innerHTML = '';
  DATA.filter(f => activeFilter === 'ALL' || f.severity === activeFilter)
      .forEach(f => {
    const div = document.createElement('div');
    div.className = 'finding ' + f.severity;
    div.innerHTML =
      '<div class="fhead"><span class="check">' + esc(f.check) + '</span>' +
      '<span class="badge ' + f.severity + '">' + f.severity + '</span></div>' +
      '<div class="target">' + esc(f.target) + ' &middot; ' + esc(f.confidence_label) + '</div>' +
      '<div class="field"><b>Descricao:</b> ' + esc(f.description) + '</div>' +
      '<div class="field"><b>Evidencia:</b> ' + esc(f.evidence) + '</div>' +
      '<div class="field"><b>Motivo:</b> ' + esc(f.reason) + '</div>' +
      '<div class="field"><b>Recomendacao:</b> ' + esc(f.recommendation) + '</div>' +
      '<div class="field"><b>Limitacoes:</b> ' + esc(f.limitations) + '</div>';
    root.appendChild(div);
  });
}
render();
</script>
</body>
</html>
HTMLEOF
}

# Extrai fingerprints "SEV|CHECK|TARGET" de um arquivo JSON no formato
# gerado por esta ferramenta (campos em linhas separadas, ordem fixa).
_pcsec_fingerprints_from_json_file() {
  local file="$1"
  awk '
    /"check":/    { gsub(/^[ \t]*"check": "/,""); gsub(/",?$/,""); chk=$0 }
    /"target":/   { gsub(/^[ \t]*"target": "/,""); gsub(/",?$/,""); tgt=$0 }
    /"severity":/ { gsub(/^[ \t]*"severity": "/,""); gsub(/",?$/,""); sev=$0; print sev "|" chk "|" tgt }
  ' "$file" 2>/dev/null
}

_pcsec_fingerprints_from_memory() {
  local i
  for i in "${!JSON_FINDINGS[@]}"; do
    echo "${JSON_FINDINGS[$i]}"
  done | _pcsec_fingerprints_from_json_file /dev/stdin
}

run_compare() {
  [ -z "$COMPARE_FILE" ] && return 0
  if [ ! -f "$COMPARE_FILE" ]; then
    printf "${C_YELLOW}[!] Arquivo de comparacao nao encontrado: %s${C_RESET}\n" "$COMPARE_FILE"
    return 0
  fi

  local old_fp new_fp
  old_fp="$(mktemp)"
  new_fp="$(mktemp)"
  _pcsec_fingerprints_from_json_file "$COMPARE_FILE" | sort -u > "$old_fp"
  _pcsec_fingerprints_from_memory | sort -u > "$new_fp"

  local novos resolvidos
  novos="$(comm -13 "$old_fp" "$new_fp")"
  resolvidos="$(comm -23 "$old_fp" "$new_fp")"

  printf "\n${C_WHITE}============================================================${C_RESET}\n"
  printf "${C_WHITE}  Comparacao com execucao anterior: %s${C_RESET}\n" "$COMPARE_FILE"
  printf "${C_WHITE}============================================================${C_RESET}\n\n"

  if [ -n "$novos" ]; then
    printf "${C_RED}[+] Achados NOVOS (nao presentes na execucao anterior):${C_RESET}\n"
    echo "$novos" | awk -F'|' '{printf "    [%s] %s -> %s\n",$1,$2,$3}'
  else
    printf "${C_GREEN}[+] Nenhum achado novo em relacao a execucao anterior.${C_RESET}\n"
  fi
  echo ""
  if [ -n "$resolvidos" ]; then
    printf "${C_GREEN}[+] Achados RESOLVIDOS (presentes antes, ausentes agora):${C_RESET}\n"
    echo "$resolvidos" | awk -F'|' '{printf "    [%s] %s -> %s\n",$1,$2,$3}'
  else
    printf "${C_GRAY}[+] Nenhum achado resolvido desde a execucao anterior.${C_RESET}\n"
  fi
  echo ""

  rm -f "$old_fp" "$new_fp" 2>/dev/null
}

write_reports() {
  mkdir -p "$OUTPUT_DIR" 2>/dev/null
  if [ ! -d "$OUTPUT_DIR" ] || [ ! -w "$OUTPUT_DIR" ]; then
    printf "${C_YELLOW}[!] Nao foi possivel criar/gravar em '%s'. Relatorios nao serao salvos em disco.${C_RESET}\n" "$OUTPUT_DIR"
    return 1
  fi

  local txt_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.txt"
  {
    echo "$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION"
    echo "Developed by $PCSEC_AUTHOR"
    echo "Data da execucao: $(date 2>/dev/null)"
    echo "Hostname........: $(hostname 2>/dev/null || echo desconhecido)"
    echo "Usuario.........: $(id -un 2>/dev/null) (uid=$(id -u 2>/dev/null))"
    echo "Modo de execucao: $SCAN_MODE"
    echo ""
    echo "RESUMO"
    echo "------"
    echo "Findings totais: $TOTAL_FINDINGS"
    echo "Critical: ${SEV_COUNT[CRITICAL]}  High: ${SEV_COUNT[HIGH]}  Medium: ${SEV_COUNT[MEDIUM]}  Low: ${SEV_COUNT[LOW]}  Info: ${SEV_COUNT[INFO]}"
    echo "Risk score agregado: $RISK_SCORE"
    echo ""
    echo "DETALHAMENTO DOS ACHADOS"
    echo "========================="
    local l
    for l in "${REPORT_LINES[@]}"; do
      echo "$l"
    done
    echo "------------------------------------------------------------"
    echo ""
    echo "AVISO: relatorio gerado apenas a partir de verificacoes de leitura"
    echo "locais. Nenhum dado foi enviado para servidores externos."
  } > "$txt_path" 2>/dev/null

  [ -f "$txt_path" ] && printf "${C_GREEN}[+] Relatorio texto salvo em:${C_RESET} %s\n" "$txt_path"

  local json_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.json"
  {
    echo "{"
    echo "  \"tool\": \"$PCSEC_SHORTNAME\","
    echo "  \"name\": \"$(json_escape "$PCSEC_NAME")\","
    echo "  \"version\": \"$PCSEC_VERSION\","
    echo "  \"author\": \"$(json_escape "$PCSEC_AUTHOR")\","
    echo "  \"generated_at\": \"$(date -Iseconds 2>/dev/null || date 2>/dev/null)\","
    echo "  \"hostname\": \"$(json_escape "$(hostname 2>/dev/null || echo unknown)")\","
    echo "  \"scan_mode\": \"$SCAN_MODE\","
    echo "  \"summary\": {"
    echo "    \"total\": $TOTAL_FINDINGS,"
    echo "    \"critical\": ${SEV_COUNT[CRITICAL]},"
    echo "    \"high\": ${SEV_COUNT[HIGH]},"
    echo "    \"medium\": ${SEV_COUNT[MEDIUM]},"
    echo "    \"low\": ${SEV_COUNT[LOW]},"
    echo "    \"info\": ${SEV_COUNT[INFO]},"
    echo "    \"risk_score\": $RISK_SCORE"
    echo "  },"
    echo "  \"findings\": ["
    local count=${#JSON_FINDINGS[@]}
    local i
    for i in "${!JSON_FINDINGS[@]}"; do
      if [ "$i" -lt $((count - 1)) ]; then
        echo "${JSON_FINDINGS[$i]},"
      else
        echo "${JSON_FINDINGS[$i]}"
      fi
    done
    echo "  ]"
    echo "}"
  } > "$json_path" 2>/dev/null
  if [ -f "$json_path" ]; then
    # O JSON e sempre escrito em disco (necessario para --compare em
    # execucoes futuras e como base do SARIF/HTML), mas so e anunciado
    # como saida solicitada quando --json foi usado explicitamente.
    [ "$JSON_OUTPUT" -eq 1 ] && printf "${C_GREEN}[+] Relatorio JSON salvo em:${C_RESET} %s\n" "$json_path"
  fi

  if [ "$SARIF_OUTPUT" -eq 1 ]; then
    local sarif_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.sarif"
    _pcsec_build_sarif "$sarif_path"
    [ -f "$sarif_path" ] && printf "${C_GREEN}[+] Relatorio SARIF salvo em:${C_RESET} %s\n" "$sarif_path"
  fi

  if [ "$HTML_OUTPUT" -eq 1 ]; then
    local html_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.html"
    _pcsec_build_html "$html_path"
    [ -f "$html_path" ] && printf "${C_GREEN}[+] Relatorio HTML salvo em:${C_RESET} %s\n" "$html_path"
  fi
}

# -----------------------------------------------------------------------------
# Tratamento de sinais / interrupcoes
# -----------------------------------------------------------------------------
on_interrupt() {
  printf "\n\n${C_YELLOW}[!] Execucao interrompida pelo usuario (SIGINT).${C_RESET}\n"
  printf "${C_YELLOW}[!] Nenhuma alteracao foi feita no sistema. Encerrando com seguranca.${C_RESET}\n"
  [ -n "$PCSEC_PARALLEL_DIR" ] && rm -rf "$PCSEC_PARALLEL_DIR" 2>/dev/null
  exit 130
}
on_term() {
  printf "\n\n${C_YELLOW}[!] Sinal de termino recebido. Encerrando com seguranca.${C_RESET}\n"
  [ -n "$PCSEC_PARALLEL_DIR" ] && rm -rf "$PCSEC_PARALLEL_DIR" 2>/dev/null
  exit 143
}
trap on_interrupt INT
trap on_term TERM

# -----------------------------------------------------------------------------
# Validacao de argumentos
# -----------------------------------------------------------------------------
validate_output_dir() {
  local dir="$1"
  if [ -z "$dir" ]; then
    echo "Erro: --output requer um caminho de diretorio." >&2
    exit 2
  fi
  OUTPUT_DIR="$dir"
}

_pcsec_require_positive_int() {
  local val="$1" flag="$2"
  case "$val" in
    ''|*[!0-9]*)
      echo "Erro: $flag requer um numero inteiro positivo." >&2
      exit 2
      ;;
  esac
}

# -----------------------------------------------------------------------------
# Parsing de argumentos
# -----------------------------------------------------------------------------
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h)
        setup_colors
        print_help
        exit 0
        ;;
      --version|-v)
        print_version
        exit 0
        ;;
      --quick) SCAN_MODE="quick" ;;
      --full) SCAN_MODE="full" ;;
      --no-color) USE_COLOR=0 ;;
      --json) JSON_OUTPUT=1 ;;
      --sarif) SARIF_OUTPUT=1 ;;
      --html) HTML_OUTPUT=1 ;;
      --checks) LIST_CHECKS_ONLY=1 ;;
      --output)
        shift
        [ $# -eq 0 ] && { echo "Erro: --output requer um argumento (diretorio)." >&2; exit 2; }
        validate_output_dir "$1"
        ;;
      --output=*) validate_output_dir "${1#--output=}" ;;
      --jobs)
        shift
        [ $# -eq 0 ] && { echo "Erro: --jobs requer um numero." >&2; exit 2; }
        _pcsec_require_positive_int "$1" "--jobs"
        PARALLEL_JOBS="$1"
        ;;
      --jobs=*)
        _pcsec_require_positive_int "${1#--jobs=}" "--jobs"
        PARALLEL_JOBS="${1#--jobs=}"
        ;;
      --timeout)
        shift
        [ $# -eq 0 ] && { echo "Erro: --timeout requer um numero de segundos." >&2; exit 2; }
        _pcsec_require_positive_int "$1" "--timeout"
        MODULE_TIMEOUT="$1"
        ;;
      --timeout=*)
        _pcsec_require_positive_int "${1#--timeout=}" "--timeout"
        MODULE_TIMEOUT="${1#--timeout=}"
        ;;
      --compare)
        shift
        [ $# -eq 0 ] && { echo "Erro: --compare requer o caminho de um relatorio JSON anterior." >&2; exit 2; }
        COMPARE_FILE="$1"
        ;;
      --compare=*) COMPARE_FILE="${1#--compare=}" ;;
      --fail-on-risk)
        shift
        [ $# -eq 0 ] && { echo "Erro: --fail-on-risk requer um numero." >&2; exit 2; }
        _pcsec_require_positive_int "$1" "--fail-on-risk"
        FAIL_ON_RISK="$1"
        ;;
      --fail-on-risk=*)
        _pcsec_require_positive_int "${1#--fail-on-risk=}" "--fail-on-risk"
        FAIL_ON_RISK="${1#--fail-on-risk=}"
        ;;
      *)
        echo "Argumento desconhecido: $1" >&2
        echo "Use --help para ver as opcoes disponiveis." >&2
        exit 2
        ;;
    esac
    shift
  done

  if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$(pwd)/pcsec-reports"
  fi
}

# -----------------------------------------------------------------------------
# Aviso de execucao como root
# -----------------------------------------------------------------------------
warn_if_root() {
  if [ "$(id -u 2>/dev/null)" = "0" ]; then
    printf "${C_YELLOW}[!] Executando como root: a analise tera maior visibilidade e podera${C_RESET}\n"
    printf "${C_YELLOW}    revelar informacoes adicionais (ex.: arquivos normalmente protegidos).${C_RESET}\n"
    printf "${C_YELLOW}    Esta condicao NAO e usada para alterar o sistema de forma alguma.${C_RESET}\n\n"
  fi
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  setup_colors

  if [ "$LIST_CHECKS_ONLY" -eq 1 ]; then
    print_checks_list
    exit 0
  fi

  print_banner
  warn_if_root

  printf "${C_GRAY}Modo de execucao: %s${C_RESET}\n" "$SCAN_MODE"
  printf "${C_GRAY}Diretorio de saida dos relatorios: %s${C_RESET}\n" "$OUTPUT_DIR"

  check_modules_present
  run_modules
  print_summary

  write_reports
  [ -n "$COMPARE_FILE" ] && run_compare

  [ -n "$PCSEC_PARALLEL_DIR" ] && rm -rf "$PCSEC_PARALLEL_DIR" 2>/dev/null

  printf "${C_GRAY}Lembre-se: esta ferramenta so realiza leitura local. Valide manualmente${C_RESET}\n"
  printf "${C_GRAY}todos os achados antes de qualquer acao corretiva ou de teste adicional.${C_RESET}\n\n"

  if [ -n "$FAIL_ON_RISK" ] && [ "$RISK_SCORE" -ge "$FAIL_ON_RISK" ]; then
    printf "${C_RED_BOLD}[!] Risk score (%s) >= limite definido em --fail-on-risk (%s). Encerrando com exit code 1.${C_RESET}\n\n" "$RISK_SCORE" "$FAIL_ON_RISK"
    exit 1
  fi
}

main "$@"
