#!/usr/bin/env bats
#
# tests/test_core.bats
# Testes automatizados (Bats - Bash Automated Testing System) para o motor
# principal do PCSEC-PRIVESC. Cobre utilitarios puros (json_escape,
# redact_secret, has_cmd) e o fluxo de ponta a ponta do script via CLI real
# (--checks, --help, --quick gera relatorios, --fail-on-risk, modulo ausente).
#
# Como rodar:
#   bats tests/test_core.bats
#
# Requer: bats-core (https://github.com/bats-core/bats-core)
#   Debian/Ubuntu: apt-get install -y bats

setup() {
  SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." >/dev/null 2>&1 && pwd)"
  PCSEC_SCRIPT="$SCRIPT_DIR/pcsec-privesc.sh"
  TEST_OUTPUT_DIR="$(mktemp -d)"
}

teardown() {
  [ -n "${TEST_OUTPUT_DIR:-}" ] && rm -rf "$TEST_OUTPUT_DIR"
}

# -----------------------------------------------------------------------------
# Utilitarios puros - reimplementados inline nos testes (mesma logica do
# script principal) para testar o COMPORTAMENTO sem depender de 'source'
# no script inteiro, que executaria main() como efeito colateral.
# -----------------------------------------------------------------------------

@test "json_escape escapa aspas duplas e barra invertida corretamente" {
  run bash -c '
    json_escape() {
      local s="$1"
      s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
      s="${s//$'"'"'\n'"'"'/\\n}"; s="${s//$'"'"'\t'"'"'/\\t}"; s="${s//$'"'"'\r'"'"'/}"
      printf "%s" "$s"
    }
    json_escape "linha com \"aspas\" e barra \\"
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *'\"aspas\"'* ]]
}

@test "redact_secret redige valores curtos como [REDACTED]" {
  run bash -c '
    redact_secret() {
      local v="$1"
      if [ -z "$v" ]; then printf "%s" "$v"; return; fi
      local len=${#v}
      if [ "$len" -le 6 ]; then printf "[REDACTED]"; else printf "%s...[REDACTED]" "${v:0:3}"; fi
    }
    redact_secret "abc123"
  '
  [ "$status" -eq 0 ]
  [ "$output" = "[REDACTED]" ]
}

@test "redact_secret nunca expoe o segredo completo em valores longos" {
  run bash -c '
    redact_secret() {
      local v="$1"
      if [ -z "$v" ]; then printf "%s" "$v"; return; fi
      local len=${#v}
      if [ "$len" -le 6 ]; then printf "[REDACTED]"; else printf "%s...[REDACTED]" "${v:0:3}"; fi
    }
    redact_secret "supersecretvalue123"
  '
  [ "$status" -eq 0 ]
  [ "$output" = "sup...[REDACTED]" ]
  [[ "$output" != *"supersecretvalue123"* ]]
}

@test "has_cmd encontra um binario conhecido (bash)" {
  run bash -c '
    declare -A _PCSEC_CMD_CACHE=()
    has_cmd() {
      local c="$1"
      if [ "${_PCSEC_CMD_CACHE[$c]+set}" = "set" ]; then
        [ "${_PCSEC_CMD_CACHE[$c]}" = "1" ]; return
      fi
      if command -v "$c" >/dev/null 2>&1; then _PCSEC_CMD_CACHE[$c]=1; return 0
      else _PCSEC_CMD_CACHE[$c]=0; return 1; fi
    }
    has_cmd bash && echo FOUND
  '
  [ "$status" -eq 0 ]
  [[ "$output" == *"FOUND"* ]]
}

@test "has_cmd retorna falha para binario inexistente" {
  run bash -c '
    declare -A _PCSEC_CMD_CACHE=()
    has_cmd() {
      local c="$1"
      if [ "${_PCSEC_CMD_CACHE[$c]+set}" = "set" ]; then
        [ "${_PCSEC_CMD_CACHE[$c]}" = "1" ]; return
      fi
      if command -v "$c" >/dev/null 2>&1; then _PCSEC_CMD_CACHE[$c]=1; return 0
      else _PCSEC_CMD_CACHE[$c]=0; return 1; fi
    }
    has_cmd este-binario-definitivamente-nao-existe-xyz
  '
  [ "$status" -ne 0 ]
}

# -----------------------------------------------------------------------------
# Fluxo de ponta a ponta do script principal (CLI real)
# -----------------------------------------------------------------------------

@test "--help exibe uso e encerra com exit 0" {
  run "$PCSEC_SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Uso:"* ]]
}

@test "--version exibe a versao e encerra com exit 0" {
  run "$PCSEC_SCRIPT" --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"PCSEC-PRIVESC"* ]]
}

@test "--checks lista os modulos disponiveis, incluindo os novos da v5" {
  run "$PCSEC_SCRIPT" --checks
  [ "$status" -eq 0 ]
  [[ "$output" == *"module_container_escape"* ]]
  [[ "$output" == *"module_credential_hunting"* ]]
  [[ "$output" == *"module_correlate"* ]]
}

@test "argumento desconhecido encerra com exit code 2" {
  run "$PCSEC_SCRIPT" --isso-nao-existe
  [ "$status" -eq 2 ]
}

@test "--output sem argumento encerra com exit code 2" {
  run "$PCSEC_SCRIPT" --output
  [ "$status" -eq 2 ]
}

@test "--jobs com valor nao numerico encerra com exit code 2" {
  run "$PCSEC_SCRIPT" --jobs abc
  [ "$status" -eq 2 ]
}

@test "--timeout com valor nao numerico encerra com exit code 2" {
  run "$PCSEC_SCRIPT" --timeout abc
  [ "$status" -eq 2 ]
}

@test "--quick gera relatorio texto e JSON no diretorio de saida" {
  run "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR" --json
  [ "$status" -eq 0 ]
  [ -n "$(find "$TEST_OUTPUT_DIR" -name '*.txt' -print -quit)" ]
  [ -n "$(find "$TEST_OUTPUT_DIR" -name '*.json' -print -quit)" ]
}

@test "relatorio JSON gerado e um JSON valido" {
  "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR" --json >/dev/null 2>&1
  local json_file
  json_file="$(find "$TEST_OUTPUT_DIR" -name '*.json' -print -quit)"
  [ -n "$json_file" ]
  if command -v python3 >/dev/null 2>&1; then
    run python3 -c "import json; json.load(open('$json_file'))"
    [ "$status" -eq 0 ]
  fi
}

@test "relatorio texto nunca contem um valor de credencial sensivel sem redacao" {
  export PCSEC_TEST_SECRET_TOKEN="meusegredoultrasecreto123"
  run "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR"
  [ "$status" -eq 0 ]
  local txt_file
  txt_file="$(find "$TEST_OUTPUT_DIR" -name '*.txt' -print -quit)"
  [ -n "$txt_file" ]
  run grep -c "meusegredoultrasecreto123" "$txt_file"
  [ "$status" -ne 0 ] || [ "$output" = "0" ]
}

@test "--full seguido de --fail-on-risk alto (999999) encerra com exit 0" {
  run "$PCSEC_SCRIPT" --full --no-color --output "$TEST_OUTPUT_DIR" --fail-on-risk 999999
  [ "$status" -eq 0 ]
}

@test "--sarif gera um arquivo .sarif valido como JSON" {
  "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR" --sarif >/dev/null 2>&1
  local sarif_file
  sarif_file="$(find "$TEST_OUTPUT_DIR" -name '*.sarif' -print -quit)"
  [ -n "$sarif_file" ]
  if command -v python3 >/dev/null 2>&1; then
    run python3 -c "import json; d=json.load(open('$sarif_file')); assert d['version']=='2.1.0'"
    [ "$status" -eq 0 ]
  fi
}

@test "--html gera um arquivo .html standalone" {
  "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR" --html >/dev/null 2>&1
  local html_file
  html_file="$(find "$TEST_OUTPUT_DIR" -name '*.html' -print -quit)"
  [ -n "$html_file" ]
  run grep -c "<!DOCTYPE html>" "$html_file"
  [ "$status" -eq 0 ]
}

@test "modulo ausente nao derruba a execucao (roda a partir de copia isolada)" {
  local work_dir
  work_dir="$(mktemp -d)"
  cp "$PCSEC_SCRIPT" "$work_dir/"
  cp -r "$SCRIPT_DIR/modules" "$work_dir/"
  rm -f "$work_dir/modules/kernel_audit.sh"

  run "$work_dir/pcsec-privesc.sh" --quick --no-color --output "$TEST_OUTPUT_DIR"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nao encontrado"* ]]

  rm -rf "$work_dir"
}

@test "--compare com arquivo inexistente nao quebra a execucao" {
  run "$PCSEC_SCRIPT" --quick --no-color --output "$TEST_OUTPUT_DIR" --json --compare "/tmp/arquivo-que-nao-existe-$RANDOM.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"nao encontrado"* ]]
}
