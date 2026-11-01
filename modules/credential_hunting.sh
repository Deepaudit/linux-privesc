#!/usr/bin/env bash
#
# modules/credential_hunting.sh
# Modulo: Deteccao de indicios de credenciais expostas em arquivos comuns
# (historico de shell, arquivos de configuracao, dotfiles).
#
# REGRA ABSOLUTA: este modulo NUNCA imprime o valor de uma credencial
# encontrada. Apenas reporta o ARQUIVO, a LINHA (numero) e um trecho
# redigido via redact_secret(). O objetivo e apontar ONDE investigar
# manualmente, nunca expor o segredo em si.

# Padroes (regex, case-insensitive) que costumam preceder um valor de credencial.
_PCSEC_CRED_PATTERNS=(
  'password[[:space:]]*='
  'passwd[[:space:]]*='
  'api[_-]?key[[:space:]]*='
  'secret[[:space:]]*='
  'token[[:space:]]*='
  'aws_secret_access_key[[:space:]]*='
  'private[_-]?key[[:space:]]*='
  'authorization:[[:space:]]*bearer'
  'BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY'
)

# Arquivos tipicos onde desenvolvedores acidentalmente deixam segredos.
_pcsec_cred_candidate_files() {
  local home="${HOME:-/root}"
  local -a candidates=(
    "$home/.bash_history"
    "$home/.zsh_history"
    "$home/.python_history"
    "$home/.mysql_history"
    "$home/.psql_history"
    "$home/.netrc"
    "$home/.git-credentials"
    "$home/.aws/credentials"
    "$home/.docker/config.json"
    "$home/.npmrc"
    "$home/.pypirc"
    "$home/.env"
  )
  local f
  for f in "${candidates[@]}"; do
    [ -f "$f" ] && [ -r "$f" ] && echo "$f"
  done
  # .env em subdiretorios imediatos do diretorio atual e do home (projetos comuns)
  find "$home" -maxdepth 3 -type f -iname "*.env" -readable 2>/dev/null
  find "$home" -maxdepth 3 -type f -iname "config.json" -path "*docker*" -readable 2>/dev/null
}

module_credential_hunting() {
  local total_hits=0
  local files_with_hits=0
  local f

  while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -r "$f" ] || continue

    local pattern file_hits=0
    for pattern in "${_PCSEC_CRED_PATTERNS[@]}"; do
      local matches
      matches="$(grep -inE "$pattern" "$f" 2>/dev/null | head -n 5)"
      [ -z "$matches" ] && continue

      local line
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        file_hits=$((file_hits + 1))
        total_hits=$((total_hits + 1))

        local lineno raw_content redacted_evidence
        lineno="$(echo "$line" | cut -d: -f1)"
        raw_content="$(echo "$line" | cut -d: -f2-)"
        redacted_evidence="$(redact_secret "$raw_content")"

        report_finding \
          "Credential Hunting" \
          "$f:$lineno" \
          "Padrao textual sugestivo de credencial encontrado em arquivo legivel. O valor completo NUNCA e exibido por esta ferramenta." \
          "Linha $lineno corresponde ao padrao '$pattern'; trecho redigido: $redacted_evidence" \
          "HIGH" \
          "Arquivos de historico, dotfiles e configuracoes frequentemente acumulam credenciais digitadas ou coladas acidentalmente (senhas em comandos, tokens de API, chaves). Se outro usuario ou processo conseguir ler este arquivo, a credencial pode ser comprometida." \
          "Revise manualmente a linha indicada, revogue/rotacione a credencial se for valida e remova-a do arquivo (considere ferramentas como 'git-secrets' ou 'trufflehog' para varreduras mais profundas, e cofres de segredos para armazenamento)." \
          "Deteccao puramente baseada em expressao regular sobre texto; gera falsos positivos (ex. comentarios, placeholders como 'password=changeme') e pode nao detectar segredos codificados ou ofuscados. O valor real nunca e lido para fora desta analise de padrao nem incluido no relatorio." \
          "potential"
      done <<< "$matches"
    done

    [ "$file_hits" -gt 0 ] && files_with_hits=$((files_with_hits + 1))
  done <<< "$(_pcsec_cred_candidate_files)"

  if [ "$total_hits" -eq 0 ]; then
    report_finding \
      "Credential Hunting" \
      "Arquivos comuns de historico/configuracao" \
      "Nenhum padrao textual sugestivo de credencial foi encontrado nos arquivos tipicos verificados." \
      "Arquivos candidatos verificados: historico de shell, .netrc, .git-credentials, .aws/credentials, .docker/config.json, .npmrc, .pypirc, .env (ate 3 niveis no HOME)" \
      "INFO" \
      "Resultado esperado em ambientes sem segredos acidentalmente commitados ou colados em historico." \
      "Nenhuma acao necessaria. Para cobertura mais ampla, considere ferramentas dedicadas de secret scanning no repositorio de codigo." \
      "Varredura limitada a um conjunto fixo de arquivos candidatos e padroes de regex nao exaustivos; nao substitui scanners dedicados (gitleaks, trufflehog)." \
      "info"
  else
    report_finding \
      "Credential Hunting" \
      "Resumo da varredura de credenciais" \
      "Totais consolidados de indicios textuais de credenciais encontrados em arquivos legiveis." \
      "Ocorrencias: $total_hits | Arquivos distintos com ocorrencias: $files_with_hits" \
      "INFO" \
      "Resumo quantitativo para priorizacao da revisao manual." \
      "Priorize a revisao dos achados classificados como HIGH listados acima." \
      "Numeros refletem apenas os arquivos candidatos e padroes verificados nesta execucao." \
      "info"
  fi
}
