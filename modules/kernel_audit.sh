#!/usr/bin/env bash
#
# modules/kernel_audit.sh
# Modulo: Informacoes de kernel e sistema operacional para correlacao manual
# com bases de vulnerabilidades conhecidas (CVE). Esta ferramenta NAO afirma
# que uma vulnerabilidade e explorável apenas com base na versao encontrada,
# e NAO executa exploits de kernel sob nenhuma circunstancia.

# Tabela OFFLINE e estatica de referencia (nao exaustiva, nao substitui NVD):
# versao MAXIMA de kernel conhecida publicamente como afetada por uma CVE
# amplamente documentada, usada apenas para levantar uma bandeira de
# "vale a pena checar manualmente" - nunca para confirmar exploracao.
# Formato: "cve|descricao curta|versao_maxima_afetada(ordenacao textual simples)"
_PCSEC_KNOWN_KERNEL_CVES=(
  "CVE-2022-0847|DirtyPipe - escrita arbitraria em arquivos read-only via pipe|5.17"
  "CVE-2021-4034|PwnKit - escalacao via polkit pkexec (nao especifico de kernel, mas correlacionado)|0"
  "CVE-2021-3493|OverlayFS - escalacao via capabilities incorretas em overlay|5.11"
  "CVE-2019-13272|PTRACE_TRACEME - escalacao via ptrace e credenciais salvas|5.1"
  "CVE-2016-5195|DirtyCOW - condicao de corrida em copy-on-write|4.8.3"
)

_pcsec_kernel_version_lt() {
  # Comparacao simplificada de versao "major.minor" usando sort -V.
  # Retorna 0 (verdadeiro) se $1 < $2. Apenas heuristica; nao cobre patches
  # distro-specific que fazem backport de correcoes em versoes "antigas".
  [ -z "$1" ] || [ -z "$2" ] && return 1
  [ "$2" = "0" ] && return 1
  local lowest
  lowest="$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)"
  [ "$lowest" = "$1" ] && [ "$1" != "$2" ]
}

module_kernel_audit() {
  local kernel_version os_pretty

  kernel_version="$(uname -r 2>/dev/null || echo desconhecida)"
  # Extrai apenas "major.minor.patch" para comparacao, descartando sufixos de distro
  local kernel_short
  kernel_short="$(echo "$kernel_version" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"

  os_pretty="desconhecida"
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    os_pretty="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-desconhecida}")"
  fi

  report_finding \
    "Kernel & Update Audit" \
    "uname -r" \
    "Versao do kernel em execucao, util para correlacao manual com bases publicas de CVE." \
    "Kernel: $kernel_version | SO: $os_pretty" \
    "INFO" \
    "A versao do kernel, isoladamente, nao comprova a presenca de uma vulnerabilidade explorável." \
    "Compare manualmente esta versao com os boletins de seguranca da distribuicao e com bases como NVD/CVE antes de qualquer conclusao." \
    "Esta ferramenta nao consulta bases de CVE automaticamente e nao tenta confirmar exploracao." \
    "info"

  # Correlacao offline, puramente informativa, contra a tabela estatica acima.
  if [ -n "$kernel_short" ]; then
    local entry cve desc max_ver
    for entry in "${_PCSEC_KNOWN_KERNEL_CVES[@]}"; do
      IFS='|' read -r cve desc max_ver <<< "$entry"
      if _pcsec_kernel_version_lt "$kernel_short" "$max_ver"; then
        report_finding \
          "Kernel & Update Audit" \
          "$cve" \
          "A versao do kernel em execucao e textualmente anterior a uma versao publicamente associada a uma CVE conhecida de escalacao de privilegios: $desc." \
          "Kernel atual: $kernel_short | Limite de referencia (nao exaustivo): $max_ver | CVE: $cve" \
          "MEDIUM" \
          "Comparacao de versao e apenas textual (sort -V) e NAO considera backports de seguranca aplicados pela distribuicao, que sao extremamente comuns em kernels de pacotes (Debian/Ubuntu/RHEL costumam corrigir CVEs sem mudar a versao base)." \
          "Consulte o boletim de seguranca oficial da sua distribuicao para $cve antes de qualquer conclusao. Nao execute PoCs/exploits sem autorizacao formal." \
          "Tabela estatica, nao exaustiva, mantida manualmente neste modulo; NAO substitui consulta a NVD/MITRE ou ao security tracker da distro. Pode gerar falsos positivos em kernels com backport de correcao." \
          "potential"
      fi
    done
  fi

  # Verifica se ha indicacao de reboot pendente (comum apos atualizacoes de kernel)
  if [ -f /var/run/reboot-required ]; then
    report_finding \
      "Kernel & Update Audit" \
      "/var/run/reboot-required" \
      "O sistema sinaliza que ha atualizacoes aplicadas que exigem reinicializacao." \
      "Arquivo /var/run/reboot-required presente" \
      "MEDIUM" \
      "Ate a reinicializacao, o kernel em execucao pode nao conter correcoes de seguranca ja instaladas em disco." \
      "Agende uma janela de manutencao para reiniciar o sistema e aplicar o kernel atualizado." \
      "A presenca deste arquivo e especifica de distribuicoes baseadas em Debian/Ubuntu." \
      "confirmed"
  fi

  # Verifica gerenciador de pacotes disponivel, apenas para indicar se e possivel checar updates manualmente
  local pkg_mgr=""
  if has_cmd apt; then pkg_mgr="apt"; fi
  if has_cmd dnf; then pkg_mgr="dnf"; fi
  if has_cmd yum; then pkg_mgr="yum"; fi
  if has_cmd pacman; then pkg_mgr="pacman"; fi
  if has_cmd zypper; then pkg_mgr="zypper"; fi

  if [ -n "$pkg_mgr" ]; then
    report_finding \
      "Kernel & Update Audit" \
      "Gerenciador de pacotes: $pkg_mgr" \
      "Gerenciador de pacotes identificado, util para o profissional checar manualmente atualizacoes de seguranca disponiveis." \
      "Comando detectado no PATH: $pkg_mgr" \
      "INFO" \
      "Informacao de apoio; esta ferramenta nao executa atualizacoes nem instala pacotes." \
      "Execute a checagem de atualizacoes do seu gerenciador de pacotes de forma manual e autorizada (ex. 'apt list --upgradable')." \
      "Nenhum comando de atualizacao foi executado por esta ferramenta." \
      "info"
  fi

  # Polkit / pkexec version hint (CVE-2021-4034 "PwnKit") - apenas presenca/versao, sem explorar
  if has_cmd pkexec; then
    local pkexec_path pkexec_perms
    pkexec_path="$(command -v pkexec 2>/dev/null)"
    pkexec_perms="$(stat -c '%A' "$pkexec_path" 2>/dev/null)"
    report_finding \
      "Kernel & Update Audit" \
      "$pkexec_path" \
      "Binario 'pkexec' (polkit) presente no sistema. Versoes vulneraveis a CVE-2021-4034 (PwnKit) permitem escalacao local de privilegios." \
      "Caminho: $pkexec_path | Permissoes: $pkexec_perms" \
      "MEDIUM" \
      "PwnKit afetou praticamente todas as instalacoes padrao de polkit por anos antes da correcao; a mera presenca do binario SUID justifica verificacao manual da versao do pacote polkit instalado." \
      "Verifique a versao do pacote polkit/policykit-1 instalada e confirme junto ao gerenciador de pacotes se a correcao de CVE-2021-4034 foi aplicada." \
      "Esta ferramenta nao consulta a versao exata do pacote nem tenta exploracao; apenas sinaliza a presenca do binario para investigacao manual." \
      "potential"
  fi
}
