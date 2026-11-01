#!/usr/bin/env bash
#
# modules/container_escape.sh
# Modulo: Vetores de escape/escalacao relacionados a containers, NFS e
# hijacking de bibliotecas dinamicas (LD_PRELOAD / ld.so).
# Apenas leitura e testes de permissao. Nenhum container e criado, iniciado,
# parado ou modificado. Nenhum socket e usado para executar comandos.

# Contexto exportado para o motor de correlacao
PCSEC_CTX_DOCKER_SOCK_WRITABLE=0
PCSEC_CTX_IN_DOCKER_GROUP=0

module_container_escape() {
  # --- Docker socket gravavel: equivalente a root no host na pratica ---
  local sock
  for sock in /var/run/docker.sock /run/docker.sock; do
    if [ -S "$sock" ]; then
      if [ -w "$sock" ]; then
        # shellcheck disable=SC2034 # lido pelo processo pai via compgen -v PCSEC_CTX_
        PCSEC_CTX_DOCKER_SOCK_WRITABLE=1
        report_finding \
          "Container Escape Audit" \
          "$sock" \
          "O socket do daemon Docker e gravavel (acessivel) pelo usuario atual." \
          "Teste de permissao: socket unix gravavel = sim" \
          "CRITICAL" \
          "Acesso de escrita ao socket do Docker permite, na pratica, iniciar containers com montagens arbitrarias do sistema de arquivos do host (ex. '-v /:/mnt'), o que equivale a obter privilegios de root no host. Esta e uma das tecnicas de escalacao mais diretas e bem documentadas em ambientes com Docker." \
          "Restrinja o acesso ao socket apenas a usuarios/grupos estritamente necessarios; evite adicionar usuarios comuns ao grupo 'docker' sem necessidade real." \
          "Esta ferramenta NAO interage com o socket (nenhuma chamada a API do Docker e feita); apenas o teste de permissao do arquivo de socket foi realizado." \
          "confirmed"
      else
        report_finding \
          "Container Escape Audit" \
          "$sock" \
          "Socket do daemon Docker presente, mas nao gravavel pelo usuario atual." \
          "Teste de permissao: socket unix gravavel = nao" \
          "INFO" \
          "Configuracao esperada quando o usuario atual nao pertence ao grupo com acesso ao Docker." \
          "Nenhuma acao necessaria." \
          "Apenas o bit de permissao do socket foi testado." \
          "info"
      fi
    fi
  done

  # --- Usuario pertence ao grupo docker (equivalente a root efetivo) ---
  local groups_now
  groups_now="$(id -Gn 2>/dev/null)"
  if echo " $groups_now " | grep -qi ' docker '; then
    # shellcheck disable=SC2034 # lido pelo processo pai via compgen -v PCSEC_CTX_
    PCSEC_CTX_IN_DOCKER_GROUP=1
    report_finding \
      "Container Escape Audit" \
      "Grupo 'docker'" \
      "O usuario atual pertence ao grupo 'docker'." \
      "Grupos do usuario: $groups_now" \
      "HIGH" \
      "Pertencer ao grupo 'docker' e amplamente documentado como equivalente, na pratica, a privilegios de root no host, pois permite montar o sistema de arquivos raiz dentro de um container controlado pelo usuario." \
      "Avalie se a associacao a este grupo e realmente necessaria; prefira alternativas com escopo reduzido (ex. rootless Docker, Podman sem privilegios de grupo equivalente a root)." \
      "A pertenca ao grupo nao confirma que o socket esteja acessivel no caminho padrao; verificado em conjunto com o achado do socket acima." \
      "confirmed"
  fi

  # --- Indicios de estar dentro de um container (reforco do que system_info ja detecta) ---
  local in_container=0
  [ -f /.dockerenv ] && in_container=1
  if [ "$in_container" -eq 1 ]; then
    # Capabilities do processo atual dentro do container (reforco contextual)
    if [ -r /proc/self/status ]; then
      local cap_eff
      cap_eff="$(grep -i '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')"
      if [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ]; then
        report_finding \
          "Container Escape Audit" \
          "Container atual - capabilities efetivas" \
          "O processo roda dentro de um container (indicio: /.dockerenv) e possui capabilities efetivas diferentes de zero." \
          "CapEff: $cap_eff" \
          "HIGH" \
          "Containers executados com capabilities elevadas (ex. --privileged, --cap-add=SYS_ADMIN) sao um vetor conhecido de escape para o host, especialmente combinados com acesso a /dev ou montagens do host." \
          "Revise a configuracao de execucao do container (docker run/compose) e remova capabilities/flags privilegiadas desnecessarias." \
          "A ferramenta nao decodifica o bitmask para nomes especificos nem tenta confirmar escape; apenas sinaliza a condicao para investigacao manual." \
          "potential"
      fi
    fi

    # cgroup release_agent (tecnica classica de escape com CAP_SYS_ADMIN)
    if [ -w /sys/fs/cgroup ] 2>/dev/null; then
      report_finding \
        "Container Escape Audit" \
        "/sys/fs/cgroup" \
        "Dentro do container, o cgroup filesystem esta montado como gravavel pelo usuario atual." \
        "Teste de permissao: /sys/fs/cgroup gravavel = sim" \
        "HIGH" \
        "cgroups graviaveis dentro de um container, combinados com CAP_SYS_ADMIN, sao a base da tecnica classica de escape via 'release_agent', permitindo execucao de comandos no host." \
        "Garanta que o container nao seja executado com CAP_SYS_ADMIN nem com /sys/fs/cgroup montado como gravavel, a menos que estritamente necessario." \
        "A ferramenta nao tenta escrever no release_agent nem confirma exploracao; apenas testa a permissao do caminho." \
        "potential"
    fi
  fi

  # --- NFS exports com no_root_squash: root remoto = root local ---
  if [ -f /etc/exports ] && [ -r /etc/exports ]; then
    if grep -qE 'no_root_squash' /etc/exports 2>/dev/null; then
      report_finding \
        "Container Escape Audit" \
        "/etc/exports" \
        "Exportacao NFS configurada com a opcao 'no_root_squash'." \
        "Padrao 'no_root_squash' encontrado em /etc/exports (conteudo completo nao reproduzido)" \
        "HIGH" \
        "Com 'no_root_squash', um cliente NFS que se conecta como root mantem privilegios de root sobre os arquivos exportados, permitindo criar binarios SUID no export e executa-los localmente para escalar privilegios." \
        "Remova 'no_root_squash' das exportacoes a menos que haja necessidade operacional explicita e o cliente seja totalmente confiavel." \
        "Deteccao textual simples; nao avalia quais hosts tem permissao de montagem nem testa a montagem de fato." \
        "potential"
    fi
  fi

  # --- ld.so.preload: hijacking global de bibliotecas para TODOS os processos ---
  if [ -f /etc/ld.so.preload ]; then
    local perms owner
    perms="$(stat -c '%A' /etc/ld.so.preload 2>/dev/null)"
    owner="$(stat -c '%U' /etc/ld.so.preload 2>/dev/null)"
    if [ -w /etc/ld.so.preload ]; then
      report_finding \
        "Container Escape Audit" \
        "/etc/ld.so.preload" \
        "Arquivo de preload global de bibliotecas dinamicas e gravavel pelo usuario atual." \
        "Permissoes: $perms | Dono: $owner" \
        "CRITICAL" \
        "Qualquer biblioteca listada em /etc/ld.so.preload e carregada em TODO processo dinamicamente linkado do sistema, incluindo processos root. Escrita neste arquivo e um caminho direto e de alta confianca para execucao de codigo como root." \
        "Corrija a permissao do arquivo imediatamente (dono root, sem escrita para outros); investigue como o arquivo ficou gravavel." \
        "Nenhuma biblioteca foi adicionada a este arquivo por esta ferramenta; apenas a permissao foi testada." \
        "confirmed"
    else
      report_finding \
        "Container Escape Audit" \
        "/etc/ld.so.preload" \
        "Arquivo de preload global de bibliotecas existe mas nao e gravavel pelo usuario atual." \
        "Permissoes: $perms | Dono: $owner" \
        "INFO" \
        "Configuracao esperada; apenas presenca do mecanismo sinalizada para contexto." \
        "Nenhuma acao necessaria." \
        "N/A" \
        "info"
    fi
  fi

  # --- Diretorios de configuracao do ld.so (/etc/ld.so.conf.d/) graviaveis ---
  if [ -d /etc/ld.so.conf.d ]; then
    if [ -w /etc/ld.so.conf.d ]; then
      report_finding \
        "Container Escape Audit" \
        "/etc/ld.so.conf.d" \
        "Diretorio de configuracao de caminhos de biblioteca dinamica e gravavel pelo usuario atual." \
        "Teste de permissao: diretorio gravavel = sim" \
        "HIGH" \
        "Adicionar um diretorio controlado pelo usuario a este caminho (seguido de 'ldconfig') pode permitir que bibliotecas maliciosas sejam carregadas por processos privilegiados que buscam bibliotecas pelo nome." \
        "Corrija a permissao do diretorio para escrita apenas por root." \
        "A exploracao depende de 'ldconfig' ser executado novamente e de processos privilegiados carregarem a biblioteca afetada por nome generico." \
        "potential"
    fi
  fi
}
