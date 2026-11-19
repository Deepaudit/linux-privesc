# Politica de Seguranca

## Reportando uma vulnerabilidade no PCSEC-PRIVESC

Se voce encontrar uma vulnerabilidade de seguranca na propria ferramenta
(por exemplo: um achado que faz a ferramenta executar codigo nao intencional,
um caminho onde a redacao de segredos falha e expoe um valor sensivel, ou
qualquer comportamento que viole o principio de "somente leitura"), por
favor **nao abra uma issue publica** imediatamente.

Em vez disso:

1. Descreva o problema com o maximo de detalhe possivel (versao afetada,
   passos para reproduzir, impacto esperado).
2. Entre em contato de forma privada com o mantenedor do projeto (ver perfil
   do autor no repositorio) antes de divulgar publicamente.
3. De um prazo razoavel para correcao antes de divulgacao publica
   (*responsible disclosure*), tipicamente 90 dias, ou menos se a correcao
   for publicada antes disso.

## O que conta como vulnerabilidade de seguranca aqui

Dado que o projeto e, por design, uma ferramenta de **somente leitura**, os
cenarios mais relevantes de vulnerabilidade na propria ferramenta sao:

- Qualquer caminho de codigo que **escreva, modifique ou execute** algo no
  sistema auditado alem dos arquivos de relatorio no diretorio de saida
  escolhido pelo usuario.
- Qualquer caminho onde `redact_secret()` ou a logica do modulo
  `credential_hunting.sh` **falhe em redigir** um valor sensivel antes de
  ele aparecer no terminal, no relatorio texto, no JSON, no SARIF ou no
  HTML.
- Injecao de comandos atraves de nomes de arquivo, variaveis de ambiente ou
  saida de comandos do sistema manipulada por um usuario malicioso local
  (ex. um nome de arquivo cuidadosamente criado para quebrar um `eval` ou
  um `printf`).
- Qualquer forma de **exfiltracao de dados** para fora do host auditado.

## O que NAO e tratado como vulnerabilidade de seguranca do projeto

- Um achado classificado com severidade que voce discorda (isso e uma
  melhoria de deteccao/classificacao, nao uma vulnerabilidade — abra uma
  issue normal).
- Falsos positivos ou negativos nas listas de referencia (`watchlist` de
  SUID, padroes de credenciais, tabela de CVEs de kernel) — sao
  limitacoes conhecidas e documentadas, nao vulnerabilidades.
- Comportamento esperado de ferramentas externas invocadas (`sudo`,
  `getcap`, `systemctl`) que a ferramenta apenas le a saida.

## Boas praticas ao usar esta ferramenta

- Sempre inspecione o codigo-fonte antes de executar em um sistema de
  producao, especialmente apos atualizar para uma nova versao.
- Nao execute via `curl | bash` sem antes revisar o conteudo.
- Os relatorios gerados (texto, JSON, SARIF, HTML) contem informacoes
  sensiveis sobre a postura de seguranca do host auditado (embora nunca
  segredos em texto claro). Trate-os com o mesmo cuidado que trataria
  qualquer relatorio de pentest: armazenamento controlado, acesso
  restrito, exclusao apos uso quando apropriado.
