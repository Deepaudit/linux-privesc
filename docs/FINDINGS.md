# Entendendo os Achados (Findings)

Cada achado reportado pela ferramenta segue uma estrutura fixa, pensada para
dar ao profissional tudo que ele precisa para validar e corrigir, sem
precisar voltar ao codigo-fonte da ferramenta.

## Estrutura de um achado

| Campo | O que significa |
|---|---|
| **Verificacao** | Nome do modulo/categoria que gerou o achado. |
| **Alvo** | O arquivo, diretorio, binario ou configuracao especifica avaliada. |
| **Severidade** | `INFO`, `LOW`, `MEDIUM`, `HIGH` ou `CRITICAL`. |
| **Confianca** | `confirmed` (testado diretamente), `potential` (indicio, requer validacao) ou `info` (contexto). |
| **Descricao** | O que foi encontrado, em linguagem direta. |
| **Evidencia** | O dado bruto (redigido quando sensivel) que sustenta o achado. |
| **Motivo** | Por que essa condicao e relevante para escalacao de privilegios. |
| **Recomendacao** | O que fazer para corrigir ou investigar. |
| **Limitacoes** | O que a ferramenta NAO verificou ou NAO pode confirmar sobre este achado especifico. |

O campo **Limitacoes** e deliberadamente obrigatorio em todo achado — a
ferramenta e transparente sobre o que cada verificacao cobre e o que fica de
fora, para evitar conclusoes precipitadas.

## Severidade x prioridade de remediacao

Sugestao de ordem de trabalho ao receber um relatorio:

1. **CRITICAL com confianca `confirmed`** — corrija imediatamente. Sao
   caminhos diretos e verificados (ex. `/etc/shadow` gravavel).
2. **Achados do Correlation Engine** — cadeias combinando dois ou mais
   vetores; priorize mesmo quando a severidade individual de cada parte
   parecer moderada.
3. **HIGH com confianca `confirmed` ou `potential`** — valide manualmente o
   quanto antes.
4. **MEDIUM** — inclua no proximo ciclo de hardening.
5. **LOW / INFO** — revise periodicamente; frequentemente sao esperados
   (ex. `passwd` com SUID).

## Por que a ferramenta nao "confirma" exploracao?

Por design. Confirmar exploracao exigiria rodar codigo arbitrario ou tentar
efetivamente escalar privilegios — exatamente o que este projeto se recusa
a fazer. A ferramenta aponta o **caminho provavel**; a validacao final e
sempre manual e, quando aplicavel, feita com autorizacao formal (ex. em um
teste de pentest contratado).

## Sobre o Correlation Engine especificamente

O motor de correlacao (`modules/correlate.sh`) nao define novos criterios de
deteccao — ele le variaveis de contexto (`PCSEC_CTX_*`) que os outros
modulos ja exportaram durante a mesma execucao e aplica um numero pequeno e
pre-programado de regras de combinacao. As regras atuais da v5:

1. Acesso ao grupo/socket Docker **+** binario `docker` presente.
2. Diretorio de unit files systemd gravavel **+** `systemctl` disponivel.
3. Regra sudo NOPASSWD arriscada **+** binario SUID suspeito fora de local
   legitimo conhecido.
4. `/etc/passwd` ou `/etc/shadow` gravavel (eleva a prioridade no resumo).
5. Cron do sistema gravavel **+** ambiente containerizado.

Novas regras de correlacao podem ser adicionadas por quem for manter o
projeto, seguindo o mesmo padrao: ler variaveis `PCSEC_CTX_*` ja exportadas,
nunca coletar dados novos nesse modulo.

## Sobre o Credential Hunting especificamente

Este modulo **nunca** imprime o valor completo de uma credencial encontrada.
O campo `Evidencia` de um achado desse modulo sempre contem um trecho
redigido (ex. `sup...[REDACTED]`), nunca o segredo completo. Se voce
precisar investigar a fundo, va diretamente ao arquivo e linha indicados no
campo `Alvo` (formato `arquivo:linha`).
