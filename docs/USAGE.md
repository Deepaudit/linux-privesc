# Guia de Uso

## Execucao basica

```bash
# Auditoria completa (todos os modulos), com saida colorida no terminal
./pcsec-privesc.sh --full

# Apenas o subconjunto rapido (System Enumeration, Sudo, SUID/SGID, Kernel)
./pcsec-privesc.sh --quick

# Sem cores (util para redirecionar para arquivo ou rodar em CI)
./pcsec-privesc.sh --full --no-color
```

## Escolhendo onde salvar os relatorios

```bash
./pcsec-privesc.sh --full --output /tmp/auditoria-$(hostname)-$(date +%F)
```

Por padrao, os relatorios vao para `./pcsec-reports/` (criado
automaticamente se necessario).

## Formatos de saida

| Flag | Gera | Quando usar |
|---|---|---|
| (padrao) | `.txt` | Sempre gerado, leitura humana direta. |
| `--json` | `.json` | Integracao com outras ferramentas, parsing automatizado, base para `--compare`. |
| `--sarif` | `.sarif` | Pipelines de CI/CD, GitHub Code Scanning, SonarQube. |
| `--html` | `.html` | Relatorio visual para compartilhar com stakeholders nao tecnicos; abre direto no navegador, sem servidor. |

Pode combinar quantos quiser na mesma execucao:

```bash
./pcsec-privesc.sh --full --json --sarif --html
```

## Performance: paralelismo e timeout

Por padrao, os modulos rodam um de cada vez (`--jobs 1`), cada um isolado em
seu proprio subprocesso com um timeout de 60 segundos. Em hosts com
filesystems muito grandes (ex. `find` em `/usr/bin` de uma imagem com
milhares de pacotes), ajuste conforme necessario:

```bash
# Roda ate 4 modulos simultaneamente, com 30s de timeout cada
./pcsec-privesc.sh --full --jobs 4 --timeout 30
```

Se um modulo estourar o timeout, ele e reportado como `INFO` (ex.: "timeout
apos 30s; modulo interrompido, auditoria prossegue") e a execucao continua
normalmente para os demais modulos — nenhuma auditoria e perdida por causa
de um unico modulo lento.

## Acompanhando hardening ao longo do tempo

Guarde o JSON de cada execucao e compare com a proxima:

```bash
# Primeira execucao (ex.: antes de aplicar hardening)
./pcsec-privesc.sh --full --json --output ./auditorias/semana-1

# Depois de corrigir os achados, compare com a execucao anterior
./pcsec-privesc.sh --full --json --output ./auditorias/semana-2 \
  --compare ./auditorias/semana-1/pcsec-privesc-report-*.json
```

A saida mostra, de forma explicita, o que ficou **novo** (regrediu) e o que
foi **resolvido** desde a ultima execucao.

## Uso em pipelines de CI/CD

```bash
# Falha o pipeline (exit code 1) se o risk score for >= 50
./pcsec-privesc.sh --full --sarif --fail-on-risk 50
```

Exemplo de step de GitHub Actions (ver tambem
`.github/workflows/lint.yml` no proprio repositorio):

```yaml
- name: Auditoria de seguranca do runner
  run: |
    chmod +x pcsec-privesc.sh
    ./pcsec-privesc.sh --full --no-color --sarif --fail-on-risk 50

- name: Upload SARIF para GitHub Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./pcsec-reports
```

## Listando os modulos disponiveis

```bash
./pcsec-privesc.sh --checks
```

## Interpretando o Correlation Engine

O modulo `Correlation Engine - Attack Path` roda sempre por ultimo e nao
coleta nenhum dado novo — ele apenas combina achados que ja foram reportados
pelos outros modulos nesta mesma execucao. Se ele nao mostrar nenhuma
cadeia, isso **nao significa que o host esta seguro**: significa apenas que
nenhuma das combinacoes pre-programadas foi encontrada. Sempre revise os
achados individuais de cada modulo tambem.

## Exemplos completos

```bash
# Auditoria de producao, completa, com todos os formatos, timeout generoso
./pcsec-privesc.sh --full --jobs 2 --timeout 90 \
  --output /var/log/pcsec/$(date +%Y%m%d) \
  --json --sarif --html

# Checagem rapida em uma nova VM recem-provisionada
./pcsec-privesc.sh --quick --no-color

# Rodando como root para visibilidade maxima (ex. apos login remoto autorizado)
sudo ./pcsec-privesc.sh --full --json
```
