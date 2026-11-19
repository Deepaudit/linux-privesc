# Instalacao

## Requisitos minimos

- Bash 4.3 ou superior.
- Utilitarios padrao do sistema: `find`, `stat`, `ps`, `uname`, `id`, `grep`,
  `awk`, `timeout`, `md5sum` (ou `cksum`).

A maioria das distribuicoes Linux modernas (Debian, Ubuntu, Fedora, RHEL,
Arch, Alpine com `bash` instalado) ja atende a esses requisitos sem nada
adicional.

## Passo a passo

```bash
git clone https://github.com/Deepaudit/linux-privesc.git
cd linux-privesc
chmod +x pcsec-privesc.sh
```

### Verifique antes de executar

```bash
less pcsec-privesc.sh
sha256sum pcsec-privesc.sh
```

Compare o hash com o publicado nas releases do projeto (quando disponivel),
e leia o conteudo do script e dos modulos em `modules/` antes da primeira
execucao. Isso vale para qualquer script baixado da internet, nao apenas
este.

### Teste a instalacao

```bash
./pcsec-privesc.sh --version
./pcsec-privesc.sh --checks
./pcsec-privesc.sh --quick --no-color
```

## Instalando dependencias opcionais

Nenhuma delas e obrigatoria; a ferramenta detecta a ausencia e pula a
verificacao correspondente com um achado INFO explicando o motivo.

```bash
# Debian / Ubuntu
sudo apt-get install -y libcap2-bin   # fornece 'getcap' (modulo Capabilities)

# Para rodar a suite de testes (opcional, apenas para desenvolvimento)
git clone https://github.com/bats-core/bats-core.git /tmp/bats-core
sudo /tmp/bats-core/install.sh /usr/local
```

## Instalando via container (ambiente isolado de teste)

Se voce quer rodar a ferramenta num ambiente descartavel para conhece-la
antes de usar em um host real:

```bash
docker run --rm -it -v "$(pwd)":/audit -w /audit debian:12-slim bash -c \
  "chmod +x pcsec-privesc.sh && ./pcsec-privesc.sh --full --no-color"
```

Note que, dentro de um container, varios achados do modulo **Container
Escape Audit** sao esperados e normais (ex. indicio de ambiente
containerizado) — isso e informativo, nao um problema por si so.
