# Kracha

Biblioteca Go pública (`github.com/Kogumelo/kracha`) que prova quem a pessoa
é, para os apps da Kogumelo. Os primeiros clientes são o Kotonazo e o Zebra
de Chapéu. Esta é a dona da ferramenta. Os apps são usuários: a adoção em
cada um é missão do app, não daqui.

## Leia antes

1. [README.md](README.md): o que a biblioteca faz, o que fica no app e como
   acrescentar um provedor.
2. [docs/decisoes.md](docs/decisoes.md): a memória das decisões, com o
   desenho de 10/10/2026 e o que foi feito. Mudança relevante ganha uma
   seção nova, datada, no fim do arquivo.

## Os invariantes

- **A biblioteca prova; o app decide.** Nada aqui cria conta, sessão ou
  cookie, nem junta contas.
- **O núcleo** (`kracha`, `email`, `senha`, `provedor`) importa só a
  biblioteca padrão, `golang.org/x/oauth2` e `golang.org/x/crypto`. O pgx
  fica em `pgkracha`. O `TestFronteira` reprova quem quebrar isso.
- **`EmailGarantido` nunca é inventado.** Ele vem do provedor ou da prova
  por e-mail. Adaptador que não sabe deixa falso.
- **O `go.mod` pede Go 1.25**, o mesmo que os clientes pedem. Subir a
  versão força os apps a subir junto.
- **Repositório público:** nada de segredo. Nos exemplos, as variáveis de
  ambiente vêm vazias.
- **Versão publicada não muda.** Para corrigir, sai uma tag nova (`v0.1.1`);
  nunca se move uma tag que já subiu.

## Testar

```sh
export PATH=/usr/local/go/bin:$PATH
gofmt -l . && go vet ./... && go test ./...
# pgkracha precisa de Postgres descartável:
docker run -d --rm --name kracha-pg -e POSTGRES_PASSWORD=x -p 55432:5432 postgres:17-alpine
KRACHA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test -race ./...
docker stop kracha-pg
```

## Convenções

- Português em tudo. Comentário no código sem acento, como no Kotonazo; o
  README e `docs/` com acento.
- Commit: uma frase declarativa no presente, sem acentos, contando o que
  passou a ser verdade. Liste os arquivos; nunca `git add -A`.
- Não afirme que testou o que não testou.
