# Katraca

Biblioteca Go pública (`github.com/Kogumelo/katraca`) que prova quem a pessoa
é, para os apps da Kogumelo. Os primeiros clientes são o Kotonazo e o Zebra
de Chapéu. Esta é a dona da ferramenta. Os apps são usuários: a adoção em
cada um é missão do app, não daqui.

## Leia antes

1. [README.md](README.md) (inglês) ou [README.pt-BR.md](README.pt-BR.md):
   o que a biblioteca faz, o que fica no app e como acrescentar um provedor.
   Os dois andam juntos: mudou um, muda o outro.
2. [docs/decisoes.md](docs/decisoes.md): a memória das decisões, com o
   desenho de 10/10/2026 e o que foi feito. Mudança relevante ganha uma
   seção nova, datada, no fim do arquivo.

## Os invariantes

- **A biblioteca prova; o app decide.** Nada aqui cria conta, sessão ou
  cookie, nem junta contas.
- **O núcleo** (`katraca`, `email`, `password`, `provider`, `i18n`) importa
  só a biblioteca padrão, `golang.org/x/oauth2` e `golang.org/x/crypto`. O
  pgx fica em `pgkatraca`. O `TestBoundary` reprova quem quebrar isso.
- **`EmailVerified` nunca é inventado.** Ele vem do provedor ou da prova
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
# pgkatraca precisa de Postgres descartável:
docker run -d --rm --name katraca-pg -e POSTGRES_PASSWORD=x -p 55432:5432 postgres:17-alpine
KATRACA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test -race ./...
docker stop katraca-pg
```

## Convenções

- **Código em inglês:** identificadores, comentários, mensagens de erro,
  testes, SQL e variáveis de ambiente. O projeto é público.
- **O que a pessoa lê passa pelo `i18n`**, em inglês e português. Texto novo
  para a tela entra nos dois catálogos (`i18n/en.go`, `i18n/pt_br.go`); o
  `TestCatalogsComplete` reprova se faltar um.
- **README em dois idiomas:** `README.md` em inglês e `README.pt-BR.md` em
  português, com acento. `docs/` (as decisões e a revisão) segue em
  português: é a memória do dono.
- Commit: em português, uma frase declarativa no presente, sem acentos, contando o que
  passou a ser verdade. Liste os arquivos; nunca `git add -A`.
- Não afirme que testou o que não testou.
