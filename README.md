<img src="docs/marca/katraca-giro.svg" width="96" height="96" alt="Logo da Katraca: um K branco sobre placa verde, formado pelo poste e pelos três braços de uma catraca">

# Katraca

Katraca vem de catraca: ela confere quem a pessoa é; quem libera a passagem é o app.

Biblioteca Go que **prova quem a pessoa é**, comum aos apps da Kogumelo
(Kotonazo, Zebra de Chapéu e os que vierem).

```sh
go get github.com/Kogumelo/katraca@v0.4.0
```

## O que ela faz e o que fica no app

**A biblioteca prova; o app decide.** Todo método termina na mesma
`katraca.Identidade`:

| Campo            | O que é                                                                 |
|------------------|-------------------------------------------------------------------------|
| `Provedor`       | `"email"`, `"senha"`, `"google"`, `"github"` ou o nome que você der      |
| `ID`             | identificador fixo no provedor: `sub` do OIDC, número da conta GitHub, e-mail normalizado na prova por e-mail, login na senha |
| `Email`          | e-mail informado, normalizado (minúsculas); pode vir vazio              |
| `EmailGarantido` | o provedor atesta que a pessoa controla esse e-mail                      |
| `Nome`, `Foto`   | cosméticos; podem vir vazios                                             |
| `Extra`          | o que um provedor tem de próprio (`login` do GitHub, por exemplo)       |

| Fica na biblioteca                                  | Fica no app                                   |
|-----------------------------------------------------|-----------------------------------------------|
| gerar e conferir tokens, códigos e hashes           | conta, sessão, cookie, tela                   |
| prazo, uso único, limite por e-mail, teto de tentativas | **juntar contas** (e com que regra)        |
| state, PKCE, nonce, conferência do id_token         | guardar o `Pendente` entre a ida e a volta    |
| argon2id, bcrypt legado, regras de força            | onde o hash mora (a `Guarda`)                 |
| pedir "mande isto para tal endereço"                | mandar o e-mail (SES, SMTP), com o texto e o remetente dele |

A biblioteca não liga conta nenhuma. Ela não tem tabela de usuários e não sabe
o que é uma.

### A regra que o app não pode quebrar

**Não ligue uma identidade a uma conta existente pelo e-mail sem
`EmailGarantido`.** Sem ele, o e-mail é só uma declaração: alguém cria no
Google (ou no GitHub, ou num provedor qualquer) uma conta com o e-mail de
outra pessoa e, se o app juntar pelo e-mail, entra na conta dela.

- Google: `EmailGarantido` é o `email_verified` do id_token. Uma conta Google
  com e-mail de fora (não Gmail) pode vir com ele falso.
- GitHub: é o `verified` do e-mail principal.
- Prova por e-mail (link ou código): sempre verdadeiro, é isso que ela prova.
- Senha: o que a `Guarda` do app disser. A senha sozinha não prova e-mail.

Com `EmailGarantido` falso, o app cria conta nova pelo par
(`Provedor`, `ID`) ou pede uma prova por e-mail antes de juntar.

## Os métodos

Cada app liga os que quer e parametriza. Os padrões estão entre parênteses.

### Prova por e-mail: link e código (`email`)

É uma prova só, com duas apresentações:

- **Link** (`EnviarLink` / `ConferirLink`): token de 32 bytes num endereço.
- **Código** (`EnviarCodigo` / `ConferirCodigo`): seis dígitos, com teto de
  tentativas.

Ela serve a três finalidades: `email.Entrar`, `email.Confirmar` (cadastro) e
`email.Redefinir` (senha). Uma prova emitida para uma finalidade não vale
para outra.

- Prazo do link (15 min) e do código (15 min).
- Limite por endereço: no máximo 3 mensagens em 15 min, somando links e
  códigos de todas as finalidades.
- Uso único. De dois cliques simultâneos, só um vence.
- Teto de tentativas por código (6). Cada tentativa conta, certa ou errada.
  Passado o teto, nem o código certo vale. Um código novo derruba o anterior.
- A `Guarda` só vê o hash: `sha256` do token; no código, `sha256(id:código)`.

```go
prova, err := email.Nova(guarda, carteiro, email.Config{})
err = prova.EnviarLink(ctx, "ana@exemplo.com", email.Entrar)
// ... a pessoa clica; a tela manda o token por POST:
id, err := prova.ConferirLink(ctx, token, email.Entrar)
```

O `Carteiro` recebe uma `email.Mensagem` (`Para`, `Finalidade`, `Forma`,
`Token` ou `Codigo`, `Expira`) e monta o e-mail. Duas recomendações do
Kotonazo:

- Ponha o token no **fragmento** (`https://app/#entrar=TOKEN`), que não vai
  a servidor nenhum, e confira por **POST**. Leitor de e-mail que "confere
  links" abre GETs e gastaria o uso único.
- Monte o endereço com a origem **configurada**, nunca com o `Host` do
  pedido.

### Senha (`senha`)

- Hash novo em **argon2id**, formato PHC. O padrão é o mínimo da OWASP:
  19 MiB, 2 passadas, 1 via.
- **Confere bcrypt** (`$2a$`, `$2b$`, `$2y$`) e avisa que o hash deve ser
  trocado. Avisa também quando um argon2id tem parâmetros abaixo dos atuais.
  `Senhas.Entrar` faz a troca pela `Guarda`; quem usa
  `Parametros.Conferir` direto recebe `trocar=true` e grava.
- **Mesma latência com e sem usuário**: login inexistente confere a senha
  contra um hash falso de mesmo custo. Durante a migração do bcrypt, quando a
  maioria dos hashes ainda é bcrypt, ponha em `Senhas.HashFalso` um bcrypt do
  mesmo custo.
- Regras de força parametrizáveis (`senha.Regras`): mínimo (8), máximo (128),
  exigências de letra, número, maiúscula e símbolo (desligadas por padrão,
  como recomenda o NIST), senhas proibidas e senha sem o login. O erro
  `*senha.Fraca` diz a regra quebrada, para o app escrever a mensagem na
  língua dele.

```go
s := &senha.Senhas{Guarda: guarda, Regras: senha.Regras{Minimo: 10}}
hash, err := s.Gerar(senhaNova, login)              // cadastro / redefinição
id, trocado, err := s.Entrar(ctx, login, senhaDigitada)
```

### Google, GitHub e outros provedores (`provedor`)

Todo provedor tem duas metades:

```go
url, pend, err := p.Iniciar(ctx)           // guarde pend; redirecione para url
id, err := p.Concluir(ctx, pend, r.Form)   // na volta
```

- `state` aleatório, conferido em tempo constante.
- **PKCE** S256 sempre, salvo `SemPKCE` para provedor que o recuse.
- `nonce` em todo OIDC.
- id_token conferido: assinatura pelo JWKS do emissor (RS256 ou ES256; nunca
  `none` nem HS*), `iss`, `aud`/`azp`, `exp`, `iat` e nonce.
- **Sem `access_type=offline`**: o login não precisa de refresh token.
- Token de acesso no cabeçalho `Authorization`, nunca na URL.
- Prazo (10 s) e limite de tamanho (1 MiB) em toda resposta de provedor.
- O `Pendente` vence em 10 minutos.

O `Pendente` é do app. Guarde-o num cookie `HttpOnly`, **assinado** e de vida
curta, ou na sessão do servidor. Quem o tiver conclui o login no lugar da
pessoa. O exemplo em [`exemplo/main.go`](exemplo/main.go) mostra o fluxo
inteiro com `net/http`.

```go
g, err := provedor.NovoGoogle(provedor.Google{ClienteID: ..., Segredo: ..., Retorno: ...})
gh := provedor.NovoGitHub(provedor.GitHub{ClienteID: ..., Segredo: ..., Retorno: ...})
```

## Acrescentar um provedor

Há dois caminhos, e nenhum mexe no núcleo.

### 1. É OIDC? Só configuração

Microsoft, Keycloak, Auth0, gov.br e o próprio Google são OIDC. A biblioteca
lê o resto em `Emissor + /.well-known/openid-configuration`:

```go
ms, err := provedor.NovoOIDC(provedor.OIDCConfig{
    Nome:      "microsoft",
    Emissor:   "https://login.microsoftonline.com/consumers/v2.0",
    ClienteID: os.Getenv("MICROSOFT_CLIENTE_ID"),
    Segredo:   os.Getenv("MICROSOFT_SEGREDO"),
    Retorno:   "https://app.exemplo/volta/microsoft",
})
```

Se o provedor foge do padrão, há ganchos sem código novo no núcleo:

- `ConferirEmissor`: aceita um `iss` diferente. A Microsoft com vários
  inquilinos põe o inquilino da pessoa no `iss`.
- `ParametrosExtra`: parâmetros no endereço de autorização (`prompt`, `hd`).
- `ModoDeResposta`: `response_mode`, como o `form_post`.
- `SegredoDinamico`: o segredo de cliente gerado a cada troca.
- `Traduzir`: ajusta a `Identidade` com as claims e os parâmetros da volta.
  Também pode recusar a volta.

### 2. Não é OIDC? Um adaptador OAuth2

GitHub e Meta não emitem id_token. O fluxo é o OAuth2 padrão, e o que muda é
ler a pessoa na API, numa função `Traduzir`:

```go
meta := &provedor.OAuth2{
    NomeDoProvedor: "meta",
    ClienteID: ..., Segredo: ..., Retorno: ...,
    Escopos:      []string{"email", "public_profile"},
    AutorizarURL: "https://www.facebook.com/v21.0/dialog/oauth",
    TokenURL:     "https://graph.facebook.com/v21.0/oauth/access_token",
    Traduzir: func(ctx context.Context, api *provedor.API) (katraca.Identidade, error) {
        var u struct{ ID, Name, Email string }
        if err := api.JSON(ctx, "https://graph.facebook.com/me?fields=id,name,email", &u); err != nil {
            return katraca.Identidade{}, err
        }
        // A Meta não diz se o e-mail foi verificado: vai como não garantido.
        return katraca.Identidade{ID: u.ID, Nome: u.Name, Email: u.Email}, nil
    },
}
```

`api.JSON` já põe o token no cabeçalho e aplica o prazo e o limite de
tamanho. [`provedor/github.go`](provedor/github.go) é um adaptador completo,
com 70 linhas.

### Apple: comportada, não implementada

A Apple é OIDC com quatro exigências próprias, e todas cabem nos ganchos
acima:

- O segredo de cliente é um JWT ES256 que vence: use `SegredoDinamico`.
- A volta vem por POST: use `ModoDeResposta: "form_post"`. O app passa
  `r.Form` a `Concluir`.
- O nome vem só no primeiro login, no parâmetro `user`: leia-o em `Traduzir`
  e guarde-o no app.
- O e-mail pode ser de retransmissão (`@privaterelay.appleid.com`), e
  `email_verified` chega como texto. `Reivindicacoes.Verdade` lê os dois
  formatos.

O teste `TestOIDCComoAApple` prova isso contra um provedor falso. Falta
escrever o gerador do JWT ES256 com a chave `.p8`. Não foi feito porque ainda
não há app que use a Apple.

## Persistência: a `Guarda`

Cada método define a sua interface pequena, e o app a implementa sobre o
banco e o driver que já usa:

- `email.Guarda`: `Emitir`, `GastarLink`, `TentarCodigo`, `Gastar`. Cada
  método é atômico, e é isso que sustenta o uso único e o limite sob
  concorrência.
- `senha.Guarda`: `Credencial`, `TrocarHash`.

Há duas implementações prontas:

- `email.NovaMemoria()`: para testes e protótipos.
- `pgkatraca.Guarda`: referência em Postgres com **pgx**, com o SQL em
  [`pgkatraca/esquema.sql`](pgkatraca/esquema.sql). É o único pacote que
  importa pgx. Quem usa `lib/pq` ou `database/sql` escreve a sua Guarda
  copiando o SQL.

Quem escreve uma `email.Guarda` própria roda o contrato contra ela:

```go
func TestMinhaGuarda(t *testing.T) {
    emailteste.Contrato(t, func(*testing.T) email.Guarda { return minhaGuarda })
}
```

## Dependências

O núcleo (`katraca`, `email`, `senha`, `provedor`) importa só três coisas:

- a biblioteca padrão;
- `golang.org/x/oauth2`;
- `golang.org/x/crypto`.

Nada de pgx, gin ou framework web. O `TestFronteira` reprova quem quebrar
isso. O `go.mod` pede Go 1.25.

## Testar

```sh
go test ./...
# com Postgres, para pgkatraca:
docker run -d --rm --name katraca-pg -e POSTGRES_PASSWORD=x -p 55432:5432 postgres:17-alpine
KATRACA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test ./...
```

Os provedores são testados contra servidores falsos (`httptest`), com chaves
RSA e EC geradas no teste. Os testes cobrem:

- `state` errado ou ausente;
- verificador PKCE de outra ida;
- nonce, `aud`, `iss` e `exp` adulterados;
- assinatura de outra chave;
- e-mail não garantido;
- resposta grande demais;
- um provedor OIDC só por configuração;
- um adaptador OAuth2 inventado.

## Segredos

Não há segredo neste repositório, nem haverá. As chaves dos provedores ficam
no `.env` de cada app. Veja [`exemplo/.env.exemplo`](exemplo/.env.exemplo):
as variáveis vêm vazias.

## Licença

[MIT](LICENSE), © 2026 Kogumelo Informática Ltda. Use, copie e modifique à
vontade, mantendo o aviso de copyright. O código vem sem garantia.
