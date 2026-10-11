# Decisões

A memória das decisões da biblioteca. Mudança relevante ganha uma seção
nova, datada, no fim do arquivo. Se algo parecer errado ou incompleto,
procure aqui o motivo antes de discordar.

As duas primeiras seções nasceram no `docs/roadmap.md` do Kotonazo, onde a
biblioteca foi decidida e construída. Desde 11/10/2026 elas moram aqui, e o
Kotonazo é só um dos apps que usam a biblioteca.

## O acesso vira biblioteca comum aos apps da Kogumelo (10/10/2026)

**A decisão do operador:** a prova de identidade sai de cada jogo para uma biblioteca Go
própria, em `~/Kogumelo/Ferramentas/acesso`, **pública desde o início** ("já fica do jeito
certo"), em `github.com/Kogumelo/acesso`. Pública e não pasta solta porque o CI do Kotonazo e o
`Dockerfile` do Zebra de Chapéu compilam longe do Mac e não enxergariam um caminho local; e
privada pediria credencial do GitHub em cada lugar que compila. Não há segredo no código: as
chaves dos provedores ficam no `.env` de cada app. Um serviço central de contas ("conta
Kogumelo", com login único entre os jogos) foi considerado e descartado por ora: mais um sistema
no ar, ida e volta entre domínios, e LGPD entre produtos.

**O desenho, conversado:**

- **Genérica por métodos.** Cada método — link mágico, Google, GitHub, Apple, login e senha — é
  um jeito de provar quem a pessoa é, e todos devolvem a mesma coisa: provedor, identificador
  fixo, e-mail e **se o e-mail é garantido**. Cada app liga os métodos que quer e os parametriza
  (prazo do link, links por e-mail, regras de senha).
- **A biblioteca prova; o app decide.** Conta, sessão, cookie e tela ficam em cada app: no
  Kotonazo, a junção dos aparelhos anônimos; no Zebra, grupos e administrador. O envio do
  e-mail também: a biblioteca pede "mande isto para tal endereço", e o app manda pelo SES dele.
  A persistência (links emitidos, hash de senha) é uma interface que o app implementa nas
  migrações dele; a biblioteca traz o SQL de referência em Postgres.
- **Nasce com tudo que os dois jogos usam (revisto em 11/10).** O operador: "a biblioteca deve
  ter google, link magico, GitHub e login/senha, para que já seja possível depois mudar o zebra
  sem precisar voltar a mexer na biblioteca. E a biblioteca já deve ser 'esperta' para permitir,
  rapidamente, incorporar outras identidades." Daí: link mágico e código de 6 dígitos como duas
  apresentações da mesma prova por e-mail; senha em argon2id que **verifica bcrypt** (o Zebra
  usa bcrypt) e avisa quando re-hashear; Google e GitHub com PKCE. Provedor novo entra como
  configuração, se for OIDC (Google, Microsoft, gov.br), ou como um adaptador pequeno, se não
  for (GitHub, Meta). Apple fica comportada no desenho e não implementada.
- **gov.br não serve aos jogos.** O Login Único é integrado por serviços públicos; a notícia de
  bancos "aderindo" é o caminho inverso (o banco como porta de entrada do gov.br). Não
  confirmado na norma da Secretaria de Governo Digital, só na pesquisa de 11/10.
- **Missões guardadas em 11/10:** `2c0dce5c` (a biblioteca), `d50b2be5` (o Kotonazo passa a
  usá-la, com Google) e `398c0c10` (o Zebra migra e fecha o defeito abaixo), as duas últimas
  esperando a primeira.
- **Um defeito a não copiar.** O Zebra liga o login do Google a um usuário existente pelo
  e-mail sem conferir `verified_email` (`oauth_service.go`, `getGoogleUser`; no GitHub ele
  confere). A biblioteca expõe o "e-mail garantido" e não liga contas sem ele; o Zebra fecha o
  defeito ao migrar.

Nada disso foi construído naquela conversa: nem a pasta, nem o repositório.

## A biblioteca de acesso existe: `github.com/Kogumelo/acesso` v0.1.0 (11/10/2026)

A missão `2c0dce5c` construiu o que a seção de 10/10 desenhou, em
`~/Kogumelo/Ferramentas/acesso`. O repositório é público e tem a tag `v0.1.0`.
O Kotonazo não mudou. A troca do link mágico dele
pela biblioteca é a missão `d50b2be5`, e a migração do Zebra é a `398c0c10`.

**O que tem:**

- `acesso.Identidade` é o resultado de todo método: provedor, ID fixo,
  e-mail normalizado, `EmailGarantido`, nome, foto e `Extra`.
- Os erros de recusa embrulham `acesso.ErrRecusado`. São eles
  `ErrExpirado` e `ErrMuitasTentativas`. `ErrMuitosPedidos` fica à parte,
  porque é limite e não recusa.
- `email`: uma prova, duas formas (link de 32 bytes, código de 6 dígitos) e
  três finalidades (`Entrar`, `Confirmar`, `Redefinir`). Os padrões vêm do
  Kotonazo e do Zebra:
  - 15 minutos de prazo;
  - 3 mensagens por endereço em 15 minutos, somando links e códigos;
  - teto de 6 tentativas por código.
  
  Um código novo derruba o anterior. Saem da biblioteca o `Carteiro`
  (o app manda o e-mail) e a `Guarda` (o app guarda só o hash).
  `email/emailteste.Contrato` confere qualquer Guarda.
- `senha`: argon2id (19 MiB, t=2, p=1). Ela confere `$2a$`, `$2b$` e `$2y$`
  e devolve `trocar=true`. `Senhas.Entrar` regrava pela Guarda. Login
  inexistente confere contra um hash falso. A medida no Mac deu 18,5 ms com
  usuário e 18,3 ms sem. `HashFalso` serve para o período em que o Zebra
  ainda tem mais bcrypt que argon2id. As regras de força dão `*senha.Fraca`
  com o nome da regra quebrada.
- `provedor`:
  - `NovoOIDC` só por configuração, pela descoberta;
  - adaptador `OAuth2` com uma função `Traduzir`;
  - `NovoGoogle` e `NovoGitHub`;
  - state, PKCE S256 e nonce;
  - id_token conferido pelo JWKS (RS256 e ES256, nunca `none`/HS*);
  - sem `access_type=offline`, token no cabeçalho, 10 s e 1 MiB por
    resposta, `Pendente` com 10 minutos.
  
  A Apple cabe sem mexer no núcleo: `SegredoDinamico`, `ModoDeResposta`,
  `Traduzir` e `Reivindicacoes.Verdade` para `email_verified` em texto.
  `TestOIDCComoAApple` prova isso contra um provedor falso. Falta só o
  gerador do JWT ES256 com a chave `.p8`.
- `pgacesso`: a Guarda de referência com pgx e o `esquema.sql`, com as
  tabelas `acesso_prova` e `acesso_senha`. O limite é atômico por
  `pg_advisory_xact_lock` no endereço. O contrato inteiro passou contra um
  Postgres 17 descartável.
- O núcleo importa só a biblioteca padrão, `x/oauth2` e `x/crypto`.
  `TestFronteira` reprova o contrário. Um módulo de fora que importou
  `v0.1.0` não herdou o pgx no `go.mod`. O `go.mod` pede Go 1.25, o mesmo
  que o Kotonazo e o Zebra.

**O que ficou pendente:**

- **O CI não subiu.** O token do `gh` neste Mac não tem o escopo `workflow`,
  e o GitHub recusa `.github/workflows/teste.yml` sem ele. O arquivo existe
  em `~/Kogumelo/Ferramentas/acesso/.github/workflows/teste.yml`, fora do
  git. Ele roda gofmt, vet e `go test -race` com um Postgres de serviço. Para
  subir: `gh auth refresh -s workflow`, depois commit e push.
- **A tag `v0.1.0` aponta para o commit `3f4fa2f`, que não está na `main`.**
  A tag subiu antes de o push da `main` ser recusado pelo workflow. A `main`
  (`4f59082`) é o mesmo commit sem o arquivo de CI. O código das duas é
  idêntico, e `git diff` mostra só `teste.yml`. Mover a tag pedia push
  forçado, que está fora do alcance das missões. Como importar funciona, a
  tag ficou. A próxima versão (`v0.1.1`) sai da `main` já com o CI.
- **Licença:** MIT, com copyright em nome da Kogumelo Informática Ltda. A
  decisão é do operador, em 11/10. A licença ficou com a empresa porque o
  código serve aos produtos dela, mora na organização dela no GitHub e é
  commitado com o e-mail dela. Entrou no commit `b58fef4`, depois da tag
  `v0.1.0`; a próxima tag já a leva.
- **Fora de escopo:** Meta, Apple e gov.br. O README mostra como cada um
  entraria.

## A biblioteca passa a ter casa própria (11/10/2026)

O operador queria a missão `2c0dce5c` criada no projeto Acesso desde o
início. Ela foi criada no Kotonazo. O código não sofreu com isso: foi escrito
direto aqui, na `main`. Mas a memória das decisões ficou no roadmap do
Kotonazo, e a sala do Acesso não tinha branch nenhuma para mostrar. Por isso
as duas seções acima vieram para este arquivo, e no Kotonazo ficou só um
apontador. Nas palavras do operador: "o Kotonazo vai ser usuário, não dono
da ferramenta".

A partir daqui:

- Mudança na biblioteca é missão do projeto Acesso.
- Adotar a biblioteca é missão de cada app: `d50b2be5` no Kotonazo,
  `398c0c10` no Zebra.

## A biblioteca passa a se chamar Kracha (11/10/2026)

Em 11/10 o operador decidiu trocar o nome `acesso` por **Kracha**. Lê-se
"Krácha" e brinca com "crachá": o crachá diz quem a pessoa é, e quem decide
se ela entra é o porteiro, ou seja, o app. É o invariante "a biblioteca
prova; o app decide".

Por que trocar:

- **"acesso" colide nos apps clientes.** A palavra aparece em 35 arquivos do
  Zebra (controle de acesso) e em 7 do Kotonazo ("último acesso"). O prefixo
  `km-` não resolveria: pacote Go não leva hífen, e no código continuaria
  `acesso.`.
- **"prova" também foi descartada.** No Kotonazo ela é a palavra para teste
  ("TestX prova que…", em 52 arquivos), e há helpers de teste com um
  parâmetro chamado `prova`.
- **"cracha" não aparece em nenhum dos dois apps.**
- **Família K.** As ferramentas da Kogumelo trocam o `km-` pela inicial K:
  Konph, Kracha. O operador preferiu Kracha a Kraxah, sabendo que a tônica se
  lê "Krácha".

A marca se escreve Kracha; caminho, pacotes e identificadores ficam em
minúsculas, porque o caminho de módulo Go diferencia maiúsculas.

O que mudou:

- **Módulo:** `github.com/Kogumelo/kracha`.
- **Pacotes:** o raiz passa a `kracha` (`acesso.go` virou `kracha.go`) e
  `pgacesso` passa a `pgkracha`. As mensagens de erro começam por
  `"kracha: "`.
- **Tabelas e índices:** `kracha_prova`, `kracha_senha`, `kracha_prova_link`
  e `kracha_prova_email`; a trava no banco usa a chave `'kracha_prova:'`.
  Renomear sem migração foi possível porque nenhum app importava a
  biblioteca ainda: o único `go.mod` que citava `github.com/Kogumelo/acesso`
  era o dela.
- A variável de teste `ACESSO_PG_URL` ficou com esse nome.

A `v0.1.0` continua no cache do Go (proxy.golang.org) sob o nome antigo,
`github.com/Kogumelo/acesso`, e não muda. A próxima tag, já com o nome novo,
é a `v0.2.0`.

Fica com o operador depois do merge:

- renomear o repositório no GitHub: `gh repo rename kracha -R Kogumelo/acesso`
  (o GitHub redireciona o endereço antigo);
- soltar a tag `v0.2.0` na `main` já renomeada, sem mover a `v0.1.0`;
- renomear a pasta local `~/Kogumelo/Ferramentas/acesso` e o projeto do
  Sitroom (`~/.sitroom/projects/acesso.toml`);
- atualizar os briefings das missões de adoção `d50b2be5` (Kotonazo) e
  `398c0c10` (Zebra), que citam `github.com/Kogumelo/acesso`;
- ajustar o CI (`.github/workflows/teste.yml`, fora do git), que ainda usa o
  nome antigo do contêiner, quando ele subir.

## O nome antigo sai do que ainda falava "acesso" (11/10/2026)

A troca de nome tinha ficado na branch da missão `ea9e0dc3`, sem chegar à
`main`, e a pasta e o repositório foram renomeados antes do merge. A missão
`73c8ccfd` trouxe aquela branch e fechou o que sobrava:

- A variável de teste passa a `KRACHA_PG_URL`; `ACESSO_PG_URL` não é mais
  lida. O CI (`.github/workflows/teste.yml`, ainda fora do git) foi ajustado
  junto.
- Já estavam feitos pelo operador: o repositório no GitHub se chama
  `Kogumelo/kracha` e a pasta é `~/Kogumelo/Ferramentas/kracha`.
- Os briefings das missões guardadas passam a citar `github.com/Kogumelo/kracha`,
  a pasta nova e os pacotes `kracha`/`pgkracha`.

As seções acima ficam como foram escritas: são a memória de quando o nome
era outro.

## O CI sobe e a versão a usar é a `v0.3.0` (11/10/2026)

- **O CI está no ar.** `.github/workflows/teste.yml` entrou no git: gofmt,
  `go vet` e `go test -race ./...` com um Postgres 17 de serviço
  (`KRACHA_PG_URL`), em todo push e pull request. A versão do Go vem do
  `go.mod`; as actions subiram para `actions/checkout@v7` e
  `actions/setup-go@v7`. O push antes recusado precisava do escopo
  `workflow` no token do `gh`, que agora existe.
- **A `v0.2.0` não serve e fica como está.** Ela já tinha sido solta, como
  tag leve, no commit `767e037`, anterior à troca de nome: o `go.mod` dali
  ainda diz `github.com/Kogumelo/acesso`. O proxy do Go guardou essa versão
  sob os dois nomes, e `go get github.com/Kogumelo/kracha@v0.2.0` falha por
  caminho de módulo divergente. Tag publicada não se move, então o número
  foi abandonado.
- **A versão a usar é a `v0.3.0`**, tag anotada no commit da `main` com o CI
  verde. É a primeira com o nome `github.com/Kogumelo/kracha` e leva a
  licença MIT, o `CLAUDE.md`, esta memória e o CI. O README já manda
  `go get github.com/Kogumelo/kracha@v0.3.0`.
- A `v0.1.0` (`3f4fa2f`, fora da `main`) continua onde estava, sob o nome
  antigo.

## O nome definitivo é Katraca, e a próxima versão é a `v0.4.0` (11/10/2026)

O operador fechou a pergunta deixada aberta pela missão `271d81f3`: o nome
definitivo é **Katraca**, de catraca. A catraca confere o crachá e libera a
passagem; quem decide quem passa continua sendo o app. Kracha foi nome de
transição.

O que mudou:

- **Módulo:** `github.com/Kogumelo/katraca`.
- **Pacotes:** o raiz passa a `katraca` (`kracha.go` virou `katraca.go`) e
  `pgkracha` passa a `pgkatraca`. As mensagens de erro começam por
  `"katraca: "`.
- **Tabelas e índices:** `katraca_prova`, `katraca_senha`,
  `katraca_prova_link` e `katraca_prova_email`; a trava no banco usa a chave
  `'katraca_prova:'`. De novo sem migração: nenhum `go.mod` em
  `~/Kogumelo/Jogos` importa a biblioteca.
- **Variável de teste:** `KATRACA_PG_URL`, no código e no CI.

As versões até a `v0.3.0` continuam no proxy do Go com os nomes antigos
(`v0.1.0` e `v0.2.0` como `github.com/Kogumelo/acesso`, `v0.3.0` como
`github.com/Kogumelo/kracha`) e não mudam; nada se publica no módulo antigo.
A próxima tag, já com o nome novo, é a `v0.4.0`.

Fica para a missão seguinte, depois do merge: renomear o repositório no
GitHub, a pasta `~/Kogumelo/Ferramentas/kracha` e o projeto do Sitroom, e
soltar a tag `v0.4.0`.

As seções acima ficam como foram escritas: são a memória de quando o nome
era outro.

## A Katraca ganha logo: o rotor K (11/10/2026)

O logo é uma catraca de tripé que forma um K. A haste da letra é o poste; os
três braços do rotor, iguais e a 120 graus, saem do cubo e formam o resto. Um
deles aponta para trás e atravessa o poste, e os outros dois sobem e descem a
60 graus.

- **Os três braços são iguais (36).** Num rascunho anterior, o braço de trás
  parava no poste e era menos da metade dos outros; ao girar, o K se
  desmontava. Com os três iguais, um terço de volta deixa o desenho igual ao
  de antes: uma pessoa passou e o K continua de pé.
- **Poste e braços com a mesma espessura (10) e o mesmo raio de canto (2).**
  O poste fica a 1,5 do disco do cubo.
- **Verde**, `#26905f` a `#155c3c`, na placa do gabarito de ícone de Mac
  (84 de lado, raio 19), a mesma do Konfig.

Os arquivos ficam em `docs/marca/`:

- `katraca.svg`: o logo oficial, parado. É o que o Sitroom mostra no cartão
  do projeto.
- `katraca-giro.svg`: o rotor dá um terço de volta a cada 3,2 s. Vai no
  topo do README. Quem pede menos movimento no sistema vê o logo parado.
- `katraca-16.svg`: desenho próprio para 16px, com tudo mais grosso (13),
  cantos retos e sem o furo do cubo.

Ficaram de fora a roda de catraca de bicicleta, o sinal `⊢` da lógica e uma
catraca sem braço, que foram as outras direções estudadas. O cartão de
compartilhamento do GitHub (1280×640) não foi feito: ele sobe à mão nas
configurações do repositório.

## O `Pendente` ganha selo, e a versão é a `v0.5.0` (11/10/2026)

Até aqui, guardar o `Pendente` entre a ida e a volta era do app, e o README
pedia um cookie assinado. O Kotonazo (missão `d50b2be5`) e o Zebra (missão
`398c0c10`) iam escrever cada um o seu HMAC: duas peças de segurança para
revisar. A biblioteca passa a ter uma, o `provedor.Selo`, como camada
opcional por cima. `Iniciar` e `Concluir` não mudaram.

- **Cifrado, não só assinado: AES-256-GCM**, da biblioteca padrão. O
  `Pendente` leva o verificador PKCE e o nonce. Com HMAC eles iriam legíveis
  no cookie, e o PKCE existe para que o verificador não passe pelo
  navegador. O GCM autentica e esconde de uma vez, e confere a etiqueta em
  tempo constante. O custo é o tamanho: cerca de 350 caracteres, que cabem
  com folga num cookie.
- **A chave do AES sai de um HMAC-SHA256 da chave do app** com o rótulo
  `katraca/provedor/selo/k1`. Assim o app pode usar a mesma chave em outro
  lugar sem que um uso abra o outro.
- **Chave de 32 bytes ou mais**, senão `ErrChaveCurta`. É erro de
  configuração e não embrulha `ErrRecusado`.
- **Formato `k1.<base64url(nonce‖cifra)>`.** O `k1` também entra como dado
  associado do GCM. Um formato novo vira `k2` sem confundir os selos antigos.
- **O prazo vai dentro**: `Criado + PrazoDoInicio`, o mesmo que `Concluir`
  confere. Vencido dá `katraca.ErrExpirado`; adulterado, de outra chave, de
  outro formato ou maior que 2 KiB dá erro que embrulha `katraca.ErrRecusado`.
- **Troca de chave:** `Chaves[0]` sela e todas abrem. A abertura tenta uma
  a uma. Não há identificador de chave no selo, porque com duas ou três
  chaves ele economizaria pouco e mostraria qual está em uso.
- **A ajuda de `net/http`** (`PlantarCookie`, `LerCookie`) usa só
  `http.ResponseWriter` e `*http.Request`, que o gin também expõe. O cookie
  `katraca_pendente` sai `HttpOnly`, `Secure`, `SameSite=Lax`, com o caminho
  da volta e `MaxAge` até o fim do prazo. `LerCookie` apaga o cookie ao ler.
- **O que o selo não resolve:** ele não é de uso único no servidor. Quem
  copiar o cookie dentro dos 10 minutos tem o mesmo que a pessoa, como antes.
  E a volta por `form_post` (Apple) não leva cookie `SameSite=Lax`; quem
  ligar a Apple planta o texto de `Selar` num cookie `SameSite=None`.

O `exemplo/main.go` passa a usar o selo, com a chave em `SELO_CHAVE` no
`.env` (vazia no `.env.exemplo`; sem ela, o exemplo sorteia uma ao subir).

**A versão é a `v0.5.0`, não a `v0.2.0`** que o briefing pedia: a `v0.2.0`
já existe (abandonada, sob o nome `acesso`) e a última publicada é a
`v0.4.0`. Tag publicada não se move, e API nova sobe o número do meio.
