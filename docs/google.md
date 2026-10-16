# Login pelo Google: como criar o projeto no Google Cloud

Guia para quem vai ligar o `provider.NewGoogle` num app da Kogumelo. Escrito
em 16/10/2026; o console do Google muda de nome de menu com frequência, então
os nomes abaixo podem ter mudado — o caminho continua o mesmo.

## Um projeto por app, não um para a Katraca

A Katraca não tem projeto no Google. Ela é uma biblioteca compilada dentro de
cada app; quem fala com o Google é o app, com o `ClientID` e o
`ClientSecret` dele. Por isso:

- **Um projeto no Google Cloud por app** (Kotonazo, Zebra de Chapéu, ...).
  A tela "Fazer login com o Google" mostra o nome, o logotipo, o domínio e a
  política de privacidade **do projeto**: um projeto só para todos faria o
  Kotonazo aparecer como "Kogumelo" ou como outro app. A marca é uma por
  projeto.
- Cada projeto tem sua própria verificação de marca, sua cota e seu
  responsável. Um problema num (suspensão, revisão) não derruba o outro —
  o mesmo motivo pelo qual o acesso não foi para um serviço central
  (`docs/decisoes.md`, 10/10 e 14/10/2026).
- **Separar não prende ninguém:** o `sub` que o Google entrega é o
  identificador da conta Google, igual em qualquer projeto. Se um dia os
  apps quiserem login único, a mesma pessoa terá o mesmo `sub` nos dois.
- **O Zebra provavelmente já tem projeto**, porque já faz login pelo Google
  hoje (`getGoogleUser` em `oauth_service.go`). Reaproveite o projeto e o
  cliente que existem; basta conferir as URLs de retorno (passo 5) quando
  ele migrar para a Katraca.
- Dentro de um projeto, crie **um cliente OAuth por ambiente** se quiser
  separar produção de desenvolvimento (passo 5); não é obrigatório.

## Antes de começar

- Uma conta Google que vá continuar existindo. De preferência a conta da
  empresa (Google Workspace da Kogumelo, se houver), e não uma pessoal: o
  projeto pertence a quem o cria. Acrescente um segundo dono no
  IAM (Identity and Access Management, a tela de permissões) para não ficar
  refém de uma conta só.
- O domínio do app (ex.: `kotonazo.com`) e páginas públicas de **página
  inicial** e **política de privacidade**. Termos de uso são opcionais.
- Acesso ao Google Search Console do domínio, para provar que ele é seu
  (necessário para a verificação de marca, passo 6).

## Passo a passo

### 1. Criar o projeto

1. Entre em <https://console.cloud.google.com>.
2. No seletor de projetos (topo da página) → **Novo projeto**.
3. Nome: o do app, ex.: `Kotonazo`. O ID do projeto é gerado; não importa.
4. Organização: a da Kogumelo, se existir; senão, "Sem organização".
5. **Criar** e confirme que o projeto novo ficou selecionado no topo.

Não é preciso ativar nenhuma API nem cadastrar cartão: login com
`openid email profile` é gratuito.

### 2. Configurar a tela de consentimento

Menu ☰ → **Google Auth Platform** (antes chamava "APIs e serviços → Tela de
permissão OAuth") → **Primeiros passos** / **Get started**.

1. **Informações do app:** nome que a pessoa vê (`Kotonazo`) e e-mail de
   suporte.
2. **Público-alvo:** **Externo** (qualquer conta Google). "Interno" só
   serve para contas do mesmo Workspace.
3. **Contato:** e-mail que recebe os avisos do Google sobre o projeto.
4. Aceite a política de dados do usuário e **Criar**.

### 3. Branding (marca)

Em **Google Auth Platform → Branding**:

- Logotipo (opcional). Quadrado, 120×120 px, PNG ou JPG, até 1 MB, com o
  fundo **até a borda**: um ícone de cantos arredondados sobre fundo
  transparente aparece com cantos brancos, porque o console pinta o
  transparente de branco. Use a versão "maskable" do ícone do app (a de PWA,
  que preenche o quadrado). Com logotipo, publicar o app exige a
  verificação de marca (passo 6); sem ele, publica na hora. Em modo de
  teste, nada disso pesa.
- **Página inicial**, **política de privacidade** e termos de uso.
- **Domínios autorizados:** o domínio raiz do app (`kotonazo.com`). Toda
  URL de retorno e as páginas acima precisam estar nesses domínios.
  `localhost` não entra aqui e não precisa.

### 4. Escopos (Data Access)

Em **Data Access → Adicionar ou remover escopos**, marque só:

- `openid`
- `.../auth/userinfo.email`
- `.../auth/userinfo.profile`

São os escopos que a Katraca pede por padrão (`Scopes` vazio no
`OIDCConfig`). Os três são "não sensíveis": não exigem a revisão de
segurança do Google. Não acrescente outros — escopo sensível obriga a uma
verificação longa e não é necessário para provar quem a pessoa é.

### 5. Criar o cliente OAuth

Em **Google Auth Platform → Clients → Criar cliente**:

1. **Tipo de aplicativo:** **Aplicativo da Web**.
2. **Nome:** só para você se achar, ex.: `Kotonazo produção`.
3. **Origens JavaScript autorizadas:** deixe vazio. O fluxo da Katraca é
   feito no servidor; o navegador só é redirecionado.
4. **URIs de redirecionamento autorizados:** a URL exata que o app passa em
   `RedirectURL`. No exemplo da Katraca e no padrão sugerido é
   `PUBLIC_URL + "/callback/google"`:
   - produção: `https://kotonazo.com/callback/google`
   - desenvolvimento: `http://localhost:8080/callback/google` (o Google
     aceita `http` só para `localhost`).

   Tem que bater caractere por caractere: `https` × `http`, `www` ou não,
   barra no fim, porta. Se não bater, o Google mostra
   `Erro 400: redirect_uri_mismatch`.
5. **Criar.** Aparecem o **ID do cliente** e a **chave secreta do
   cliente**. **Copie a chave secreta agora** (ou baixe o JSON): o Google
   só mostra a chave inteira nesse momento. Se perder, crie uma chave nova
   no mesmo cliente e apague a antiga.

Mudanças nas URLs podem levar de alguns minutos a algumas horas para valer.

### 6. Publicar (sair do modo de teste)

Em **Google Auth Platform → Audience (Público-alvo)**:

- O projeto nasce em **Teste**: só entram as contas listadas em
  **Usuários de teste** (até 100). Bom para desenvolver; acrescente a sua.
- Para abrir ao público, **Publicar app** → **Em produção**. Com só os três
  escopos do passo 4, não há revisão de segurança.
- **Verificação de marca:** para o nome e o logotipo aparecerem na tela do
  Google (e não só o domínio), o Google confere a marca. Pede o domínio
  verificado no Search Console pela mesma conta dona do projeto e costuma
  levar alguns dias úteis. O login funciona enquanto isso.

### 7. Pôr as chaves no app

As duas chaves vão para o ambiente do servidor do app, nunca para o git:

```sh
GOOGLE_CLIENT_ID=1234567890-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...   # do passo 5
```

E no código:

```go
g, err := provider.NewGoogle(provider.Google{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("PUBLIC_URL") + "/callback/google",
})
```

`HostedDomain` fica vazio: ele restringe o login a um Workspace e só serve
para ferramenta interna.

### 8. Testar com o exemplo da Katraca

Antes de mexer no app, dá para conferir o cliente com o exemplo deste
repositório (precisa da URL `http://localhost:8080/callback/google`
cadastrada e da sua conta em Usuários de teste, se o projeto ainda estiver
em Teste):

```sh
export PATH=/usr/local/go/bin:$PATH
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
PUBLIC_URL=http://localhost:8080 go run ./example
```

Abra <http://localhost:8080/login/google>. Ao voltar do Google, a página
mostra a identidade provada:
`provider=google id=... email=... verified=true`.

## Erros comuns

| O Google mostra                           | Causa                                                         |
| ----------------------------------------- | ------------------------------------------------------------- |
| `Erro 400: redirect_uri_mismatch`         | `RedirectURL` diferente da cadastrada no passo 5              |
| `Erro 403: access_denied` em modo de teste | a conta não está em Usuários de teste (passo 6)              |
| `Erro 401: invalid_client`                | ID ou chave secreta errados, ou chave apagada                 |
| `Erro 400: invalid_request` sobre domínio | página ou URL fora dos Domínios autorizados (passo 3)         |

## Lembrete de segurança

`EmailVerified` pode vir **falso** numa conta Google criada com e-mail de
fora (não Gmail). O app não deve juntar essa conta a uma existente pelo
e-mail — ver o README, "A regra que o app não pode quebrar".
