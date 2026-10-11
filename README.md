<img src="docs/marca/katraca-giro.svg" width="96" height="96" alt="Katraca logo: a white K on a green plate, made of the post and the three arms of a turnstile">

# Katraca

**English** · [Português](README.pt-BR.md)

Katraca comes from *catraca*, Portuguese for turnstile: it checks who the
person is; the app is the one that lets them through.

A Go library that **proves who a person is**, shared by Kogumelo's apps
(Kotonazo, Zebra de Chapéu and the ones to come).

```sh
go get github.com/Kogumelo/katraca@v0.7.0
```

Code, comments and error strings are in English. Messages for the person
signing in come in English and Portuguese through package
[`i18n`](#messages-for-the-person-i18n).

## What it does and what stays in the app

**The library proves; the app decides.** Every method ends in the same
`katraca.Identity`:

| Field             | What it is                                                              |
|-------------------|-------------------------------------------------------------------------|
| `Provider`        | `"email"`, `"password"`, `"google"`, `"github"` or the name you give    |
| `ID`              | fixed identifier at the provider: OIDC `sub`, GitHub account number, normalized address in the email proof, login in the password |
| `Email`           | reported address, normalized (lowercase); may be empty                  |
| `EmailVerified`   | the provider vouches that the person controls that address              |
| `Name`, `Picture` | cosmetic; may be empty                                                  |
| `Extra`           | what is specific to a provider (GitHub's `login`, for example)          |

| Stays in the library                                | Stays in the app                              |
|-----------------------------------------------------|-----------------------------------------------|
| generating and checking tokens, codes and hashes    | account, session, cookie, screen              |
| expiry, single use, per-address limit, attempt limit | **linking accounts** (and by which rule)     |
| state, PKCE, nonce, id_token verification           | keeping the `Pending` between leaving and coming back |
| argon2id, legacy bcrypt, strength rules             | where the hash lives (the `Store`)            |
| asking "send this to that address"                  | sending the email (SES, SMTP), with its own text and sender |

The library links no account. It has no users table and does not know what
one is.

### The rule the app must not break

**Do not link an identity to an existing account by email without
`EmailVerified`.** Without it, the address is only a claim: someone creates
an account at Google (or GitHub, or any provider) with someone else's
address and, if the app links by email, gets into that person's account.

- Google: `EmailVerified` is the id_token's `email_verified`. A Google
  account with an outside address (not Gmail) may come with it false.
- GitHub: it is the `verified` flag of the primary address.
- Email proof (link or code): always true, that is what it proves.
- Password: whatever the app's `Store` says. A password alone proves no
  address.

With `EmailVerified` false, the app creates a new account by the
(`Provider`, `ID`) pair or asks for an email proof before linking.

`EmailVerified` true is necessary, not sufficient. Before linking, also
check:

- **Does the existing account have its address verified on its side?** If
  the account was born with a password and an address never confirmed, an
  attacker may have created it with the victim's address, waiting for the
  victim to sign in with Google. Linking hands the victim an account the
  attacker can still enter with the password. In that case, don't link; or,
  when linking, drop the account's unconfirmed credentials.
- **Does the account already have an identity from this provider with
  another `ID`?** Then it is another person with the same address (a domain
  that changed hands and recreated its Google Workspace, for example). Don't
  link.
- **The `ID` is unique within a single issuer only.** With `AcceptIssuer`
  accepting more than one `iss` (multi-tenant Microsoft), put the `iss` into
  the ID in `Customize`, or one tenant's `sub` may collide with another's.

### What else stays with the app

- **Password attempt limits.** `Passwords.SignIn` does not count attempts:
  limit per login and per IP on the route. For the email code the library
  already limits per address (6 per code, 30 a day); a per-IP limit on
  `VerifyCode` still helps against someone guessing across many addresses.
- **Don't reveal who has an account.** Answer "send me the link" the same
  way whether the account exists or not, and for password resets send the
  message only if the account exists, with the same answer in both cases.
  `ErrTooManyRequests` applies to any address and reveals nothing.
- **Build with an up-to-date Go.** `go.mod` asks for the minimum (1.25);
  `govulncheck` finds flaws in the 1.25.0 standard library in `net/http`,
  `net/mail` and `crypto/tls` that the library calls. Use the latest patch.

## The methods

Each app enables the ones it wants and sets them up. Defaults are in
parentheses.

### Email proof: link and code (`email`)

It is a single proof with two presentations:

- **Link** (`SendLink` / `VerifyLink`): a 32-byte token inside a URL.
- **Code** (`SendCode` / `VerifyCode`): six digits, with an attempt limit.

It serves three purposes: `email.SignIn`, `email.Confirm` (sign-up) and
`email.Reset` (password). A proof issued for one purpose is not valid for
another.

- Link expiry (15 min) and code expiry (15 min).
- Per-address limit: at most 3 messages in 15 min, adding up links and codes
  of every purpose.
- Single use. Of two simultaneous clicks, only one wins.
- Attempt limit per code (6). Every attempt counts, right or wrong. Past the
  limit, not even the right code is valid. A new code voids the previous
  one.
- Daily limit per address (30 attempts in 24 hours, adding up every code).
  Without it, the 18 guesses every 15 minutes would never end. Past the
  limit, codes for that address are not valid until the window moves on;
  the person can still sign in by link or another method.
- The `Store` only sees the hash: `sha256` of the token; for the code, an
  HMAC-SHA256 of `id:code` with the app key. The key does not live in the
  database, and whoever reads the database cannot find the code by trying
  the million possibilities.
- **`Config.Key` is required:** 32 bytes or more from `crypto/rand`, in the
  app's `.env`. It can be the same as the `provider.Sealer` key, since each
  use derives its own. Changing the key voids the codes not yet used
  (15 min).

```go
prover, err := email.New(store, mailer, email.Config{Key: key})
err = prover.SendLink(ctx, "ana@example.com", email.SignIn)
// ... the person clicks; the page sends the token by POST:
id, err := prover.VerifyLink(ctx, token, email.SignIn)
```

The `Mailer` receives an `email.Message` (`To`, `Purpose`, `Kind`, `Token`
or `Code`, `Expires`) and builds the email. Two recommendations from
Kotonazo:

- Put the token in the **fragment** (`https://app/#signin=TOKEN`), which
  goes to no server, and check it by **POST**. Mail scanners that "check
  links" open GETs and would use up the single use.
- Build the URL from the **configured** origin, never from the request's
  `Host`.

### Password (`password`)

- New hashes in **argon2id**, PHC format. The default is the OWASP minimum:
  19 MiB, 2 iterations, parallelism 1.
- **Verifies bcrypt** (`$2a$`, `$2b$`, `$2y$`) and flags that the hash should
  be replaced. It also flags an argon2id with parameters below the current
  ones. `Passwords.SignIn` does the replacement through the `Store`; whoever
  calls `Params.Verify` directly gets `rehash=true` and stores the new hash.
- **Same latency with and without a user**: an unknown login checks the
  password against a dummy hash of the same cost. During a bcrypt migration,
  while most hashes are still bcrypt, set `Passwords.DummyHash` to a bcrypt
  hash of the same cost.
- **Cost ceilings when reading:** an argon2id hash above 256 MiB, 32
  iterations or parallelism 16, or bcrypt above cost 15, gives
  `ErrInvalidHash` without being computed. An absurd hash in the database
  would make every attempt on that account, by anyone, hang the server.
  `Params.Hash` refuses parameters above the same ceilings.
- Configurable strength rules (`password.Rules`): minimum (8), maximum
  (128), requiring a letter, digit, uppercase letter and symbol (off by
  default, as NIST recommends), forbidden passwords and no login inside the
  password. The `*password.Weak` error tells which rule broke
  (`password.RuleMinLength`, `password.RuleForbidden`...), and `i18n` writes
  it in English or Portuguese.

```go
p := &password.Passwords{Store: store, Rules: password.Rules{MinLength: 10}}
hash, err := p.Hash(newPassword, login)              // sign-up / reset
id, rehashed, err := p.SignIn(ctx, login, typedPassword)
```

### Google, GitHub and other providers (`provider`)

Every provider has two halves:

```go
url, pend, err := p.Begin(ctx)             // keep pend; redirect to url
id, err := p.Complete(ctx, pend, r.Form)   // on the way back
```

- Random `state`, checked in constant time, before anything else: the
  provider's refusal (`ProviderError`) only counts with the outgoing state.
  `ProviderError.Description` is free text from the provider; don't render
  it as HTML.
- **PKCE** S256 always, unless `DisablePKCE` for a provider that rejects it.
- `nonce` on every OIDC flow.
- The userinfo fills in what the id_token lacks, with the same `sub`. The
  address and `email_verified` always come from the same source.
- id_token verified: signature by the issuer's JWKS (RS256 or ES256; never
  `none` or HS*), `iss`, `aud`/`azp`, `exp`, `iat` and nonce.
- **No `access_type=offline`**: signing in needs no refresh token.
- Access token in the `Authorization` header, never in the URL.
- Timeout (10 s) and size limit (1 MiB) on every provider response.
- The `Pending` expires in 10 minutes (`PendingTTL`).

The `Pending` belongs to the app, and whoever holds it completes the sign-in
in the person's place. To keep it in the browser, use `provider.Sealer`,
with the app key:

```go
sealer := &provider.Sealer{Keys: [][]byte{key}} // 32 bytes or more, from crypto/rand

// on the way out:
url, pend, err := p.Begin(ctx)
err = sealer.SetCookie(w, "/callback/", pend)
http.Redirect(w, r, url, http.StatusFound)

// on the way back:
pend, err := sealer.ReadCookie(w, r, "/callback/") // opens and deletes the cookie
id, err := p.Complete(ctx, pend, r.Form)
```

- The `Pending` goes **encrypted and authenticated** (AES-256-GCM): the
  browser cannot read the PKCE verifier or the nonce, and cannot change
  anything without the opening refusing it.
- The expiry goes inside the seal, the same `PendingTTL` as `Complete`.
- A tampered seal, one from another key or an expired one gives an error
  that wraps `katraca.ErrRejected`. A key shorter than 32 bytes gives
  `ErrShortKey`.
- The cookie (`katraca_pending`) is `HttpOnly`, `Secure`, `SameSite=Lax`,
  restricted to the callback path and with `MaxAge` until the expiry.
- **Key rotation:** put the new key first, `Keys: [][]byte{newKey,
  oldKey}`. The first one seals and all of them open. After 10 minutes,
  remove the old one.
- Without `net/http`, call `sealer.Seal(pend)` and `sealer.Open(text)` and
  keep the text wherever you like. In gin, `c.Writer` and `c.Request` work
  with `SetCookie` and `ReadCookie`.
- A `form_post` callback (Apple) is a cross-site POST, and the browser does
  not send `SameSite=Lax` cookies with it. There, set the text from `Seal`
  yourself, in a `SameSite=None`, `Secure` cookie.

The example in [`example/main.go`](example/main.go) shows the whole flow with
`net/http`.

```go
g, err := provider.NewGoogle(provider.Google{ClientID: ..., ClientSecret: ..., RedirectURL: ...})
gh := provider.NewGitHub(provider.GitHub{ClientID: ..., ClientSecret: ..., RedirectURL: ...})
```

## Messages for the person (`i18n`)

The library returns errors; the screen belongs to the app. For those who
don't want to write the messages, package `i18n` has a short text for each
error, in English and Brazilian Portuguese:

```go
lang := i18n.Match(r.Header.Get("Accept-Language")) // i18n.English or i18n.Portuguese
http.Error(w, i18n.Message(lang, err), http.StatusUnauthorized)
```

- `Message` covers `ErrRejected`, `ErrExpired`, `ErrTooManyAttempts`,
  `ErrTooManyRequests`, `ErrInvalidEmail`, the provider's `access_denied`
  refusal (the person cancelled) and every `*password.Weak` rule, with the
  limit in the text ("Use at least 10 characters.").
- Any other error (database down, misconfiguration) becomes "Something went
  wrong", without details: those go to the log.
- `ErrRejected` has a single text on purpose: the message does not tell
  whether the login exists.
- `Match` reads the `Accept-Language` header with its weights (`q=`); any
  `pt` gives Portuguese, and everything else gives English.
- `Text(lang, key)` returns a standalone text, such as
  `i18n.KeyProviderUnavailable` when `Begin` fails.

**Adding a language:** write a catalog like `i18n/pt_br.go`, register it in
`catalogs` and `Languages`, and teach `Match` its tag.
`TestCatalogsComplete` fails while any key is missing.

## Adding a provider

There are two paths, and neither touches the core.

### 1. Is it OIDC? Configuration only

Microsoft, Keycloak, Auth0, gov.br and Google itself are OIDC. The library
reads the rest from `Issuer + /.well-known/openid-configuration`:

```go
ms, err := provider.NewOIDC(provider.OIDCConfig{
    Name:         "microsoft",
    Issuer:       "https://login.microsoftonline.com/consumers/v2.0",
    ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
    ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
    RedirectURL:  "https://app.example/callback/microsoft",
})
```

If the provider strays from the standard, there are hooks that need no new
code in the core:

- `AcceptIssuer`: accepts a different `iss`. Multi-tenant Microsoft puts
  the person's tenant in the `iss`.
- `ExtraParams`: parameters on the authorization URL (`prompt`, `hd`).
- `ResponseMode`: `response_mode`, such as `form_post`.
- `ClientSecretFunc`: a client secret generated on every exchange.
- `Customize`: adjusts the `Identity` with the claims and the callback
  parameters. It can also reject the callback.

### 2. Not OIDC? An OAuth2 adapter

GitHub and Meta issue no id_token. The flow is standard OAuth2, and what
changes is reading the person from the API, in an `Identify` function:

```go
meta := &provider.OAuth2{
    ProviderName: "meta",
    ClientID: ..., ClientSecret: ..., RedirectURL: ...,
    Scopes:   []string{"email", "public_profile"},
    AuthURL:  "https://www.facebook.com/v21.0/dialog/oauth",
    TokenURL: "https://graph.facebook.com/v21.0/oauth/access_token",
    Identify: func(ctx context.Context, api *provider.API) (katraca.Identity, error) {
        var u struct{ ID, Name, Email string }
        if err := api.JSON(ctx, "https://graph.facebook.com/me?fields=id,name,email", &u); err != nil {
            return katraca.Identity{}, err
        }
        // Meta doesn't say whether the address was verified: it goes as unverified.
        return katraca.Identity{ID: u.ID, Name: u.Name, Email: u.Email}, nil
    },
}
```

`api.JSON` already puts the token in the header and applies the timeout and
the size limit. [`provider/github.go`](provider/github.go) is a complete
adapter, in 70 lines.

### Apple: supported, not implemented

Apple is OIDC with four requirements of its own, and all of them fit the
hooks above:

- The client secret is an ES256 JWT that expires: use `ClientSecretFunc`.
- The callback comes by POST: use `ResponseMode: "form_post"`. The app
  passes `r.Form` to `Complete`.
- The name comes only on the first sign-in, in the `user` parameter: read
  it in `Customize` and keep it in the app.
- The address may be a relay (`@privaterelay.appleid.com`), and
  `email_verified` arrives as text. `Claims.Bool` reads both formats.

The `TestOIDCLikeApple` test proves this against a fake provider. What is
missing is the generator for the ES256 JWT with the `.p8` key. It wasn't
written because no app uses Apple yet.

## Persistence: the `Store`

Each method defines its own small interface, and the app implements it on
top of the database and driver it already uses:

- `email.Store`: `Issue`, `ConsumeLink`, `AttemptCode`, `Consume`. Each
  method is atomic, and that is what holds single use and the limit under
  concurrency. `AttemptCode` also returns the address's total attempts in
  the last 24 hours, for the daily limit.
- `pgkatraca.Store.Purge` deletes expired proofs. Run it once a day with a
  cutoff 24 hours ago or earlier, or the daily limit forgets attempts that
  still count.
- `password.Store`: `Credential`, `ReplaceHash`.

There are two ready implementations:

- `email.NewMemory()`: for tests and prototypes.
- `pgkatraca.Store`: reference in Postgres with **pgx**, with the SQL in
  [`pgkatraca/schema.sql`](pgkatraca/schema.sql). It is the only package
  that imports pgx. Those using `lib/pq` or `database/sql` write their own
  `Store` by copying the SQL.

Whoever writes their own `email.Store` runs the contract against it:

```go
func TestMyStore(t *testing.T) {
    emailtest.Contract(t, func(*testing.T) email.Store { return myStore })
}
```

## Dependencies

The core (`katraca`, `email`, `password`, `provider`, `i18n`) imports only
three things:

- the standard library;
- `golang.org/x/oauth2`;
- `golang.org/x/crypto`.

No pgx, gin or web framework. `TestBoundary` fails whoever breaks this.
`go.mod` asks for Go 1.25.

## Testing

```sh
go test ./...
# with Postgres, for pgkatraca:
docker run -d --rm --name katraca-pg -e POSTGRES_PASSWORD=x -p 55432:5432 postgres:17-alpine
KATRACA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test ./...
```

Providers are tested against fake servers (`httptest`), with RSA and EC keys
generated in the test. The tests cover:

- wrong or missing `state`;
- a `Pending` seal that is tampered, from another key, expired, with a short
  key and with key rotation;
- a PKCE verifier from another flow;
- tampered nonce, `aud`, `iss` and `exp`;
- a signature from another key;
- unverified address;
- an oversized response;
- an OIDC provider by configuration alone;
- a made-up OAuth2 adapter;
- swapped alg, short RSA or weak exponent, ES256 with `r`/`s` out of range;
- a userinfo that tries to verify the id_token's address;
- a provider refusal without `state`;
- a password hash with absurd cost;
- the code's limit and single use under concurrent attempts;
- the daily attempt limit per address;
- a code hash that cannot be cracked from the database without the app key;
- `i18n` catalogs complete in both languages.

The security review of 2026-10-11 is in
[`docs/revisao-2026-10-11.md`](docs/revisao-2026-10-11.md) (in Portuguese,
with the names from before the English translation).

## Secrets

There are no secrets in this repository, and there won't be. Provider keys
live in each app's `.env`. See [`example/.env.example`](example/.env.example):
the variables are empty.

## License

[MIT](LICENSE), © 2026 Kogumelo Informática Ltda. Use, copy and modify
freely, keeping the copyright notice. The code comes with no warranty.
