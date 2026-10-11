package provedor

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Kogumelo/katraca"
	"golang.org/x/oauth2"
)

// OIDCConfig descreve um provedor OpenID Connect. Para a maioria (Google,
// Microsoft, Keycloak, gov.br), acrescentar o provedor e so preencher isto: o
// resto vem do documento de descoberta
// (Emissor + "/.well-known/openid-configuration").
type OIDCConfig struct {
	Nome      string // vai em Identidade.Provedor
	Emissor   string // "https://accounts.google.com"
	ClienteID string
	Segredo   string
	// SegredoDinamico, se dado, substitui Segredo a cada troca de code. A
	// Apple pede um JWT assinado em ES256 que vence; e aqui que ele e gerado.
	SegredoDinamico func(ctx context.Context) (string, error)
	Retorno         string   // URL de volta, registrada no provedor
	Escopos         []string // vazio vale openid, email, profile
	// ModoDeResposta vai como response_mode ("form_post" na Apple, que
	// manda a volta por POST quando pede nome ou e-mail).
	ModoDeResposta string
	// ParametrosExtra vao no endereco de autorizacao ("prompt", "hd"...).
	ParametrosExtra map[string]string
	// SemPKCE desliga o PKCE, para provedor que o recusa.
	SemPKCE bool
	// ConferirEmissor aceita um iss diferente do Emissor. A Microsoft
	// multi-inquilino, por exemplo, emite com o inquilino da pessoa no iss.
	// Vazio: o iss tem de ser igual ao do documento de descoberta.
	ConferirEmissor func(iss string) bool
	// Traduzir ajusta a Identidade depois da leitura padrao (sub, email,
	// email_verified, name, picture), com as reivindicacoes do id_token e os
	// parametros da volta. A Apple, por exemplo, manda o nome so no primeiro
	// login, no parametro "user" do form_post.
	Traduzir func(r Reivindicacoes, resposta url.Values, id *katraca.Identidade) error
	Cliente  *http.Client // vazio vale ClientePadrao
	Agora    func() time.Time
}

// Reivindicacoes sao as claims do id_token, decodificadas como vieram.
type Reivindicacoes map[string]any

// Texto devolve a claim como texto ("" se nao for texto).
func (r Reivindicacoes) Texto(nome string) string {
	s, _ := r[nome].(string)
	return s
}

// Verdade le uma claim booleana que alguns provedores (Apple) mandam como
// texto "true".
func (r Reivindicacoes) Verdade(nome string) bool {
	switch v := r[nome].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// OIDC e o provedor montado. A descoberta e o JWKS sao lidos no primeiro uso
// e guardados; o JWKS e relido quando aparece um kid desconhecido (o
// provedor trocou a chave).
type OIDC struct {
	cfg OIDCConfig

	mu       sync.Mutex
	doc      *descoberta
	chaves   map[string]chaveJWK
	lidoJWKS time.Time
}

type descoberta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NovoOIDC monta o provedor sem ir a rede: a descoberta fica para o primeiro
// Iniciar, e um provedor fora do ar nao impede o app de subir.
func NovoOIDC(cfg OIDCConfig) (*OIDC, error) {
	if cfg.Nome == "" || cfg.Emissor == "" || cfg.ClienteID == "" || cfg.Retorno == "" {
		return nil, fmt.Errorf("provedor OIDC: Nome, Emissor, ClienteID e Retorno sao obrigatorios")
	}
	if len(cfg.Escopos) == 0 {
		cfg.Escopos = []string{"openid", "email", "profile"}
	}
	if cfg.Agora == nil {
		cfg.Agora = time.Now
	}
	return &OIDC{cfg: cfg}, nil
}

func (o *OIDC) Nome() string { return o.cfg.Nome }

func (o *OIDC) descobrir(ctx context.Context) (*descoberta, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.doc != nil {
		return o.doc, nil
	}
	endereco := strings.TrimRight(o.cfg.Emissor, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endereco, nil)
	if err != nil {
		return nil, err
	}
	var d descoberta
	if err := lerJSON(o.cfg.Cliente, req, &d); err != nil {
		return nil, fmt.Errorf("provedor %s: descoberta: %w", o.cfg.Nome, err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("provedor %s: documento de descoberta incompleto", o.cfg.Nome)
	}
	// O documento diz quem e o emissor; ele tem de ser quem configuramos.
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(o.cfg.Emissor, "/") {
		return nil, fmt.Errorf("provedor %s: descoberta diz emissor %q", o.cfg.Nome, d.Issuer)
	}
	o.doc = &d
	return o.doc, nil
}

func (o *OIDC) chave(ctx context.Context, d *descoberta, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	k, ok := o.chaves[kid]
	// Kid desconhecido rele o JWKS, mas no maximo uma vez por minuto: token
	// forjado com kid aleatorio nao vira martelo no provedor.
	if !ok && o.cfg.Agora().Sub(o.lidoJWKS) > time.Minute {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
		if err != nil {
			return nil, err
		}
		var j jwks
		if err := lerJSON(o.cfg.Cliente, req, &j); err != nil {
			return nil, fmt.Errorf("provedor %s: jwks: %w", o.cfg.Nome, err)
		}
		o.chaves = map[string]chaveJWK{}
		for _, c := range j.Keys {
			if c.Use == "" || c.Use == "sig" {
				o.chaves[c.Kid] = c
			}
		}
		o.lidoJWKS = o.cfg.Agora()
		k, ok = o.chaves[kid]
	}
	if !ok {
		return nil, fmt.Errorf("%w: chave %q fora do jwks", katraca.ErrRecusado, kid)
	}
	return k.publica()
}

func (o *OIDC) config(d *descoberta) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.cfg.ClienteID,
		ClientSecret: o.cfg.Segredo,
		RedirectURL:  o.cfg.Retorno,
		Scopes:       o.cfg.Escopos,
		Endpoint:     oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint},
	}
}

func (o *OIDC) Iniciar(ctx context.Context) (string, Pendente, error) {
	d, err := o.descobrir(ctx)
	if err != nil {
		return "", Pendente{}, err
	}
	pend := Pendente{Provedor: o.cfg.Nome, Estado: aleatorio(), Nonce: aleatorio(), Criado: o.cfg.Agora()}
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", pend.Nonce)}
	if !o.cfg.SemPKCE {
		pend.Verificador = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pend.Verificador))
	}
	if o.cfg.ModoDeResposta != "" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", o.cfg.ModoDeResposta))
	}
	for k, v := range o.cfg.ParametrosExtra {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return o.config(d).AuthCodeURL(pend.Estado, opts...), pend, nil
}

func (o *OIDC) Concluir(ctx context.Context, pend Pendente, resposta url.Values) (katraca.Identidade, error) {
	agora := o.cfg.Agora()
	code, err := conferirVolta(o.cfg.Nome, pend, resposta, agora)
	if err != nil {
		return katraca.Identidade{}, err
	}
	d, err := o.descobrir(ctx)
	if err != nil {
		return katraca.Identidade{}, err
	}
	cfg := o.config(d)
	if o.cfg.SegredoDinamico != nil {
		if cfg.ClientSecret, err = o.cfg.SegredoDinamico(ctx); err != nil {
			return katraca.Identidade{}, fmt.Errorf("provedor %s: segredo: %w", o.cfg.Nome, err)
		}
	}
	var opts []oauth2.AuthCodeOption
	if pend.Verificador != "" {
		opts = append(opts, oauth2.VerifierOption(pend.Verificador))
	}
	tok, err := cfg.Exchange(comCliente(ctx, o.cfg.Cliente), code, opts...)
	if err != nil {
		return katraca.Identidade{}, fmt.Errorf("%w: troca do code: %v", katraca.ErrRecusado, err)
	}
	bruto, _ := tok.Extra("id_token").(string)
	if bruto == "" {
		return katraca.Identidade{}, fmt.Errorf("%w: resposta sem id_token", katraca.ErrRecusado)
	}
	r, err := o.conferirIDToken(ctx, d, bruto, pend.Nonce, agora)
	if err != nil {
		return katraca.Identidade{}, err
	}

	// O userinfo completa o que o id_token nao trouxe (o Google as vezes
	// manda so o sub e o e-mail). O sub tem de ser o mesmo.
	if d.UserinfoEndpoint != "" && (r.Texto("email") == "" || r.Texto("name") == "") {
		var u Reivindicacoes
		api := &API{Cliente: o.cfg.Cliente, Token: tok}
		if err := api.JSON(ctx, d.UserinfoEndpoint, &u); err == nil && u.Texto("sub") == r.Texto("sub") {
			for k, v := range u {
				if _, ja := r[k]; !ja {
					r[k] = v
				}
			}
		}
	}

	id := katraca.Identidade{
		Provedor: o.cfg.Nome,
		ID:       r.Texto("sub"),
		Nome:     r.Texto("name"),
		Foto:     r.Texto("picture"),
	}
	if e, err := katraca.NormalizarEmail(r.Texto("email")); err == nil {
		id.Email = e
		id.EmailGarantido = r.Verdade("email_verified")
	}
	if o.cfg.Traduzir != nil {
		if err := o.cfg.Traduzir(r, resposta, &id); err != nil {
			return katraca.Identidade{}, err
		}
	}
	if id.ID == "" {
		return katraca.Identidade{}, fmt.Errorf("%w: id_token sem sub", katraca.ErrRecusado)
	}
	if id.Email == "" {
		id.EmailGarantido = false
	}
	return id, nil
}

// conferirIDToken confere assinatura, emissor, audiencia, prazo e nonce.
func (o *OIDC) conferirIDToken(ctx context.Context, d *descoberta, bruto, nonce string, agora time.Time) (Reivindicacoes, error) {
	recusa := func(motivo string) error { return fmt.Errorf("%w: id_token %s", katraca.ErrRecusado, motivo) }
	cab, corpo, ass, assinado, err := partirJWT(bruto)
	if err != nil {
		return nil, recusa(err.Error())
	}
	chave, err := o.chave(ctx, d, cab.Kid)
	if err != nil {
		return nil, err
	}
	if err := conferirAssinatura(cab.Alg, chave, assinado, ass); err != nil {
		return nil, recusa(err.Error())
	}
	var r Reivindicacoes
	dec := json.NewDecoder(strings.NewReader(string(corpo)))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return nil, recusa("ilegivel")
	}

	iss := r.Texto("iss")
	if o.cfg.ConferirEmissor != nil {
		if !o.cfg.ConferirEmissor(iss) {
			return nil, recusa("de outro emissor")
		}
	} else if strings.TrimRight(iss, "/") != strings.TrimRight(d.Issuer, "/") {
		return nil, recusa("de outro emissor")
	}

	var auds []string
	switch a := r["aud"].(type) {
	case string:
		auds = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	minha := false
	for _, a := range auds {
		minha = minha || a == o.cfg.ClienteID
	}
	if !minha {
		return nil, recusa("para outro cliente")
	}
	if len(auds) > 1 {
		if azp := r.Texto("azp"); azp != "" && azp != o.cfg.ClienteID {
			return nil, recusa("com azp de outro cliente")
		}
	}

	// Um minuto de folga para relogios desencontrados.
	folga := time.Minute
	exp, ok := numero(r["exp"])
	if !ok || agora.After(time.Unix(exp, 0).Add(folga)) {
		return nil, recusa("vencido")
	}
	if iat, ok := numero(r["iat"]); ok && time.Unix(iat, 0).After(agora.Add(folga)) {
		return nil, recusa("emitido no futuro")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(r.Texto("nonce")), []byte(nonce)) != 1 {
		return nil, recusa("com nonce que nao confere")
	}
	return r, nil
}

func numero(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, err := n.Float64()
			return int64(f), err == nil
		}
		return i, true
	case float64:
		return int64(n), true
	}
	return 0, false
}
