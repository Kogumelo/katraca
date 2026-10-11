package provider

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

// OIDCConfig describes an OpenID Connect provider. For most of them (Google,
// Microsoft, Keycloak, gov.br), adding the provider is just filling this in:
// the rest comes from the discovery document
// (Issuer + "/.well-known/openid-configuration").
type OIDCConfig struct {
	Name         string // goes in Identity.Provider
	Issuer       string // "https://accounts.google.com"
	ClientID     string
	ClientSecret string
	// ClientSecretFunc, if set, replaces ClientSecret on every code
	// exchange. Apple wants an ES256-signed JWT that expires; this is where
	// it is generated.
	ClientSecretFunc func(ctx context.Context) (string, error)
	RedirectURL      string   // callback URL, registered with the provider
	Scopes           []string // empty means openid, email, profile
	// ResponseMode goes as response_mode ("form_post" for Apple, which sends
	// the callback by POST when it asks for name or email).
	ResponseMode string
	// ExtraParams go in the authorization URL ("prompt", "hd"...).
	ExtraParams map[string]string
	// DisablePKCE turns PKCE off, for a provider that rejects it.
	DisablePKCE bool
	// AcceptIssuer accepts an iss different from Issuer. Multi-tenant
	// Microsoft, for example, issues with the person's tenant in the iss.
	// Nil: the iss has to match the one in the discovery document.
	AcceptIssuer func(iss string) bool
	// Customize adjusts the Identity after the standard reading (sub, email,
	// email_verified, name, picture), with the id_token claims and the
	// callback parameters. Apple, for example, sends the name only on the
	// first sign-in, in the "user" parameter of the form_post.
	Customize func(c Claims, response url.Values, id *katraca.Identity) error
	Client    *http.Client // nil means DefaultClient
	Now       func() time.Time
}

// Claims are the id_token claims, decoded as they came.
type Claims map[string]any

// String returns the claim as a string ("" if it is not a string).
func (c Claims) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Bool reads a boolean claim that some providers (Apple) send as the string
// "true".
func (c Claims) Bool(name string) bool {
	switch v := c[name].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// OIDC is the assembled provider. The discovery document and the JWKS are
// read on first use and kept; the JWKS is read again when an unknown kid
// shows up (the provider rotated its key).
type OIDC struct {
	cfg OIDCConfig

	mu          sync.Mutex
	doc         *discovery
	keys        map[string]jwk
	jwksFetched time.Time
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewOIDC builds the provider without going to the network: discovery waits
// for the first Begin, and a provider that is down does not keep the app
// from starting.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	if cfg.Name == "" || cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("provider OIDC: Name, Issuer, ClientID and RedirectURL are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OIDC{cfg: cfg}, nil
}

func (o *OIDC) Name() string { return o.cfg.Name }

func (o *OIDC) discover(ctx context.Context) (*discovery, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.doc != nil {
		return o.doc, nil
	}
	endpoint := strings.TrimRight(o.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	var d discovery
	if err := readJSON(o.cfg.Client, req, &d); err != nil {
		return nil, fmt.Errorf("provider %s: discovery: %w", o.cfg.Name, err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("provider %s: incomplete discovery document", o.cfg.Name)
	}
	// The document says who the issuer is; it has to be the one we configured.
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(o.cfg.Issuer, "/") {
		return nil, fmt.Errorf("provider %s: discovery reports issuer %q", o.cfg.Name, d.Issuer)
	}
	o.doc = &d
	return o.doc, nil
}

func (o *OIDC) key(ctx context.Context, d *discovery, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	k, ok := o.keys[kid]
	// An unknown kid refetches the JWKS, but at most once a minute: a forged
	// token with a random kid does not become a hammer on the provider.
	if !ok && o.cfg.Now().Sub(o.jwksFetched) > time.Minute {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
		if err != nil {
			return nil, err
		}
		var j jwks
		if err := readJSON(o.cfg.Client, req, &j); err != nil {
			return nil, fmt.Errorf("provider %s: jwks: %w", o.cfg.Name, err)
		}
		o.keys = map[string]jwk{}
		for _, c := range j.Keys {
			if c.Use == "" || c.Use == "sig" {
				o.keys[c.Kid] = c
			}
		}
		o.jwksFetched = o.cfg.Now()
		k, ok = o.keys[kid]
	}
	if !ok {
		return nil, fmt.Errorf("%w: key %q not in jwks", katraca.ErrRejected, kid)
	}
	return k.public()
}

func (o *OIDC) config(d *discovery) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		RedirectURL:  o.cfg.RedirectURL,
		Scopes:       o.cfg.Scopes,
		Endpoint:     oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint},
	}
}

func (o *OIDC) Begin(ctx context.Context) (string, Pending, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return "", Pending{}, err
	}
	pend := Pending{Provider: o.cfg.Name, State: random(), Nonce: random(), Created: o.cfg.Now()}
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", pend.Nonce)}
	if !o.cfg.DisablePKCE {
		pend.Verifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pend.Verifier))
	}
	if o.cfg.ResponseMode != "" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", o.cfg.ResponseMode))
	}
	for k, v := range o.cfg.ExtraParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return o.config(d).AuthCodeURL(pend.State, opts...), pend, nil
}

func (o *OIDC) Complete(ctx context.Context, pend Pending, response url.Values) (katraca.Identity, error) {
	now := o.cfg.Now()
	code, err := checkCallback(o.cfg.Name, pend, response, now)
	if err != nil {
		return katraca.Identity{}, err
	}
	d, err := o.discover(ctx)
	if err != nil {
		return katraca.Identity{}, err
	}
	cfg := o.config(d)
	if o.cfg.ClientSecretFunc != nil {
		if cfg.ClientSecret, err = o.cfg.ClientSecretFunc(ctx); err != nil {
			return katraca.Identity{}, fmt.Errorf("provider %s: client secret: %w", o.cfg.Name, err)
		}
	}
	var opts []oauth2.AuthCodeOption
	if pend.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(pend.Verifier))
	}
	tok, err := cfg.Exchange(withClient(ctx, o.cfg.Client), code, opts...)
	if err != nil {
		return katraca.Identity{}, fmt.Errorf("%w: code exchange: %v", katraca.ErrRejected, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return katraca.Identity{}, fmt.Errorf("%w: response without id_token", katraca.ErrRejected)
	}
	c, err := o.verifyIDToken(ctx, d, raw, pend.Nonce, now)
	if err != nil {
		return katraca.Identity{}, err
	}

	// The userinfo fills in what the id_token did not bring (Google sometimes
	// sends only the sub and the email). The sub has to be the same. Email
	// and email_verified go together: the userinfo's email_verified speaks
	// about the userinfo's email, and does not vouch for the id_token's.
	if d.UserinfoEndpoint != "" && (c.String("email") == "" || c.String("name") == "") {
		var u Claims
		api := &API{Client: o.cfg.Client, Token: tok}
		if err := api.JSON(ctx, d.UserinfoEndpoint, &u); err == nil && u.String("sub") == c.String("sub") {
			_, hasEmail := c["email"]
			for k, v := range u {
				if k == "email_verified" && hasEmail {
					continue
				}
				if _, present := c[k]; !present {
					c[k] = v
				}
			}
		}
	}

	id := katraca.Identity{
		Provider: o.cfg.Name,
		ID:       c.String("sub"),
		Name:     c.String("name"),
		Picture:  c.String("picture"),
	}
	if e, err := katraca.NormalizeEmail(c.String("email")); err == nil {
		id.Email = e
		id.EmailVerified = c.Bool("email_verified")
	}
	if o.cfg.Customize != nil {
		if err := o.cfg.Customize(c, response, &id); err != nil {
			return katraca.Identity{}, err
		}
	}
	if id.ID == "" {
		return katraca.Identity{}, fmt.Errorf("%w: id_token without sub", katraca.ErrRejected)
	}
	if id.Email == "" {
		id.EmailVerified = false
	}
	return id, nil
}

// verifyIDToken checks signature, issuer, audience, expiry and nonce.
func (o *OIDC) verifyIDToken(ctx context.Context, d *discovery, raw, nonce string, now time.Time) (Claims, error) {
	reject := func(reason string) error { return fmt.Errorf("%w: id_token %s", katraca.ErrRejected, reason) }
	head, body, sig, signed, err := splitJWT(raw)
	if err != nil {
		return nil, reject(err.Error())
	}
	key, err := o.key(ctx, d, head.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(head.Alg, key, signed, sig); err != nil {
		return nil, reject(err.Error())
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return nil, reject("unreadable")
	}

	iss := c.String("iss")
	if o.cfg.AcceptIssuer != nil {
		if !o.cfg.AcceptIssuer(iss) {
			return nil, reject("from another issuer")
		}
	} else if strings.TrimRight(iss, "/") != strings.TrimRight(d.Issuer, "/") {
		return nil, reject("from another issuer")
	}

	var auds []string
	switch a := c["aud"].(type) {
	case string:
		auds = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	mine := false
	for _, a := range auds {
		mine = mine || a == o.cfg.ClientID
	}
	if !mine {
		return nil, reject("for another client")
	}
	if len(auds) > 1 {
		if azp := c.String("azp"); azp != "" && azp != o.cfg.ClientID {
			return nil, reject("with azp of another client")
		}
	}

	// One minute of leeway for clocks that disagree.
	leeway := time.Minute
	exp, ok := number(c["exp"])
	if !ok || now.After(time.Unix(exp, 0).Add(leeway)) {
		return nil, reject("expired")
	}
	if iat, ok := number(c["iat"]); ok && time.Unix(iat, 0).After(now.Add(leeway)) {
		return nil, reject("issued in the future")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(c.String("nonce")), []byte(nonce)) != 1 {
		return nil, reject("with mismatched nonce")
	}
	return c, nil
}

func number(v any) (int64, bool) {
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
