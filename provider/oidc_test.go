package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/provider"
)

// A provider the library has never seen comes in by configuration alone:
// that is how Microsoft, Keycloak or gov.br would come in.
func TestOIDCGenericByConfigurationOnly(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	p, err := provider.NewOIDC(provider.OIDCConfig{
		Name:         "microsoft",
		Issuer:       f.URL,
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
		RedirectURL:  "https://app.example/callback/microsoft",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	authURL, pend, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Complete(ctx, pend, f.authorize(t, authURL, "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "microsoft" || id.ID != "abc" || !id.EmailVerified {
		t.Fatalf("identity: %+v", id)
	}
}

func TestOIDCDiscoveryFromAnotherIssuer(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	p, _ := provider.NewOIDC(provider.OIDCConfig{
		Name: "x", Issuer: f.URL + "/other", ClientID: "c", RedirectURL: "https://a/v",
	})
	if _, _, err := p.Begin(context.Background()); err == nil {
		t.Fatal("discovery with an issuer different from the configured one should fail")
	}
}

// The design fits Apple without touching the core: a client secret generated
// on every exchange (there, an ES256 JWT), form_post, id_token in ES256, name
// only in the "user" parameter of the first callback, email_verified as a
// string and the private relay email.
func TestOIDCLikeApple(t *testing.T) {
	f := newFakeOIDC(t, "ES256")
	f.clientSecret = "es256-jwt-generated-now"
	f.Claims = func(c map[string]any) {
		delete(c, "name")
		delete(c, "picture")
		c["email"] = "xyz123@privaterelay.appleid.com"
		c["email_verified"] = "true"
		c["is_private_email"] = "true"
	}
	generated := 0
	p, err := provider.NewOIDC(provider.OIDCConfig{
		Name:     "apple",
		Issuer:   f.URL,
		ClientID: f.clientID,
		ClientSecretFunc: func(context.Context) (string, error) {
			generated++
			return "es256-jwt-generated-now", nil
		},
		RedirectURL:  "https://app.example/callback/apple",
		Scopes:       []string{"openid", "name", "email"},
		ResponseMode: "form_post",
		Customize: func(c provider.Claims, response url.Values, id *katraca.Identity) error {
			if c.Bool("is_private_email") {
				id.Extra = map[string]string{"private_email": "yes"}
			}
			var u struct {
				Name struct{ FirstName, LastName string } `json:"name"`
			}
			if s := response.Get("user"); s != "" && json.Unmarshal([]byte(s), &u) == nil {
				id.Name = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	authURL, pend, _ := p.Begin(ctx)
	if q, _ := url.Parse(authURL); q.Query().Get("response_mode") != "form_post" {
		t.Fatalf("no response_mode: %s", authURL)
	}
	callback := f.authorize(t, authURL, "000123.abc")
	callback.Set("user", `{"name":{"firstName":"Ana","lastName":"Lima"},"email":"xyz123@privaterelay.appleid.com"}`)
	id, err := p.Complete(ctx, pend, callback)
	if err != nil {
		t.Fatal(err)
	}
	if generated != 1 {
		t.Fatalf("secret generated %d times", generated)
	}
	if id.ID != "000123.abc" || id.Name != "Ana Lima" || !id.EmailVerified ||
		id.Email != "xyz123@privaterelay.appleid.com" || id.Extra["private_email"] != "yes" {
		t.Fatalf("identity: %+v", id)
	}

	// Second sign-in: Apple no longer sends "user"; the name comes empty,
	// and the app keeps what it stored the first time.
	authURL, pend, _ = p.Begin(ctx)
	id, err = p.Complete(ctx, pend, f.authorize(t, authURL, "000123.abc"))
	if err != nil || id.Name != "" {
		t.Fatalf("second sign-in: %+v, %v", id, err)
	}
}

func TestOIDCCustomizeCanReject(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	p, _ := provider.NewGoogle(provider.Google{
		ClientID: f.clientID, ClientSecret: f.clientSecret, RedirectURL: "https://a/v", Issuer: f.URL, HostedDomain: "company.com",
	})
	ctx := context.Background()
	authURL, pend, _ := p.Begin(ctx)
	if q, _ := url.Parse(authURL); q.Query().Get("hd") != "company.com" {
		t.Fatalf("no hd: %s", authURL)
	}
	if _, err := p.Complete(ctx, pend, f.authorize(t, authURL, "1")); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("account outside the domain: want ErrRejected, got %v", err)
	}
	f.Claims = func(c map[string]any) { c["hd"] = "company.com" }
	authURL, pend, _ = p.Begin(ctx)
	if _, err := p.Complete(ctx, pend, f.authorize(t, authURL, "1")); err != nil {
		t.Fatalf("account in the domain: %v", err)
	}
}
