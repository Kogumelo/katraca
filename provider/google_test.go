package provider_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/provider"
)

func googleAgainst(t *testing.T, f *fakeOIDC) *provider.OIDC {
	t.Helper()
	g, err := provider.NewGoogle(provider.Google{
		ClientID: f.clientID, ClientSecret: f.clientSecret,
		RedirectURL: "https://app.example/callback/google", Issuer: f.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGoogleHappyPath(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()

	authURL, pend, err := g.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(authURL)
	v := q.Query()
	if v.Get("code_challenge") == "" || v.Get("code_challenge_method") != "S256" {
		t.Fatalf("no PKCE S256: %s", authURL)
	}
	if v.Get("nonce") == "" || v.Get("nonce") != pend.Nonce {
		t.Fatalf("no nonce: %s", authURL)
	}
	if v.Get("access_type") != "" || v.Get("prompt") == "consent" {
		t.Fatalf("asked for a refresh token without needing one: %s", authURL)
	}
	if !strings.Contains(v.Get("scope"), "openid") || v.Get("redirect_uri") != "https://app.example/callback/google" {
		t.Fatalf("wrong scope or redirect: %s", authURL)
	}

	id, err := g.Complete(ctx, pend, f.authorize(t, authURL, "1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	want := katraca.Identity{Provider: "google", ID: "1234567890", Email: "ana@example.com",
		EmailVerified: true, Name: "Ana", Picture: "https://example.com/ana.png"}
	if id.Provider != want.Provider || id.ID != want.ID || id.Email != want.Email ||
		id.EmailVerified != want.EmailVerified || id.Name != want.Name || id.Picture != want.Picture {
		t.Fatalf("identity:\n  got %+v\n want %+v", id, want)
	}
	// The PKCE verifier went to /token.
	if f.Seen.Get("code_verifier") != pend.Verifier {
		t.Fatal("the code_verifier did not go in the exchange")
	}
}

func TestGoogleWrongStateRejected(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL, "1")
	callback.Set("state", "other")
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	// A callback without state, too.
	callback.Del("state")
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("without state: want ErrRejected, got %v", err)
	}
}

// A code stolen from another attempt does not work with my Pending: the
// state and the verifier are mine. And even with the right state, the wrong
// verifier is rejected by the provider.
func TestGooglePKCE(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL, "1")
	pend.Verifier = "a-verifier-that-did-not-generate-the-challenge-aaaaa"
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestGoogleEmailNotVerified(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	f.Claims = func(c map[string]any) { c["email_verified"] = false }
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	id, err := g.Complete(ctx, pend, f.authorize(t, authURL, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "ana@example.com" || id.EmailVerified {
		t.Fatalf("the email should come, flagged as not verified: %+v", id)
	}
}

func TestGoogleIDTokenTampered(t *testing.T) {
	cases := map[string]func(c map[string]any){
		"nonce":            func(c map[string]any) { c["nonce"] = "other" },
		"audience":         func(c map[string]any) { c["aud"] = "other-client" },
		"issuer":           func(c map[string]any) { c["iss"] = "https://malicious.example" },
		"expired":          func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"no exp":           func(c map[string]any) { delete(c, "exp") },
		"azp from another": func(c map[string]any) { c["aud"] = []any{"test-client", "other"}; c["azp"] = "other" },
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeOIDC(t, "RS256")
			f.Claims = tweak
			g := googleAgainst(t, f)
			ctx := context.Background()
			authURL, pend, _ := g.Begin(ctx)
			if _, err := g.Complete(ctx, pend, f.authorize(t, authURL, "1")); !errors.Is(err, katraca.ErrRejected) {
				t.Fatalf("want ErrRejected, got %v", err)
			}
		})
	}
}

func TestGoogleSignatureFromAnotherKey(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	other := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL, "1")
	// The fake starts signing with another provider's key, same kid; the
	// JWKS keeps publishing the real one.
	f.Impostor = other.rsa
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestPendingExpiredOrFromAnother(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL, "1")

	old := pend
	old.Created = time.Now().Add(-provider.PendingTTL - time.Second)
	if _, err := g.Complete(ctx, old, callback); !errors.Is(err, katraca.ErrExpired) {
		t.Fatalf("expired: want ErrExpired, got %v", err)
	}
	other := pend
	other.Provider = "github"
	if _, err := g.Complete(ctx, other, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("from another provider: want ErrRejected, got %v", err)
	}
}

func TestProviderRejection(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	_, pend, _ := g.Begin(ctx)
	_, err := g.Complete(ctx, pend, url.Values{"error": {"access_denied"}, "state": {pend.State}})
	var pe *provider.ProviderError
	if !errors.As(err, &pe) || pe.Code != "access_denied" || !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ProviderError access_denied, got %v", err)
	}
}

func TestUserinfoFillsIDToken(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	f.Claims = func(c map[string]any) { delete(c, "name"); delete(c, "picture") }
	f.Userinfo = map[string]any{"sub": "1", "name": "Ana from Userinfo", "picture": "p.png"}
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	id, err := g.Complete(ctx, pend, f.authorize(t, authURL, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "Ana from Userinfo" || id.Picture != "p.png" {
		t.Fatalf("userinfo did not fill in: %+v", id)
	}
	// Userinfo for another sub is ignored.
	f.Userinfo["sub"] = "2"
	authURL, pend, _ = g.Begin(ctx)
	id, _ = g.Complete(ctx, pend, f.authorize(t, authURL, "1"))
	if id.Name != "" {
		t.Fatalf("another person's userinfo got in: %+v", id)
	}
}

// The email and email_verified come from the same place. If the id_token
// brings the email without saying whether it is verified, the userinfo's
// email_verified (which speaks about another address) does not vouch for it.
func TestUserinfoDoesNotVerifyIDTokenEmail(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	f.Claims = func(c map[string]any) { delete(c, "email_verified"); delete(c, "name") }
	f.Userinfo = map[string]any{"sub": "1", "name": "Ana", "email": "other@example.com", "email_verified": true}
	g := googleAgainst(t, f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	id, err := g.Complete(ctx, pend, f.authorize(t, authURL, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "ana@example.com" || id.EmailVerified {
		t.Fatalf("id_token email verified by the userinfo: %+v", id)
	}

	// With no email in the id_token, the whole pair comes from the userinfo.
	f.Claims = func(c map[string]any) { delete(c, "email"); delete(c, "email_verified") }
	authURL, pend, _ = g.Begin(ctx)
	id, err = g.Complete(ctx, pend, f.authorize(t, authURL, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "other@example.com" || !id.EmailVerified {
		t.Fatalf("userinfo pair did not come: %+v", id)
	}
}

// The provider's error only counts with the state of the outgoing request:
// without it, anyone can send the person to the callback with text of their
// choosing in error_description.
func TestProviderRejectionWithoutState(t *testing.T) {
	f := newFakeOIDC(t, "RS256")
	g := googleAgainst(t, f)
	ctx := context.Background()
	_, pend, _ := g.Begin(ctx)
	callback := url.Values{"error": {"access_denied"}, "error_description": {"Your account was blocked, call 0800"}}
	_, err := g.Complete(ctx, pend, callback)
	var pe *provider.ProviderError
	if errors.As(err, &pe) || !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("error without state became a ProviderError: %v", err)
	}
	callback.Set("state", "other")
	if _, err := g.Complete(ctx, pend, callback); errors.As(err, &pe) {
		t.Fatalf("error with wrong state became a ProviderError: %v", err)
	}
}
