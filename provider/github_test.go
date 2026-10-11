package provider_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/provider"
)

// fakeGitHub imitates github.com and api.github.com: authorization, code
// exchange with PKCE, /user and /user/emails. API calls only go through with
// the token in the header.
type fakeGitHub struct {
	*httptest.Server
	mu         sync.Mutex
	challenges map[string]string
	Emails     []map[string]any
	// Huge makes /user answer more than the limit.
	Huge bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{challenges: map[string]string{}, Emails: []map[string]any{
		{"email": "other@example.com", "primary": false, "verified": true},
		{"email": "Bia@Example.com", "primary": true, "verified": true},
	}}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		challenge, ok := f.challenges[r.PostForm.Get("code")]
		delete(f.challenges, r.PostForm.Get("code"))
		f.mu.Unlock()
		h := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		w.Header().Set("Content-Type", "application/json")
		// GitHub answers 200 with "error" in the body.
		if !ok || base64.RawURLEncoding.EncodeToString(h[:]) != challenge {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_fake", "token_type": "bearer", "scope": "read:user,user:email"})
	})
	api := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer gho_fake" || r.URL.Query().Get("access_token") != "" {
			w.WriteHeader(401)
			return false
		}
		return true
	}
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if !api(w, r) {
			return
		}
		if f.Huge {
			w.Write([]byte(`{"login":"` + strings.Repeat("a", provider.MaxResponseSize) + `"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 583231, "login": "bia", "name": "", "avatar_url": "https://avatars.example/bia"})
	})
	mux.HandleFunc("/api/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if !api(w, r) {
			return
		}
		json.NewEncoder(w).Encode(f.Emails)
	})
	return f
}

func (f *fakeGitHub) authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	u, _ := url.Parse(authURL)
	q := u.Query()
	if u.Path != "/login/oauth/authorize" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("wrong authorization URL: %s", authURL)
	}
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.challenges[code] = q.Get("code_challenge")
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}

func githubAgainst(f *fakeGitHub) *provider.OAuth2 {
	return provider.NewGitHub(provider.GitHub{
		ClientID: "gh-client", ClientSecret: "gh-secret", RedirectURL: "https://app.example/callback/github",
		BaseURL: f.URL, APIURL: f.URL + "/api",
	})
}

func TestGitHubHappyPath(t *testing.T) {
	f := newFakeGitHub(t)
	g := githubAgainst(f)
	ctx := context.Background()
	authURL, pend, err := g.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := g.Complete(ctx, pend, f.authorize(t, authURL))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "github" || id.ID != "583231" || id.Email != "bia@example.com" || !id.EmailVerified ||
		id.Name != "bia" || id.Extra["login"] != "bia" {
		t.Fatalf("identity: %+v", id)
	}
}

func TestGitHubWrongState(t *testing.T) {
	f := newFakeGitHub(t)
	g := githubAgainst(f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL)
	callback.Set("state", pend.State+"x")
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestGitHubPKCE(t *testing.T) {
	f := newFakeGitHub(t)
	g := githubAgainst(f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	callback := f.authorize(t, authURL)
	pend.Verifier = "verifier-from-another-attempt-aaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := g.Complete(ctx, pend, callback); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestGitHubEmailNotVerified(t *testing.T) {
	f := newFakeGitHub(t)
	f.Emails = []map[string]any{{"email": "bia@example.com", "primary": true, "verified": false}}
	g := githubAgainst(f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	id, err := g.Complete(ctx, pend, f.authorize(t, authURL))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "bia@example.com" || id.EmailVerified {
		t.Fatalf("the email should come flagged as not verified: %+v", id)
	}
}

func TestGitHubResponseTooLarge(t *testing.T) {
	f := newFakeGitHub(t)
	f.Huge = true
	g := githubAgainst(f)
	ctx := context.Background()
	authURL, pend, _ := g.Begin(ctx)
	_, err := g.Complete(ctx, pend, f.authorize(t, authURL))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want rejection by size, got %v", err)
	}
}

// A made-up OAuth2 adapter (as Meta would be): only the function that
// translates the API response. The core does not change.
func TestFakeOAuth2Adapter(t *testing.T) {
	f := newFakeGitHub(t) // the same authorization and token mechanics will do
	p := &provider.OAuth2{
		ProviderName: "meta",
		ClientID:     "meta-app",
		ClientSecret: "s",
		RedirectURL:  "https://app.example/callback/meta",
		Scopes:       []string{"email", "public_profile"},
		AuthURL:      f.URL + "/login/oauth/authorize",
		TokenURL:     f.URL + "/login/oauth/access_token",
		Identify: func(ctx context.Context, api *provider.API) (katraca.Identity, error) {
			var u struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
			}
			if err := api.JSON(ctx, f.URL+"/api/user", &u); err != nil {
				return katraca.Identity{}, err
			}
			// Meta does not say whether the email is verified: the adapter
			// sends it as not verified.
			return katraca.Identity{ID: "m" + u.Login, Email: u.Login + "@example.com", Name: u.Login}, nil
		},
	}
	ctx := context.Background()
	authURL, pend, _ := p.Begin(ctx)
	id, err := p.Complete(ctx, pend, f.authorize(t, authURL))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "meta" || id.ID != "mbia" || id.EmailVerified {
		t.Fatalf("identity: %+v", id)
	}
}
