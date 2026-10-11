package provider_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOIDC is a whole OIDC provider in an httptest server: discovery, JWKS,
// token (with real PKCE) and userinfo. It signs with RS256 or ES256.
type fakeOIDC struct {
	*httptest.Server
	t            *testing.T
	clientID     string
	clientSecret string
	rsa          *rsa.PrivateKey
	ec           *ecdsa.PrivateKey
	alg          string // "RS256" or "ES256"
	// Impostor, if set, signs instead of the key published in the JWKS.
	Impostor *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]fakeGrant
	// Claims tweaks the claims of the next id_token.
	Claims func(c map[string]any)
	// Userinfo is what /userinfo answers, for tests that force the userinfo.
	Userinfo map[string]any
	// Seen keeps the last request to /token, for the test to check.
	Seen url.Values
}

type fakeGrant struct {
	challenge, method, nonce, sub string
}

func newFakeOIDC(t *testing.T, alg string) *fakeOIDC {
	f := &fakeOIDC{t: t, clientID: "test-client", clientSecret: "test-secret", alg: alg, codes: map[string]fakeGrant{}}
	f.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/authorize",
			"token_endpoint":         f.URL + "/token",
			"userinfo_endpoint":      f.URL + "/userinfo",
			"jwks_uri":               f.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b := base64.RawURLEncoding
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "r1", "use": "sig", "alg": "RS256",
				"n": b.EncodeToString(f.rsa.N.Bytes()), "e": b.EncodeToString(big.NewInt(int64(f.rsa.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "use": "sig", "alg": "ES256", "crv": "P-256",
				"x": b.EncodeToString(f.ec.X.FillBytes(make([]byte, 32))), "y": b.EncodeToString(f.ec.Y.FillBytes(make([]byte, 32)))},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		f.Seen = r.PostForm
		p, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		id, sec, hasBasic := r.BasicAuth()
		if !hasBasic {
			id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id, _ = url.QueryUnescape(id); sec != "" {
			sec, _ = url.QueryUnescape(sec)
		}
		fail := func(e string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": e})
		}
		if !ok || r.PostForm.Get("grant_type") != "authorization_code" {
			fail("invalid_grant")
			return
		}
		if id != f.clientID || sec != f.clientSecret {
			fail("invalid_client")
			return
		}
		if p.challenge != "" {
			v := r.PostForm.Get("code_verifier")
			h := sha256.Sum256([]byte(v))
			if p.method != "S256" || base64.RawURLEncoding.EncodeToString(h[:]) != p.challenge {
				fail("invalid_grant")
				return
			}
		}
		claims := map[string]any{
			"iss": f.URL, "aud": f.clientID, "sub": p.sub,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": p.nonce, "email": "Ana@Example.com", "email_verified": true,
			"name": "Ana", "picture": "https://example.com/ana.png",
		}
		if f.Claims != nil {
			f.Claims(claims)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + p.sub, "token_type": "Bearer", "expires_in": 3600,
			"id_token": f.sign(claims),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer token-") {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(f.Userinfo)
	})
	return f
}

func (f *fakeOIDC) sign(claims map[string]any) string {
	b := base64.RawURLEncoding
	kid := "r1"
	if f.alg == "ES256" {
		kid = "e1"
	}
	head, _ := json.Marshal(map[string]string{"alg": f.alg, "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signed := b.EncodeToString(head) + "." + b.EncodeToString(body)
	h := sha256.Sum256([]byte(signed))
	var sig []byte
	if f.alg == "ES256" {
		r, s, _ := ecdsa.Sign(rand.Reader, f.ec, h[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	} else {
		k := f.rsa
		if f.Impostor != nil {
			k = f.Impostor
		}
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	}
	return signed + "." + b.EncodeToString(sig)
}

// authorize plays the person at the provider: it reads the URL Begin
// returned, "consents" and returns the callback parameters.
func (f *fakeOIDC) authorize(t *testing.T, authURL, sub string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != f.clientID || q.Get("response_type") != "code" {
		t.Fatalf("wrong authorization URL: %s", authURL)
	}
	code := "code-" + sub + "-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = fakeGrant{challenge: q.Get("code_challenge"), method: q.Get("code_challenge_method"), nonce: q.Get("nonce"), sub: sub}
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}
