package provedor_test

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

// oidcFalso e um provedor OIDC inteiro num httptest: descoberta, JWKS,
// token (com PKCE de verdade) e userinfo. Assina em RS256 ou ES256.
type oidcFalso struct {
	*httptest.Server
	t         *testing.T
	clienteID string
	segredo   string
	rsa       *rsa.PrivateKey
	ec        *ecdsa.PrivateKey
	alg       string // "RS256" ou "ES256"
	// Impostora, se dada, assina no lugar da chave publicada no JWKS.
	Impostora *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]pedidoFalso
	// Claims mexe nas reivindicacoes do proximo id_token.
	Claims func(c map[string]any)
	// SemIDTokenEmail tira email do id_token, para forcar o userinfo.
	Userinfo map[string]any
	// Visto guarda o ultimo pedido ao /token, para o teste conferir.
	Visto url.Values
}

type pedidoFalso struct {
	desafio, metodo, nonce, sub string
}

func novoOIDCFalso(t *testing.T, alg string) *oidcFalso {
	f := &oidcFalso{t: t, clienteID: "cliente-teste", segredo: "segredo-teste", alg: alg, codes: map[string]pedidoFalso{}}
	f.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/autorizar",
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
		f.Visto = r.PostForm
		p, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		id, seg, temBasic := r.BasicAuth()
		if !temBasic {
			id, seg = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id, _ = url.QueryUnescape(id); seg != "" {
			seg, _ = url.QueryUnescape(seg)
		}
		erro := func(e string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": e})
		}
		if !ok || r.PostForm.Get("grant_type") != "authorization_code" {
			erro("invalid_grant")
			return
		}
		if id != f.clienteID || seg != f.segredo {
			erro("invalid_client")
			return
		}
		if p.desafio != "" {
			v := r.PostForm.Get("code_verifier")
			h := sha256.Sum256([]byte(v))
			if p.metodo != "S256" || base64.RawURLEncoding.EncodeToString(h[:]) != p.desafio {
				erro("invalid_grant")
				return
			}
		}
		claims := map[string]any{
			"iss": f.URL, "aud": f.clienteID, "sub": p.sub,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": p.nonce, "email": "Ana@Exemplo.com", "email_verified": true,
			"name": "Ana", "picture": "https://exemplo.com/ana.png",
		}
		if f.Claims != nil {
			f.Claims(claims)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "acesso-" + p.sub, "token_type": "Bearer", "expires_in": 3600,
			"id_token": f.assinar(claims),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer acesso-") {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(f.Userinfo)
	})
	return f
}

func (f *oidcFalso) assinar(claims map[string]any) string {
	b := base64.RawURLEncoding
	kid := "r1"
	if f.alg == "ES256" {
		kid = "e1"
	}
	cab, _ := json.Marshal(map[string]string{"alg": f.alg, "kid": kid, "typ": "JWT"})
	corpo, _ := json.Marshal(claims)
	assinado := b.EncodeToString(cab) + "." + b.EncodeToString(corpo)
	h := sha256.Sum256([]byte(assinado))
	var ass []byte
	if f.alg == "ES256" {
		r, s, _ := ecdsa.Sign(rand.Reader, f.ec, h[:])
		ass = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	} else {
		k := f.rsa
		if f.Impostora != nil {
			k = f.Impostora
		}
		ass, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	}
	return assinado + "." + b.EncodeToString(ass)
}

// autorizar faz o papel da pessoa no provedor: le o endereco que Iniciar
// devolveu, "consente" e devolve os parametros da volta.
func (f *oidcFalso) autorizar(t *testing.T, endereco, sub string) url.Values {
	t.Helper()
	u, err := url.Parse(endereco)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != f.clienteID || q.Get("response_type") != "code" {
		t.Fatalf("endereco de autorizacao errado: %s", endereco)
	}
	code := "code-" + sub + "-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = pedidoFalso{desafio: q.Get("code_challenge"), metodo: q.Get("code_challenge_method"), nonce: q.Get("nonce"), sub: sub}
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}
