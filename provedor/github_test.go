package provedor_test

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

	"github.com/Kogumelo/kracha"
	"github.com/Kogumelo/kracha/provedor"
)

// githubFalso imita github.com e api.github.com: autorizacao, troca do code
// com PKCE, /user e /user/emails. As chamadas a API so passam com o token no
// cabecalho.
type githubFalso struct {
	*httptest.Server
	mu       sync.Mutex
	desafios map[string]string
	Emails   []map[string]any
	// Enorme faz o /user responder mais que o limite.
	Enorme bool
}

func novoGitHubFalso(t *testing.T) *githubFalso {
	f := &githubFalso{desafios: map[string]string{}, Emails: []map[string]any{
		{"email": "outro@exemplo.com", "primary": false, "verified": true},
		{"email": "Bia@Exemplo.com", "primary": true, "verified": true},
	}}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		desafio, ok := f.desafios[r.PostForm.Get("code")]
		delete(f.desafios, r.PostForm.Get("code"))
		f.mu.Unlock()
		h := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		w.Header().Set("Content-Type", "application/json")
		// O GitHub responde 200 com "error" no corpo.
		if !ok || base64.RawURLEncoding.EncodeToString(h[:]) != desafio {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_falso", "token_type": "bearer", "scope": "read:user,user:email"})
	})
	api := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer gho_falso" || r.URL.Query().Get("access_token") != "" {
			w.WriteHeader(401)
			return false
		}
		return true
	}
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if !api(w, r) {
			return
		}
		if f.Enorme {
			w.Write([]byte(`{"login":"` + strings.Repeat("a", provedor.LimiteDaResposta) + `"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 583231, "login": "bia", "name": "", "avatar_url": "https://avatars.exemplo/bia"})
	})
	mux.HandleFunc("/api/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if !api(w, r) {
			return
		}
		json.NewEncoder(w).Encode(f.Emails)
	})
	return f
}

func (f *githubFalso) autorizar(t *testing.T, endereco string) url.Values {
	t.Helper()
	u, _ := url.Parse(endereco)
	q := u.Query()
	if u.Path != "/login/oauth/authorize" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("endereco de autorizacao errado: %s", endereco)
	}
	code := "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.desafios[code] = q.Get("code_challenge")
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}

func githubContra(f *githubFalso) *provedor.OAuth2 {
	return provedor.NovoGitHub(provedor.GitHub{
		ClienteID: "cliente-gh", Segredo: "segredo-gh", Retorno: "https://app.exemplo/volta/github",
		Site: f.URL, API: f.URL + "/api",
	})
}

func TestGitHubCaminhoFeliz(t *testing.T) {
	f := novoGitHubFalso(t)
	g := githubContra(f)
	ctx := context.Background()
	endereco, pend, err := g.Iniciar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := g.Concluir(ctx, pend, f.autorizar(t, endereco))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provedor != "github" || id.ID != "583231" || id.Email != "bia@exemplo.com" || !id.EmailGarantido ||
		id.Nome != "bia" || id.Extra["login"] != "bia" {
		t.Fatalf("identidade: %+v", id)
	}
}

func TestGitHubStateErrado(t *testing.T) {
	f := novoGitHubFalso(t)
	g := githubContra(f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco)
	volta.Set("state", pend.Estado+"x")
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, kracha.ErrRecusado) {
		t.Fatalf("quero ErrRecusado, veio %v", err)
	}
}

func TestGitHubPKCE(t *testing.T) {
	f := novoGitHubFalso(t)
	g := githubContra(f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco)
	pend.Verificador = "verificador-de-outra-ida-aaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, kracha.ErrRecusado) {
		t.Fatalf("quero ErrRecusado, veio %v", err)
	}
}

func TestGitHubEmailNaoVerificado(t *testing.T) {
	f := novoGitHubFalso(t)
	f.Emails = []map[string]any{{"email": "bia@exemplo.com", "primary": true, "verified": false}}
	g := githubContra(f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	id, err := g.Concluir(ctx, pend, f.autorizar(t, endereco))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "bia@exemplo.com" || id.EmailGarantido {
		t.Fatalf("o e-mail devia vir sinalizado como nao garantido: %+v", id)
	}
}

func TestGitHubRespostaGrandeDemais(t *testing.T) {
	f := novoGitHubFalso(t)
	f.Enorme = true
	g := githubContra(f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	_, err := g.Concluir(ctx, pend, f.autorizar(t, endereco))
	if err == nil || !strings.Contains(err.Error(), "passa de") {
		t.Fatalf("quero recusa pelo tamanho, veio %v", err)
	}
}

// Um adaptador OAuth2 inventado (como seria a Meta): so a funcao que traduz
// a resposta da API. O nucleo nao muda.
func TestAdaptadorOAuth2Falso(t *testing.T) {
	f := novoGitHubFalso(t) // a mesma mecanica de autorizacao e token serve
	p := &provedor.OAuth2{
		NomeDoProvedor: "meta",
		ClienteID:      "app-meta",
		Segredo:        "s",
		Retorno:        "https://app.exemplo/volta/meta",
		Escopos:        []string{"email", "public_profile"},
		AutorizarURL:   f.URL + "/login/oauth/authorize",
		TokenURL:       f.URL + "/login/oauth/access_token",
		Traduzir: func(ctx context.Context, api *provedor.API) (kracha.Identidade, error) {
			var u struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
			}
			if err := api.JSON(ctx, f.URL+"/api/user", &u); err != nil {
				return kracha.Identidade{}, err
			}
			// A Meta nao diz se o e-mail e verificado: o adaptador o manda
			// como nao garantido.
			return kracha.Identidade{ID: "m" + u.Login, Email: u.Login + "@exemplo.com", Nome: u.Login}, nil
		},
	}
	ctx := context.Background()
	endereco, pend, _ := p.Iniciar(ctx)
	id, err := p.Concluir(ctx, pend, f.autorizar(t, endereco))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provedor != "meta" || id.ID != "mbia" || id.EmailGarantido {
		t.Fatalf("identidade: %+v", id)
	}
}
