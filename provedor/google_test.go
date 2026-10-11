package provedor_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kogumelo/acesso"
	"github.com/Kogumelo/acesso/provedor"
)

func googleContra(t *testing.T, f *oidcFalso) *provedor.OIDC {
	t.Helper()
	g, err := provedor.NovoGoogle(provedor.Google{
		ClienteID: f.clienteID, Segredo: f.segredo,
		Retorno: "https://app.exemplo/volta/google", Emissor: f.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGoogleCaminhoFeliz(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()

	endereco, pend, err := g.Iniciar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(endereco)
	v := q.Query()
	if v.Get("code_challenge") == "" || v.Get("code_challenge_method") != "S256" {
		t.Fatalf("sem PKCE S256: %s", endereco)
	}
	if v.Get("nonce") == "" || v.Get("nonce") != pend.Nonce {
		t.Fatalf("sem nonce: %s", endereco)
	}
	if v.Get("access_type") != "" || v.Get("prompt") == "consent" {
		t.Fatalf("pediu refresh token sem precisar: %s", endereco)
	}
	if !strings.Contains(v.Get("scope"), "openid") || v.Get("redirect_uri") != "https://app.exemplo/volta/google" {
		t.Fatalf("escopo ou retorno errado: %s", endereco)
	}

	id, err := g.Concluir(ctx, pend, f.autorizar(t, endereco, "1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	quer := acesso.Identidade{Provedor: "google", ID: "1234567890", Email: "ana@exemplo.com",
		EmailGarantido: true, Nome: "Ana", Foto: "https://exemplo.com/ana.png"}
	if id.Provedor != quer.Provedor || id.ID != quer.ID || id.Email != quer.Email ||
		id.EmailGarantido != quer.EmailGarantido || id.Nome != quer.Nome || id.Foto != quer.Foto {
		t.Fatalf("identidade:\n veio %+v\nquero %+v", id, quer)
	}
	// O verificador PKCE foi ao /token.
	if f.Visto.Get("code_verifier") != pend.Verificador {
		t.Fatal("o code_verifier nao foi na troca")
	}
}

func TestGoogleStateErradoRecusado(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco, "1")
	volta.Set("state", "outro")
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("quero ErrRecusado, veio %v", err)
	}
	// Volta sem state, tambem.
	volta.Del("state")
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("sem state: quero ErrRecusado, veio %v", err)
	}
}

// O code roubado de outra ida nao serve com o meu Pendente: o state e o
// verificador sao meus. E mesmo com o state certo, o verificador errado e
// recusado pelo provedor.
func TestGooglePKCE(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco, "1")
	pend.Verificador = "um-verificador-que-nao-gerou-o-desafio-aaaaaaaaaaaa"
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("quero ErrRecusado, veio %v", err)
	}
}

func TestGoogleEmailNaoGarantido(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	f.Claims = func(c map[string]any) { c["email_verified"] = false }
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	id, err := g.Concluir(ctx, pend, f.autorizar(t, endereco, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "ana@exemplo.com" || id.EmailGarantido {
		t.Fatalf("o e-mail devia vir, sinalizado como nao garantido: %+v", id)
	}
}

func TestGoogleIDTokenAdulterado(t *testing.T) {
	casos := map[string]func(c map[string]any){
		"nonce":        func(c map[string]any) { c["nonce"] = "outro" },
		"audiencia":    func(c map[string]any) { c["aud"] = "outro-cliente" },
		"emissor":      func(c map[string]any) { c["iss"] = "https://malicioso.exemplo" },
		"vencido":      func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"sem exp":      func(c map[string]any) { delete(c, "exp") },
		"azp de outro": func(c map[string]any) { c["aud"] = []any{"cliente-teste", "outro"}; c["azp"] = "outro" },
	}
	for nome, mexer := range casos {
		t.Run(nome, func(t *testing.T) {
			f := novoOIDCFalso(t, "RS256")
			f.Claims = mexer
			g := googleContra(t, f)
			ctx := context.Background()
			endereco, pend, _ := g.Iniciar(ctx)
			if _, err := g.Concluir(ctx, pend, f.autorizar(t, endereco, "1")); !errors.Is(err, acesso.ErrRecusado) {
				t.Fatalf("quero ErrRecusado, veio %v", err)
			}
		})
	}
}

func TestGoogleAssinaturaDeOutraChave(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	outro := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco, "1")
	// O falso passa a assinar com a chave de outro provedor, mesmo kid; o
	// JWKS continua publicando a verdadeira.
	f.Impostora = outro.rsa
	if _, err := g.Concluir(ctx, pend, volta); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("quero ErrRecusado, veio %v", err)
	}
}

func TestPendenteVencidoOuDeOutro(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	volta := f.autorizar(t, endereco, "1")

	velho := pend
	velho.Criado = time.Now().Add(-provedor.PrazoDoInicio - time.Second)
	if _, err := g.Concluir(ctx, velho, volta); !errors.Is(err, acesso.ErrExpirado) {
		t.Fatalf("vencido: quero ErrExpirado, veio %v", err)
	}
	outro := pend
	outro.Provedor = "github"
	if _, err := g.Concluir(ctx, outro, volta); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("de outro provedor: quero ErrRecusado, veio %v", err)
	}
}

func TestRecusaDoProvedor(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	g := googleContra(t, f)
	ctx := context.Background()
	_, pend, _ := g.Iniciar(ctx)
	_, err := g.Concluir(ctx, pend, url.Values{"error": {"access_denied"}, "state": {pend.Estado}})
	var ep *provedor.ErroDoProvedor
	if !errors.As(err, &ep) || ep.Codigo != "access_denied" || !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("quero ErroDoProvedor access_denied, veio %v", err)
	}
}

func TestUserinfoCompletaOIDToken(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	f.Claims = func(c map[string]any) { delete(c, "name"); delete(c, "picture") }
	f.Userinfo = map[string]any{"sub": "1", "name": "Ana do Userinfo", "picture": "p.png"}
	g := googleContra(t, f)
	ctx := context.Background()
	endereco, pend, _ := g.Iniciar(ctx)
	id, err := g.Concluir(ctx, pend, f.autorizar(t, endereco, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Nome != "Ana do Userinfo" || id.Foto != "p.png" {
		t.Fatalf("userinfo nao completou: %+v", id)
	}
	// Userinfo de outro sub e ignorado.
	f.Userinfo["sub"] = "2"
	endereco, pend, _ = g.Iniciar(ctx)
	id, _ = g.Concluir(ctx, pend, f.autorizar(t, endereco, "1"))
	if id.Nome != "" {
		t.Fatalf("userinfo de outra pessoa entrou: %+v", id)
	}
}
