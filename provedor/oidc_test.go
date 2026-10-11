package provedor_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/Kogumelo/acesso"
	"github.com/Kogumelo/acesso/provedor"
)

// Um provedor que a biblioteca nunca viu entra so por configuracao: e assim
// que Microsoft, Keycloak ou gov.br entrariam.
func TestOIDCGenericoSoPorConfiguracao(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	p, err := provedor.NovoOIDC(provedor.OIDCConfig{
		Nome:      "microsoft",
		Emissor:   f.URL,
		ClienteID: f.clienteID,
		Segredo:   f.segredo,
		Retorno:   "https://app.exemplo/volta/microsoft",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	endereco, pend, err := p.Iniciar(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Concluir(ctx, pend, f.autorizar(t, endereco, "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Provedor != "microsoft" || id.ID != "abc" || !id.EmailGarantido {
		t.Fatalf("identidade: %+v", id)
	}
}

func TestOIDCDescobertaDeOutroEmissor(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	p, _ := provedor.NovoOIDC(provedor.OIDCConfig{
		Nome: "x", Emissor: f.URL + "/outro", ClienteID: "c", Retorno: "https://a/v",
	})
	if _, _, err := p.Iniciar(context.Background()); err == nil {
		t.Fatal("descoberta com issuer diferente do configurado devia falhar")
	}
}

// O desenho comporta a Apple sem mexer no nucleo: segredo de cliente gerado
// a cada troca (la, um JWT ES256), form_post, id_token em ES256, nome so no
// parametro "user" da primeira volta, email_verified como texto e o e-mail
// de retransmissao privada.
func TestOIDCComoAApple(t *testing.T) {
	f := novoOIDCFalso(t, "ES256")
	f.segredo = "jwt-es256-gerado-agora"
	f.Claims = func(c map[string]any) {
		delete(c, "name")
		delete(c, "picture")
		c["email"] = "xyz123@privaterelay.appleid.com"
		c["email_verified"] = "true"
		c["is_private_email"] = "true"
	}
	gerados := 0
	p, err := provedor.NovoOIDC(provedor.OIDCConfig{
		Nome:      "apple",
		Emissor:   f.URL,
		ClienteID: f.clienteID,
		SegredoDinamico: func(context.Context) (string, error) {
			gerados++
			return "jwt-es256-gerado-agora", nil
		},
		Retorno:        "https://app.exemplo/volta/apple",
		Escopos:        []string{"openid", "name", "email"},
		ModoDeResposta: "form_post",
		Traduzir: func(r provedor.Reivindicacoes, volta url.Values, id *acesso.Identidade) error {
			if r.Verdade("is_private_email") {
				id.Extra = map[string]string{"email_privado": "sim"}
			}
			var u struct {
				Name struct{ FirstName, LastName string } `json:"name"`
			}
			if s := volta.Get("user"); s != "" && json.Unmarshal([]byte(s), &u) == nil {
				id.Nome = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	endereco, pend, _ := p.Iniciar(ctx)
	if q, _ := url.Parse(endereco); q.Query().Get("response_mode") != "form_post" {
		t.Fatalf("sem response_mode: %s", endereco)
	}
	volta := f.autorizar(t, endereco, "000123.abc")
	volta.Set("user", `{"name":{"firstName":"Ana","lastName":"Lima"},"email":"xyz123@privaterelay.appleid.com"}`)
	id, err := p.Concluir(ctx, pend, volta)
	if err != nil {
		t.Fatal(err)
	}
	if gerados != 1 {
		t.Fatalf("segredo gerado %d vezes", gerados)
	}
	if id.ID != "000123.abc" || id.Nome != "Ana Lima" || !id.EmailGarantido ||
		id.Email != "xyz123@privaterelay.appleid.com" || id.Extra["email_privado"] != "sim" {
		t.Fatalf("identidade: %+v", id)
	}

	// Segundo login: a Apple nao manda mais o "user"; o nome vem vazio, e o
	// app fica com o que guardou da primeira vez.
	endereco, pend, _ = p.Iniciar(ctx)
	id, err = p.Concluir(ctx, pend, f.autorizar(t, endereco, "000123.abc"))
	if err != nil || id.Nome != "" {
		t.Fatalf("segundo login: %+v, %v", id, err)
	}
}

func TestOIDCTraduzirPodeRecusar(t *testing.T) {
	f := novoOIDCFalso(t, "RS256")
	p, _ := provedor.NovoGoogle(provedor.Google{
		ClienteID: f.clienteID, Segredo: f.segredo, Retorno: "https://a/v", Emissor: f.URL, Dominio: "empresa.com",
	})
	ctx := context.Background()
	endereco, pend, _ := p.Iniciar(ctx)
	if q, _ := url.Parse(endereco); q.Query().Get("hd") != "empresa.com" {
		t.Fatalf("sem hd: %s", endereco)
	}
	if _, err := p.Concluir(ctx, pend, f.autorizar(t, endereco, "1")); !errors.Is(err, acesso.ErrRecusado) {
		t.Fatalf("conta de fora do dominio: quero ErrRecusado, veio %v", err)
	}
	f.Claims = func(c map[string]any) { c["hd"] = "empresa.com" }
	endereco, pend, _ = p.Iniciar(ctx)
	if _, err := p.Concluir(ctx, pend, f.autorizar(t, endereco, "1")); err != nil {
		t.Fatalf("conta do dominio: %v", err)
	}
}
