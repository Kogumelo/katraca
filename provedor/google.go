package provedor

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/Kogumelo/kracha"
)

// Google configura o login pelo Google.
type Google struct {
	ClienteID string
	Segredo   string
	Retorno   string
	// Emissor troca accounts.google.com (teste). Vazio vale o publico.
	Emissor string
	// Dominio restringe a um Google Workspace ("hd"). Vazio aceita todos.
	Dominio string
	Cliente *http.Client
}

// NovoGoogle monta o Google como um OIDC qualquer. Sem access_type=offline:
// o login nao precisa de refresh token, e pedir um so faz o Google guardar
// uma permissao que ninguem usa.
//
// EmailGarantido e o email_verified do id_token. Conta Google com e-mail de
// fora (um Gmail nao, mas um "ana@empresa.com" cadastrado no Google) pode
// vir com ele falso.
func NovoGoogle(c Google) (*OIDC, error) {
	emissor := c.Emissor
	if emissor == "" {
		emissor = "https://accounts.google.com"
	}
	cfg := OIDCConfig{
		Nome:      "google",
		Emissor:   emissor,
		ClienteID: c.ClienteID,
		Segredo:   c.Segredo,
		Retorno:   c.Retorno,
		Cliente:   c.Cliente,
		// O Google as vezes emite o iss sem o https.
		ConferirEmissor: func(iss string) bool {
			return iss == emissor || "https://"+iss == emissor
		},
	}
	if c.Dominio != "" {
		cfg.ParametrosExtra = map[string]string{"hd": c.Dominio}
		// O "hd" na URL e so sugestao; quem garante e a claim.
		cfg.Traduzir = func(r Reivindicacoes, _ url.Values, _ *kracha.Identidade) error {
			if r.Texto("hd") != c.Dominio {
				return fmt.Errorf("%w: conta de fora do dominio %s", kracha.ErrRecusado, c.Dominio)
			}
			return nil
		}
	}
	return NovoOIDC(cfg)
}
