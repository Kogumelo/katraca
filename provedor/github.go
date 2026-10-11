package provedor

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kogumelo/kracha"
)

// GitHub configura o login pelo GitHub (OAuth App ou GitHub App).
type GitHub struct {
	ClienteID string
	Segredo   string
	Retorno   string
	// Site e API trocam github.com e api.github.com (GitHub Enterprise,
	// teste). Vazios valem os publicos.
	Site    string
	API     string
	Cliente *http.Client
}

// NovoGitHub monta o adaptador. Pede so read:user e user:email: o bastante
// para saber quem e e qual e-mail o GitHub ja verificou.
//
// O ID e o numero da conta, que nao muda; o login muda e vai em
// Extra["login"]. O e-mail e o principal, e EmailGarantido e o "verified"
// que o GitHub da a ele.
func NovoGitHub(c GitHub) *OAuth2 {
	site := strings.TrimRight(c.Site, "/")
	if site == "" {
		site = "https://github.com"
	}
	api := strings.TrimRight(c.API, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	return &OAuth2{
		NomeDoProvedor: "github",
		ClienteID:      c.ClienteID,
		Segredo:        c.Segredo,
		Retorno:        c.Retorno,
		Escopos:        []string{"read:user", "user:email"},
		AutorizarURL:   site + "/login/oauth/authorize",
		TokenURL:       site + "/login/oauth/access_token",
		Cliente:        c.Cliente,
		Traduzir: func(ctx context.Context, a *API) (kracha.Identidade, error) {
			var u struct {
				ID        int64  `json:"id"`
				Login     string `json:"login"`
				Name      string `json:"name"`
				AvatarURL string `json:"avatar_url"`
			}
			if err := a.JSON(ctx, api+"/user", &u); err != nil {
				return kracha.Identidade{}, err
			}
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := a.JSON(ctx, api+"/user/emails", &emails); err != nil {
				return kracha.Identidade{}, err
			}
			id := kracha.Identidade{
				ID:    strconv.FormatInt(u.ID, 10),
				Nome:  u.Name,
				Foto:  u.AvatarURL,
				Extra: map[string]string{"login": u.Login},
			}
			if u.ID == 0 {
				id.ID = ""
			}
			if id.Nome == "" {
				id.Nome = u.Login
			}
			for _, e := range emails {
				if e.Primary {
					id.Email, id.EmailGarantido = e.Email, e.Verified
				}
			}
			return id, nil
		},
	}
}
