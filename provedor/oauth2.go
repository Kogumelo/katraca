package provedor

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Kogumelo/katraca"
	"golang.org/x/oauth2"
)

// OAuth2 e o adaptador para provedor que nao e OIDC (GitHub, Meta): o fluxo
// de autorizacao e o padrao, e quem sabe ler a pessoa e Traduzir, uma
// funcao pequena que consulta a API do provedor.
type OAuth2 struct {
	NomeDoProvedor string
	ClienteID      string
	Segredo        string
	Retorno        string // URL de volta, registrada no provedor
	Escopos        []string
	AutorizarURL   string
	TokenURL       string
	// SemPKCE desliga o PKCE, para provedor que o recusa. Ligado por padrao.
	SemPKCE bool
	// ParametrosExtra vao no endereco de autorizacao.
	ParametrosExtra map[string]string
	// Traduzir le a pessoa na API do provedor. api ja leva o token no
	// cabecalho, prazo e limite de tamanho.
	Traduzir func(ctx context.Context, api *API) (katraca.Identidade, error)
	Cliente  *http.Client // vazio vale ClientePadrao
	Agora    func() time.Time
}

func (o *OAuth2) Nome() string { return o.NomeDoProvedor }

func (o *OAuth2) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClienteID,
		ClientSecret: o.Segredo,
		RedirectURL:  o.Retorno,
		Scopes:       o.Escopos,
		Endpoint:     oauth2.Endpoint{AuthURL: o.AutorizarURL, TokenURL: o.TokenURL},
	}
}

func (o *OAuth2) agora() time.Time {
	if o.Agora != nil {
		return o.Agora()
	}
	return time.Now()
}

func (o *OAuth2) Iniciar(ctx context.Context) (string, Pendente, error) {
	if o.ClienteID == "" || o.Retorno == "" || o.Traduzir == nil {
		return "", Pendente{}, fmt.Errorf("provedor %s: ClienteID, Retorno e Traduzir sao obrigatorios", o.NomeDoProvedor)
	}
	pend := Pendente{Provedor: o.NomeDoProvedor, Estado: aleatorio(), Criado: o.agora()}
	var opts []oauth2.AuthCodeOption
	if !o.SemPKCE {
		pend.Verificador = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pend.Verificador))
	}
	for k, v := range o.ParametrosExtra {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return o.config().AuthCodeURL(pend.Estado, opts...), pend, nil
}

func (o *OAuth2) Concluir(ctx context.Context, pend Pendente, resposta url.Values) (katraca.Identidade, error) {
	code, err := conferirVolta(o.NomeDoProvedor, pend, resposta, o.agora())
	if err != nil {
		return katraca.Identidade{}, err
	}
	var opts []oauth2.AuthCodeOption
	if pend.Verificador != "" {
		opts = append(opts, oauth2.VerifierOption(pend.Verificador))
	}
	tok, err := o.config().Exchange(comCliente(ctx, o.Cliente), code, opts...)
	if err != nil {
		return katraca.Identidade{}, fmt.Errorf("%w: troca do code: %v", katraca.ErrRecusado, err)
	}
	id, err := o.Traduzir(ctx, &API{Cliente: o.Cliente, Token: tok})
	if err != nil {
		return katraca.Identidade{}, err
	}
	if id.ID == "" {
		return katraca.Identidade{}, fmt.Errorf("provedor %s: identidade sem ID", o.NomeDoProvedor)
	}
	id.Provedor = o.NomeDoProvedor
	if id.Email != "" {
		if e, err := katraca.NormalizarEmail(id.Email); err == nil {
			id.Email = e
		} else {
			id.Email, id.EmailGarantido = "", false
		}
	} else {
		id.EmailGarantido = false
	}
	return id, nil
}
