// Package provedor prova a identidade por um provedor externo — Google,
// GitHub, qualquer OIDC por configuracao, qualquer OAuth2 por um adaptador.
//
// O fluxo tem duas metades, e entre elas a pessoa vai ao provedor e volta:
//
//	url, pend, err := p.Iniciar(ctx)
//	// o app guarda pend (cookie assinado, sessao) e redireciona para url
//	...
//	// na volta, com os parametros que o provedor mandou (r.Form):
//	id, err := p.Concluir(ctx, pend, r.Form)
//
// Pendente leva o state, o verificador PKCE e o nonce. Guarda-lo e do app,
// e e ele que amarra a volta a quem saiu: sem ele, Concluir recusa.
package provedor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Kogumelo/katraca"
	"golang.org/x/oauth2"
)

// Provedor e um jeito de provar identidade com ida e volta a um terceiro.
type Provedor interface {
	// Nome e o que vai em Identidade.Provedor ("google", "github", ...).
	Nome() string
	// Iniciar devolve o endereco do provedor e o que o app guarda ate a volta.
	Iniciar(ctx context.Context) (string, Pendente, error)
	// Concluir confere a volta contra o Pendente e devolve a identidade.
	// resposta sao os parametros da volta: a query no GET, o corpo no
	// form_post (r.Form cobre os dois).
	Concluir(ctx context.Context, pend Pendente, resposta url.Values) (katraca.Identidade, error)
}

// Pendente e o que o app guarda entre Iniciar e Concluir. Nao e segredo de
// longo prazo, mas quem o tem conclui o login no lugar da pessoa: guarde-o
// num cookie HttpOnly, assinado, de vida curta, ou na sessao do servidor.
type Pendente struct {
	Provedor    string    `json:"p"`
	Estado      string    `json:"s"`
	Verificador string    `json:"v,omitempty"` // PKCE
	Nonce       string    `json:"n,omitempty"` // OIDC
	Criado      time.Time `json:"c"`
}

// ErroDoProvedor e a recusa que o proprio provedor mandou na volta
// (?error=access_denied, por exemplo). Embrulha katraca.ErrRecusado.
type ErroDoProvedor struct {
	Codigo    string
	Descricao string
}

func (e *ErroDoProvedor) Error() string {
	return fmt.Sprintf("provedor: %s (%s)", e.Codigo, e.Descricao)
}
func (e *ErroDoProvedor) Unwrap() error { return katraca.ErrRecusado }

// PrazoDoInicio e quanto tempo a pessoa tem para ir ao provedor e voltar.
const PrazoDoInicio = 10 * time.Minute

// LimiteDaResposta e o tamanho maximo lido de qualquer resposta de provedor.
const LimiteDaResposta = 1 << 20

// ClientePadrao e o cliente HTTP usado quando a configuracao nao da outro.
// Tem prazo: provedor lento nao prende o pedido da pessoa.
var ClientePadrao = &http.Client{Timeout: 10 * time.Second}

func aleatorio() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// conferirVolta e a parte comum de Concluir: provedor, prazo, erro do
// provedor, state e presenca do code.
func conferirVolta(nome string, pend Pendente, resposta url.Values, agora time.Time) (string, error) {
	if pend.Provedor != nome || pend.Estado == "" {
		return "", fmt.Errorf("%w: pendente de outro provedor", katraca.ErrRecusado)
	}
	if agora.Sub(pend.Criado) > PrazoDoInicio || agora.Before(pend.Criado.Add(-time.Minute)) {
		return "", katraca.ErrExpirado
	}
	if e := resposta.Get("error"); e != "" {
		return "", &ErroDoProvedor{Codigo: e, Descricao: resposta.Get("error_description")}
	}
	if subtle.ConstantTimeCompare([]byte(resposta.Get("state")), []byte(pend.Estado)) != 1 {
		return "", fmt.Errorf("%w: state nao confere", katraca.ErrRecusado)
	}
	code := resposta.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: volta sem code", katraca.ErrRecusado)
	}
	return code, nil
}

// API chama a API do provedor com o access token no cabecalho
// Authorization — nunca na URL, onde cairia em log.
type API struct {
	Cliente *http.Client
	Token   *oauth2.Token
}

// JSON faz GET em endereco e decodifica a resposta em destino. Le no maximo
// LimiteDaResposta bytes.
func (a *API) JSON(ctx context.Context, endereco string, destino any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endereco, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if a.Token != nil {
		req.Header.Set("Authorization", "Bearer "+a.Token.AccessToken)
	}
	return lerJSON(a.Cliente, req, destino)
}

func lerJSON(c *http.Client, req *http.Request, destino any) error {
	if c == nil {
		c = ClientePadrao
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	corpo, err := io.ReadAll(io.LimitReader(resp.Body, LimiteDaResposta+1))
	if err != nil {
		return err
	}
	if len(corpo) > LimiteDaResposta {
		return fmt.Errorf("provedor: resposta de %s passa de %d bytes", req.URL.Host, LimiteDaResposta)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("provedor: %s respondeu %d", req.URL.Host, resp.StatusCode)
	}
	if err := json.Unmarshal(corpo, destino); err != nil {
		return fmt.Errorf("provedor: resposta de %s ilegivel: %w", req.URL.Host, err)
	}
	return nil
}

// comCliente poe o cliente no contexto, que e por onde o x/oauth2 o acha.
func comCliente(ctx context.Context, c *http.Client) context.Context {
	if c == nil {
		c = ClientePadrao
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}
