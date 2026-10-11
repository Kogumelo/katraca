// Package email prova que a pessoa le uma caixa de correio. A prova e uma so,
// com duas apresentacoes:
//
//   - Link: um token longo vai dentro de um endereco; quem clica, prova.
//   - Codigo: seis digitos que a pessoa digita; curto, entao tem teto de
//     tentativas.
//
// E serve a tres finalidades: entrar, confirmar um cadastro e redefinir a
// senha. Uma prova emitida para uma finalidade nao vale para outra.
//
// A biblioteca nao manda e-mail: ela entrega a Mensagem ao Carteiro do app,
// que monta o texto, o endereco do link e o remetente. Nem guarda nada: a
// Guarda e do app (ha uma de referencia em pgkracha). Do segredo, a Guarda so
// ve o hash.
package email

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Kogumelo/kracha"
)

// Finalidade e para que a prova foi pedida.
type Finalidade string

const (
	Entrar    Finalidade = "entrar"
	Confirmar Finalidade = "confirmar"
	Redefinir Finalidade = "redefinir"
)

// Forma e a apresentacao da prova.
type Forma string

const (
	Link   Forma = "link"
	Codigo Forma = "codigo"
)

// Emissao e uma prova emitida, como a Guarda a ve. Sem o segredo: so o hash.
type Emissao struct {
	ID         string // aleatorio, gerado aqui
	Email      string // normalizado
	Finalidade Finalidade
	Forma      Forma
	Hash       []byte // sha256 do token; no codigo, sha256(ID ":" codigo)
	Criada     time.Time
	Expira     time.Time
	Tentativas int // so no codigo; a Guarda a incrementa em TentarCodigo
}

// ErrNaoHa e o que a Guarda devolve quando nao ha emissao viva que sirva.
var ErrNaoHa = errors.New("email: nenhuma emissao viva")

// Guarda persiste as emissoes. Cada metodo e atomico: e isso que faz o uso
// unico e o teto valerem com dois pedidos ao mesmo tempo.
type Guarda interface {
	// Emitir guarda e. Antes, conta as emissoes do mesmo e-mail criadas
	// depois de desde (qualquer forma e finalidade, usadas ou nao); se ja
	// forem maximo, nao guarda e devolve kracha.ErrMuitosPedidos. Contar e
	// guardar nao se separam. Se e.Forma for Codigo, os codigos ainda nao
	// usados do mesmo e-mail e finalidade deixam de valer.
	Emitir(ctx context.Context, e Emissao, maximo int, desde time.Time) error

	// GastarLink marca como usado o link de hash e finalidade dados, se ainda
	// nao foi, e o devolve — vencido ou nao; o prazo a biblioteca confere.
	// Sem link por usar: ErrNaoHa.
	GastarLink(ctx context.Context, hash []byte, f Finalidade) (Emissao, error)

	// TentarCodigo soma uma tentativa ao codigo mais recente ainda nao usado
	// do e-mail e finalidade, e o devolve ja com a soma. Sem codigo: ErrNaoHa.
	TentarCodigo(ctx context.Context, email string, f Finalidade) (Emissao, error)

	// Gastar marca como usada a emissao id, se ainda nao foi. Devolve false se
	// outro pedido a gastou antes.
	Gastar(ctx context.Context, id string) (bool, error)
}

// Mensagem e o que o Carteiro manda. Token vem preenchido no Link, Codigo no
// Codigo. O app monta o endereco do link (de preferencia com o token no
// fragmento, "#", que nao vai a servidor nenhum) e o texto.
type Mensagem struct {
	Para       string
	Finalidade Finalidade
	Forma      Forma
	Token      string // base64url, 43 caracteres
	Codigo     string // seis digitos
	Expira     time.Time
}

// Carteiro entrega a Mensagem. E do app: SES, SMTP, o que for.
type Carteiro interface {
	Enviar(ctx context.Context, m Mensagem) error
}

// CarteiroFunc deixa uma funcao servir de Carteiro.
type CarteiroFunc func(ctx context.Context, m Mensagem) error

func (f CarteiroFunc) Enviar(ctx context.Context, m Mensagem) error { return f(ctx, m) }

// Config parametriza a prova. O zero de cada campo vale o padrao ao lado.
type Config struct {
	PrazoDoLink   time.Duration // 15 min
	PrazoDoCodigo time.Duration // 15 min
	// MaximoPorJanela mensagens por e-mail dentro de Janela, somando links e
	// codigos de todas as finalidades. Sem limite, a rota vira um jeito de
	// encher a caixa de alguem — e cada mensagem gasta a reputacao do dominio.
	MaximoPorJanela int           // 3
	Janela          time.Duration // 15 min
	// TetoDeTentativas por codigo. Seis digitos sao um milhao de
	// possibilidades; com 6 tentativas por codigo e 3 codigos por janela, a
	// chance de acertar no chute e de 18 em um milhao a cada 15 minutos.
	TetoDeTentativas int // 6
	// Agora substitui o relogio, para teste.
	Agora func() time.Time
}

// Prova e a prova por e-mail configurada.
type Prova struct {
	guarda   Guarda
	carteiro Carteiro
	cfg      Config
}

// Nova monta a prova. Guarda e Carteiro sao obrigatorios.
func Nova(g Guarda, c Carteiro, cfg Config) (*Prova, error) {
	if g == nil || c == nil {
		return nil, errors.New("email: Guarda e Carteiro sao obrigatorios")
	}
	if cfg.PrazoDoLink <= 0 {
		cfg.PrazoDoLink = 15 * time.Minute
	}
	if cfg.PrazoDoCodigo <= 0 {
		cfg.PrazoDoCodigo = 15 * time.Minute
	}
	if cfg.MaximoPorJanela <= 0 {
		cfg.MaximoPorJanela = 3
	}
	if cfg.Janela <= 0 {
		cfg.Janela = 15 * time.Minute
	}
	if cfg.TetoDeTentativas <= 0 {
		cfg.TetoDeTentativas = 6
	}
	if cfg.Agora == nil {
		cfg.Agora = time.Now
	}
	return &Prova{guarda: g, carteiro: c, cfg: cfg}, nil
}

func finalidadeValida(f Finalidade) bool {
	return f == Entrar || f == Confirmar || f == Redefinir
}

// EnviarLink emite um link para o endereco e o entrega ao Carteiro.
func (p *Prova) EnviarLink(ctx context.Context, endereco string, f Finalidade) error {
	return p.enviar(ctx, endereco, f, Link)
}

// EnviarCodigo emite um codigo de seis digitos e o entrega ao Carteiro. O
// codigo anterior do mesmo endereco e finalidade deixa de valer.
func (p *Prova) EnviarCodigo(ctx context.Context, endereco string, f Finalidade) error {
	return p.enviar(ctx, endereco, f, Codigo)
}

func (p *Prova) enviar(ctx context.Context, endereco string, f Finalidade, forma Forma) error {
	if !finalidadeValida(f) {
		return fmt.Errorf("email: finalidade desconhecida %q", f)
	}
	addr, err := kracha.NormalizarEmail(endereco)
	if err != nil {
		return err
	}
	agora := p.cfg.Agora()
	e := Emissao{ID: idNovo(), Email: addr, Finalidade: f, Forma: forma, Criada: agora}
	m := Mensagem{Para: addr, Finalidade: f, Forma: forma}
	if forma == Link {
		bruto := make([]byte, 32)
		rand.Read(bruto)
		m.Token = base64.RawURLEncoding.EncodeToString(bruto)
		h := sha256.Sum256(bruto)
		e.Hash = h[:]
		e.Expira = agora.Add(p.cfg.PrazoDoLink)
	} else {
		m.Codigo = codigoNovo()
		e.Hash = hashDoCodigo(e.ID, m.Codigo)
		e.Expira = agora.Add(p.cfg.PrazoDoCodigo)
	}
	m.Expira = e.Expira
	if err := p.guarda.Emitir(ctx, e, p.cfg.MaximoPorJanela, agora.Add(-p.cfg.Janela)); err != nil {
		return err
	}
	return p.carteiro.Enviar(ctx, m)
}

// ConferirLink gasta o token e devolve a identidade do endereco. O token so
// vale uma vez, so para a finalidade em que foi emitido e so dentro do prazo.
//
// Receba o token por POST, nunca por GET: leitor de e-mail que "confere
// links" abre GETs, e gastaria o uso unico antes da pessoa.
func (p *Prova) ConferirLink(ctx context.Context, token string, f Finalidade) (kracha.Identidade, error) {
	bruto, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(bruto) != 32 {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	h := sha256.Sum256(bruto)
	e, err := p.guarda.GastarLink(ctx, h[:], f)
	if errors.Is(err, ErrNaoHa) {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	if err != nil {
		return kracha.Identidade{}, err
	}
	if e.Finalidade != f || e.Forma != Link {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	if !p.cfg.Agora().Before(e.Expira) {
		return kracha.Identidade{}, kracha.ErrExpirado
	}
	return identidade(e.Email), nil
}

// ConferirCodigo confere o codigo digitado para o endereco. Cada chamada gasta
// uma tentativa, certa ou errada; passado o teto, nem o codigo certo vale.
func (p *Prova) ConferirCodigo(ctx context.Context, endereco, codigo string, f Finalidade) (kracha.Identidade, error) {
	addr, err := kracha.NormalizarEmail(endereco)
	if err != nil {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	codigo = limparCodigo(codigo)
	if len(codigo) != 6 {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	e, err := p.guarda.TentarCodigo(ctx, addr, f)
	if errors.Is(err, ErrNaoHa) {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	if err != nil {
		return kracha.Identidade{}, err
	}
	if e.Finalidade != f || e.Forma != Codigo || e.Email != addr {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	if e.Tentativas > p.cfg.TetoDeTentativas {
		return kracha.Identidade{}, kracha.ErrMuitasTentativas
	}
	if !p.cfg.Agora().Before(e.Expira) {
		return kracha.Identidade{}, kracha.ErrExpirado
	}
	if subtle.ConstantTimeCompare(e.Hash, hashDoCodigo(e.ID, codigo)) != 1 {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	ok, err := p.guarda.Gastar(ctx, e.ID)
	if err != nil {
		return kracha.Identidade{}, err
	}
	if !ok {
		return kracha.Identidade{}, kracha.ErrRecusado
	}
	return identidade(addr), nil
}

func identidade(addr string) kracha.Identidade {
	return kracha.Identidade{Provedor: "email", ID: addr, Email: addr, EmailGarantido: true}
}

// limparCodigo tira espacos e hifens que a pessoa digite ou cole ("123 456").
func limparCodigo(c string) string {
	var b strings.Builder
	for _, r := range c {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '\t':
		default:
			return ""
		}
	}
	return b.String()
}

// hashDoCodigo prende o codigo a emissao: o mesmo codigo em duas emissoes da
// hashes diferentes, e uma tabela pronta do milhao de hashes nao serve.
func hashDoCodigo(id, codigo string) []byte {
	h := sha256.Sum256([]byte(id + ":" + codigo))
	return h[:]
}

func codigoNovo() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err) // crypto/rand nao falha desde o Go 1.24
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func idNovo() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
