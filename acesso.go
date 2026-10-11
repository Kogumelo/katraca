// Package acesso prova quem a pessoa e. Nao cria conta, nao abre sessao, nao
// planta cookie: isso e do app.
//
// Todo metodo — prova por e-mail (link ou codigo), senha, Google, GitHub ou
// qualquer provedor OIDC ou OAuth2 — termina na mesma Identidade. O app olha
// para ela e decide: acha a conta pelo par (Provedor, ID), cria uma nova, ou
// junta com outra. Juntar pelo e-mail so e seguro quando EmailGarantido e
// verdadeiro; veja o README.
//
// Os subpacotes:
//
//   - email: link magico e codigo de 6 digitos, duas apresentacoes da mesma
//     prova por e-mail.
//   - senha: argon2id, verificacao de bcrypt legado, regras de forca.
//   - provedor: OIDC por descoberta, adaptador OAuth2, Google e GitHub.
//   - pgacesso: guarda de referencia em Postgres com pgx (opcional).
package acesso

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// Identidade e o que uma prova estabelece. O par (Provedor, ID) e fixo para a
// mesma pessoa no mesmo provedor; e por ele que o app acha a conta.
type Identidade struct {
	// Provedor nomeia o metodo: "email", "senha", "google", "github", ou o
	// nome dado a um provedor configurado.
	Provedor string
	// ID e o identificador fixo dentro do provedor: o `sub` do OIDC, o id
	// numerico do GitHub, o e-mail normalizado na prova por e-mail, o login
	// na senha.
	ID string
	// Email e o endereco que o provedor informou, normalizado. Pode vir vazio.
	Email string
	// EmailGarantido diz que o provedor (ou a prova por e-mail) atesta que a
	// pessoa controla Email. Sem ele, Email e so uma declaracao: o app NAO
	// liga esta identidade a uma conta existente pelo e-mail.
	EmailGarantido bool
	// Nome e Foto sao cosmeticos e podem vir vazios.
	Nome string
	Foto string
	// Extra guarda o que um provedor tem de proprio e o app talvez queira
	// (por exemplo, "email_privado" da Apple). Pode ser nil.
	Extra map[string]string
}

// Os erros de prova. Todos os de recusa embrulham ErrRecusado, para o app
// tratar "nao provou" num lugar so e, se quiser, distinguir o motivo.
var (
	// ErrRecusado: a prova nao vale (senha errada, usuario inexistente, link
	// usado, codigo errado, state trocado). O app responde sem dizer qual.
	ErrRecusado = errors.New("acesso: prova recusada")
	// ErrExpirado: a prova valia, mas o prazo passou.
	ErrExpirado = fmt.Errorf("%w: prazo vencido", ErrRecusado)
	// ErrMuitasTentativas: o codigo gastou o teto de tentativas.
	ErrMuitasTentativas = fmt.Errorf("%w: tentativas esgotadas", ErrRecusado)
	// ErrMuitosPedidos: o endereco ja recebeu o maximo de mensagens na janela.
	ErrMuitosPedidos = errors.New("acesso: pedidos demais para este endereco")
	// ErrEmailInvalido: o endereco nao e um e-mail nu e valido.
	ErrEmailInvalido = errors.New("acesso: e-mail invalido")
)

// NormalizarEmail aceita so o endereco nu ("ana@exemplo.com"), sem nome, sem
// quebra de linha e sem nada que vire um segundo destinatario, e o devolve em
// minusculas. A parte local e, pela norma, sensivel a caixa; na pratica nenhum
// provedor grande a trata assim, e duas contas para "Ana@" e "ana@" seriam
// pior que o raro caso contrario.
func NormalizarEmail(bruto string) (string, error) {
	e := strings.TrimSpace(bruto)
	if e == "" || len(e) > 254 || strings.ContainsAny(e, "\r\n<>\",; \t") {
		return "", ErrEmailInvalido
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return "", ErrEmailInvalido
	}
	arroba := strings.LastIndex(e, "@")
	if arroba < 1 || !strings.Contains(e[arroba+1:], ".") {
		return "", ErrEmailInvalido
	}
	return strings.ToLower(e), nil
}
