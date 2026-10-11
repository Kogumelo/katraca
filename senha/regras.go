package senha

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Regras de forca. O zero vale: no minimo 8 caracteres, no maximo 128.
//
// A recomendacao atual (NIST SP 800-63B) e exigir comprimento e recusar
// senhas conhecidas, nao exigir mistura de classes; as exigencias de classe
// estao aqui porque ha app que as quer, e ficam desligadas por padrao.
type Regras struct {
	Minimo int // caracteres; 0 vale 8
	// Maximo em caracteres; 0 vale 128. Ha teto porque o hash custa tempo
	// proporcional ao tamanho, e uma senha de um megabyte e um ataque.
	Maximo          int
	ExigirLetra     bool
	ExigirNumero    bool
	ExigirMaiuscula bool
	ExigirSimbolo   bool
	// Proibidas: senhas recusadas, sem distinguir caixa ("12345678",
	// "senha123", o nome do app).
	Proibidas []string
	// SemLogin recusa a senha que contem o login (ou a parte local do
	// e-mail), sem distinguir caixa.
	SemLogin bool
}

// Fraca e o erro de Conferir: diz qual regra a senha quebrou, para o app
// escrever a mensagem na lingua dele.
type Fraca struct {
	Regra string // "minimo", "maximo", "letra", "numero", "maiuscula", "simbolo", "proibida", "login"
	Valor int    // o limite, nas regras de tamanho
}

func (f *Fraca) Error() string { return "senha: fraca (" + f.Regra + ")" }

// Conferir devolve nil se a senha cumpre as regras, ou *Fraca com a primeira
// regra quebrada.
func (r Regras) Conferir(senha, login string) error {
	min, max := r.Minimo, r.Maximo
	if min <= 0 {
		min = 8
	}
	if max <= 0 {
		max = 128
	}
	n := utf8.RuneCountInString(senha)
	if n < min {
		return &Fraca{Regra: "minimo", Valor: min}
	}
	if n > max {
		return &Fraca{Regra: "maximo", Valor: max}
	}
	var letra, numero, maiuscula, simbolo bool
	for _, c := range senha {
		switch {
		case unicode.IsUpper(c):
			maiuscula, letra = true, true
		case unicode.IsLetter(c):
			letra = true
		case unicode.IsDigit(c):
			numero = true
		default:
			simbolo = true
		}
	}
	switch {
	case r.ExigirLetra && !letra:
		return &Fraca{Regra: "letra"}
	case r.ExigirNumero && !numero:
		return &Fraca{Regra: "numero"}
	case r.ExigirMaiuscula && !maiuscula:
		return &Fraca{Regra: "maiuscula"}
	case r.ExigirSimbolo && !simbolo:
		return &Fraca{Regra: "simbolo"}
	}
	baixa := strings.ToLower(senha)
	for _, p := range r.Proibidas {
		if baixa == strings.ToLower(p) {
			return &Fraca{Regra: "proibida"}
		}
	}
	if r.SemLogin && login != "" {
		l := strings.ToLower(login)
		if i := strings.Index(l, "@"); i > 0 {
			l = l[:i]
		}
		if len(l) >= 3 && strings.Contains(baixa, l) {
			return &Fraca{Regra: "login"}
		}
	}
	return nil
}
