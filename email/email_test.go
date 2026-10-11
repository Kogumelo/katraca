package email_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Kogumelo/acesso"
	"github.com/Kogumelo/acesso/email"
	"github.com/Kogumelo/acesso/email/emailteste"
)

func TestMemoria(t *testing.T) {
	emailteste.Contrato(t, func(*testing.T) email.Guarda { return email.NovaMemoria() })
}

func TestEnderecoInvalido(t *testing.T) {
	p, _ := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, email.Config{})
	for _, e := range []string{"", "ana", "ana@x", "Ana <ana@x.com>", "a@x.com\r\nBcc: b@y.com", "a@x.com, b@y.com"} {
		if err := p.EnviarLink(context.Background(), e, email.Entrar); !errors.Is(err, acesso.ErrEmailInvalido) {
			t.Errorf("%q: quero ErrEmailInvalido, veio %v", e, err)
		}
	}
}

func TestFinalidadeDesconhecida(t *testing.T) {
	p, _ := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, email.Config{})
	if err := p.EnviarLink(context.Background(), "a@b.com", "qualquer"); err == nil {
		t.Fatal("finalidade desconhecida devia falhar")
	}
}
