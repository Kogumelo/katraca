package email_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/email/emailteste"
)

func TestMemoria(t *testing.T) {
	emailteste.Contrato(t, func(*testing.T) email.Guarda { return email.NovaMemoria() })
}

func TestEnderecoInvalido(t *testing.T) {
	p, _ := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, configDeTeste())
	for _, e := range []string{"", "ana", "ana@x", "Ana <ana@x.com>", "a@x.com\r\nBcc: b@y.com", "a@x.com, b@y.com"} {
		if err := p.EnviarLink(context.Background(), e, email.Entrar); !errors.Is(err, katraca.ErrEmailInvalido) {
			t.Errorf("%q: quero ErrEmailInvalido, veio %v", e, err)
		}
	}
}

func TestFinalidadeDesconhecida(t *testing.T) {
	p, _ := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, configDeTeste())
	if err := p.EnviarLink(context.Background(), "a@b.com", "qualquer"); err == nil {
		t.Fatal("finalidade desconhecida devia falhar")
	}
}

// Sem chave do servidor, quem le o banco acha o codigo vivo testando o
// milhao de codigos contra o hash. A chave e obrigatoria.
func TestSemChaveNaoMonta(t *testing.T) {
	if _, err := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, email.Config{}); !errors.Is(err, email.ErrChaveCurta) {
		t.Fatalf("sem chave: quero ErrChaveCurta, veio %v", err)
	}
	curta := email.Config{Chave: make([]byte, email.TamanhoMinimoDaChave-1)}
	if _, err := email.Nova(email.NovaMemoria(), &emailteste.Caixa{}, curta); !errors.Is(err, email.ErrChaveCurta) {
		t.Fatalf("chave curta: quero ErrChaveCurta, veio %v", err)
	}
}

// espia guarda a ultima Emissao, como o banco a veria.
type espia struct {
	*email.Memoria
	ultima email.Emissao
}

func (e *espia) Emitir(ctx context.Context, x email.Emissao, maximo int, desde time.Time) error {
	e.ultima = x
	return e.Memoria.Emitir(ctx, x, maximo, desde)
}

// O hash guardado nao sai so do que esta no banco: testar o milhao de
// codigos contra sha256(id:codigo) nao acha nada.
func TestHashDoCodigoPedeAChave(t *testing.T) {
	g := &espia{Memoria: email.NovaMemoria()}
	c := &emailteste.Caixa{}
	p, err := email.Nova(g, c, configDeTeste())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.EnviarCodigo(ctx, "ana@exemplo.com", email.Entrar); err != nil {
		t.Fatal(err)
	}
	cod := c.Ultima(t).Codigo
	for i := 0; i < 1_000_000; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%06d", g.ultima.ID, i)))
		if bytes.Equal(h[:], g.ultima.Hash) {
			t.Fatalf("o codigo %06d (enviado %s) saiu do banco sem chave", i, cod)
		}
	}
}
