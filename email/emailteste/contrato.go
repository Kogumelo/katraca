// Package emailteste confere se uma email.Guarda cumpre o contrato: prazo,
// uso unico, limite por endereco, teto de tentativas e finalidade. Quem
// escreve uma Guarda propria roda Contrato contra ela.
package emailteste

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
)

// Relogio e um relogio de teste que so anda quando mandam.
type Relogio struct {
	mu sync.Mutex
	t  time.Time
}

func (r *Relogio) Agora() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.t
}

func (r *Relogio) Andar(d time.Duration) {
	r.mu.Lock()
	r.t = r.t.Add(d)
	r.mu.Unlock()
}

// Caixa e um Carteiro que guarda as mensagens em vez de manda-las.
type Caixa struct {
	mu        sync.Mutex
	Mensagens []email.Mensagem
}

func (c *Caixa) Enviar(_ context.Context, m email.Mensagem) error {
	c.mu.Lock()
	c.Mensagens = append(c.Mensagens, m)
	c.mu.Unlock()
	return nil
}

// Ultima devolve a ultima mensagem entregue.
func (c *Caixa) Ultima(t testing.TB) email.Mensagem {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.Mensagens) == 0 {
		t.Fatal("nenhuma mensagem entregue")
	}
	return c.Mensagens[len(c.Mensagens)-1]
}

// Contrato roda os casos contra Guardas novas, uma por subteste. A guarda
// pode compartilhar o banco entre subtestes: cada um usa enderecos proprios.
func Contrato(t *testing.T, nova func(t *testing.T) email.Guarda) {
	ctx := context.Background()
	montar := func(t *testing.T) (*email.Prova, *Caixa, *Relogio) {
		// O relogio parte do agora verdadeiro, arredondado: uma Guarda em
		// banco pode carimbar com o relogio dela, e o teste nao deve brigar
		// com isso.
		r := &Relogio{t: time.Now().Truncate(time.Second)}
		c := &Caixa{}
		p, err := email.Nova(nova(t), c, email.Config{Agora: r.Agora})
		if err != nil {
			t.Fatal(err)
		}
		return p, c, r
	}
	endereco := func(t *testing.T) string {
		return "Pessoa." + time.Now().Format("150405.000000000") + "@Exemplo.com"
	}

	t.Run("link vale uma vez e da e-mail garantido", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarLink(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		m := c.Ultima(t)
		if m.Forma != email.Link || m.Token == "" || m.Codigo != "" {
			t.Fatalf("mensagem de link errada: %+v", m)
		}
		id, err := p.ConferirLink(ctx, m.Token, email.Entrar)
		if err != nil {
			t.Fatal(err)
		}
		norm, _ := katraca.NormalizarEmail(ender)
		if id.Provedor != "email" || id.ID != norm || id.Email != norm || !id.EmailGarantido {
			t.Fatalf("identidade errada: %+v", id)
		}
		if _, err := p.ConferirLink(ctx, m.Token, email.Entrar); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("segundo uso: quero ErrRecusado, veio %v", err)
		}
	})

	t.Run("link vencido", func(t *testing.T) {
		p, c, r := montar(t)
		if err := p.EnviarLink(ctx, endereco(t), email.Entrar); err != nil {
			t.Fatal(err)
		}
		r.Andar(15*time.Minute + time.Second)
		_, err := p.ConferirLink(ctx, c.Ultima(t).Token, email.Entrar)
		if !errors.Is(err, katraca.ErrExpirado) || !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("quero ErrExpirado, veio %v", err)
		}
	})

	t.Run("link de outra finalidade nao vale", func(t *testing.T) {
		p, c, _ := montar(t)
		if err := p.EnviarLink(ctx, endereco(t), email.Confirmar); err != nil {
			t.Fatal(err)
		}
		tok := c.Ultima(t).Token
		if _, err := p.ConferirLink(ctx, tok, email.Redefinir); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("quero ErrRecusado, veio %v", err)
		}
		// E a tentativa errada nao o gastou.
		if _, err := p.ConferirLink(ctx, tok, email.Confirmar); err != nil {
			t.Fatalf("o link de confirmar devia valer: %v", err)
		}
	})

	t.Run("token adulterado", func(t *testing.T) {
		p, _, _ := montar(t)
		for _, tok := range []string{"", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			if _, err := p.ConferirLink(ctx, tok, email.Entrar); !errors.Is(err, katraca.ErrRecusado) {
				t.Fatalf("token %q: quero ErrRecusado, veio %v", tok, err)
			}
		}
	})

	t.Run("limite por endereco soma links e codigos", func(t *testing.T) {
		p, _, r := montar(t)
		ender := endereco(t)
		if err := p.EnviarLink(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		if err := p.EnviarCodigo(ctx, ender, email.Redefinir); err != nil {
			t.Fatal(err)
		}
		// Caixa diferente, mesmo endereco: o limite e do endereco.
		if err := p.EnviarLink(ctx, ender, email.Confirmar); err != nil {
			t.Fatal(err)
		}
		if err := p.EnviarLink(ctx, ender, email.Entrar); !errors.Is(err, katraca.ErrMuitosPedidos) {
			t.Fatalf("quarto pedido: quero ErrMuitosPedidos, veio %v", err)
		}
		// Outro endereco nao e afetado.
		if err := p.EnviarLink(ctx, "outra."+ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		r.Andar(15*time.Minute + time.Second)
		if err := p.EnviarLink(ctx, ender, email.Entrar); err != nil {
			t.Fatalf("depois da janela devia passar: %v", err)
		}
	})

	t.Run("codigo vale uma vez", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Redefinir); err != nil {
			t.Fatal(err)
		}
		m := c.Ultima(t)
		if m.Forma != email.Codigo || len(m.Codigo) != 6 || m.Token != "" {
			t.Fatalf("mensagem de codigo errada: %+v", m)
		}
		// Com espaco no meio, como a pessoa digita.
		id, err := p.ConferirCodigo(ctx, ender, m.Codigo[:3]+" "+m.Codigo[3:], email.Redefinir)
		if err != nil {
			t.Fatal(err)
		}
		if !id.EmailGarantido {
			t.Fatal("codigo certo devia garantir o e-mail")
		}
		if _, err := p.ConferirCodigo(ctx, ender, m.Codigo, email.Redefinir); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("segundo uso: quero ErrRecusado, veio %v", err)
		}
	})

	t.Run("teto de tentativas", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		certo := c.Ultima(t).Codigo
		errado := "000000"
		if certo == errado {
			errado = "111111"
		}
		for i := 0; i < 6; i++ {
			if _, err := p.ConferirCodigo(ctx, ender, errado, email.Entrar); !errors.Is(err, katraca.ErrRecusado) {
				t.Fatalf("tentativa %d: quero ErrRecusado, veio %v", i+1, err)
			}
		}
		_, err := p.ConferirCodigo(ctx, ender, certo, email.Entrar)
		if !errors.Is(err, katraca.ErrMuitasTentativas) {
			t.Fatalf("certo depois do teto: quero ErrMuitasTentativas, veio %v", err)
		}
	})

	t.Run("codigo vencido", func(t *testing.T) {
		p, c, r := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		r.Andar(15*time.Minute + time.Second)
		_, err := p.ConferirCodigo(ctx, ender, c.Ultima(t).Codigo, email.Entrar)
		if !errors.Is(err, katraca.ErrExpirado) {
			t.Fatalf("quero ErrExpirado, veio %v", err)
		}
	})

	t.Run("codigo novo derruba o anterior e zera tentativas", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		velho := c.Ultima(t).Codigo
		for i := 0; i < 5; i++ {
			p.ConferirCodigo(ctx, ender, "999999", email.Entrar)
		}
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		novo := c.Ultima(t).Codigo
		if velho != novo {
			if _, err := p.ConferirCodigo(ctx, ender, velho, email.Entrar); !errors.Is(err, katraca.ErrRecusado) {
				t.Fatalf("codigo velho: quero ErrRecusado, veio %v", err)
			}
		}
		if _, err := p.ConferirCodigo(ctx, ender, novo, email.Entrar); err != nil {
			t.Fatalf("codigo novo devia valer: %v", err)
		}
	})

	t.Run("codigo de outra finalidade ou outro endereco nao vale", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Confirmar); err != nil {
			t.Fatal(err)
		}
		cod := c.Ultima(t).Codigo
		if _, err := p.ConferirCodigo(ctx, ender, cod, email.Entrar); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("outra finalidade: quero ErrRecusado, veio %v", err)
		}
		if _, err := p.ConferirCodigo(ctx, "x"+ender, cod, email.Confirmar); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("outro endereco: quero ErrRecusado, veio %v", err)
		}
	})

	t.Run("dois cliques simultaneos, um vence", func(t *testing.T) {
		p, c, _ := montar(t)
		if err := p.EnviarLink(ctx, endereco(t), email.Entrar); err != nil {
			t.Fatal(err)
		}
		tok := c.Ultima(t).Token
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := p.ConferirLink(ctx, tok, email.Entrar); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d cliques venceram; quero 1", ok)
		}
	})

	t.Run("teto vale com tentativas simultaneas", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		certo := c.Ultima(t).Codigo
		errado := "000000"
		if certo == errado {
			errado = "111111"
		}
		// Cada tentativa tem de ver a soma das outras: com contagem
		// perdida, vinte chutes ao mesmo tempo passariam por seis.
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.ConferirCodigo(ctx, ender, errado, email.Entrar)
			}()
		}
		wg.Wait()
		if _, err := p.ConferirCodigo(ctx, ender, certo, email.Entrar); !errors.Is(err, katraca.ErrMuitasTentativas) {
			t.Fatalf("certo depois de 20 chutes simultaneos: quero ErrMuitasTentativas, veio %v", err)
		}
	})

	t.Run("codigo certo simultaneo, um vence", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		if err := p.EnviarCodigo(ctx, ender, email.Entrar); err != nil {
			t.Fatal(err)
		}
		cod := c.Ultima(t).Codigo
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := p.ConferirCodigo(ctx, ender, cod, email.Entrar); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d conferencias venceram; quero 1", ok)
		}
	})

	t.Run("limite vale com pedidos simultaneos", func(t *testing.T) {
		p, c, _ := montar(t)
		ender := endereco(t)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.EnviarLink(ctx, ender, email.Entrar)
			}()
		}
		wg.Wait()
		if n := len(c.Mensagens); n != 3 {
			t.Fatalf("%d mensagens sairam; o limite e 3", n)
		}
	})
}
