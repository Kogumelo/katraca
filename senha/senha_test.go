package senha_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kogumelo/kracha"
	"github.com/Kogumelo/kracha/senha"
	"golang.org/x/crypto/bcrypt"
)

func TestArgon2idIdaEVolta(t *testing.T) {
	h, err := senha.Padrao.Gerar("cavalo correto bateria")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("formato inesperado: %s", h)
	}
	ok, trocar, err := senha.Padrao.Conferir(h, "cavalo correto bateria")
	if err != nil || !ok || trocar {
		t.Fatalf("certa: ok=%v trocar=%v err=%v", ok, trocar, err)
	}
	ok, _, err = senha.Padrao.Conferir(h, "cavalo correto bateriA")
	if err != nil || ok {
		t.Fatalf("errada: ok=%v err=%v", ok, err)
	}
	// Dois hashes da mesma senha diferem: o sal e aleatorio.
	h2, _ := senha.Padrao.Gerar("cavalo correto bateria")
	if h == h2 {
		t.Fatal("sal repetido")
	}
}

func TestBcryptConfereEPedeTroca(t *testing.T) {
	b, _ := bcrypt.GenerateFromPassword([]byte("segredo123"), bcrypt.MinCost)
	ok, trocar, err := senha.Padrao.Conferir(string(b), "segredo123")
	if err != nil || !ok || !trocar {
		t.Fatalf("bcrypt certo: ok=%v trocar=%v err=%v", ok, trocar, err)
	}
	ok, trocar, err = senha.Padrao.Conferir(string(b), "segredo124")
	if err != nil || ok || trocar {
		t.Fatalf("bcrypt errado: ok=%v trocar=%v err=%v", ok, trocar, err)
	}
	// $2y$ (PHP) tambem.
	y := "$2y$" + string(b)[4:]
	if ok, _, err := senha.Padrao.Conferir(y, "segredo123"); err != nil || !ok {
		t.Fatalf("$2y$: ok=%v err=%v", ok, err)
	}
}

func TestArgon2idFracoPedeTroca(t *testing.T) {
	fraco := senha.Parametros{Memoria: 8 * 1024, Passadas: 1, Vias: 1}
	h, _ := fraco.Gerar("abc")
	ok, trocar, err := senha.Padrao.Conferir(h, "abc")
	if err != nil || !ok || !trocar {
		t.Fatalf("ok=%v trocar=%v err=%v", ok, trocar, err)
	}
}

func TestHashDesconhecido(t *testing.T) {
	for _, h := range []string{"", "texto puro", "$argon2id$v=19$m=1,t=1$x$y", "$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", "$1$md5"} {
		if _, _, err := senha.Padrao.Conferir(h, "x"); !errors.Is(err, senha.ErrHashInvalido) {
			t.Errorf("%q: quero ErrHashInvalido, veio %v", h, err)
		}
	}
}

type guarda struct {
	mu sync.Mutex
	c  map[string]senha.Credencial
}

func (g *guarda) Credencial(_ context.Context, login string) (senha.Credencial, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.c[login]
	if !ok {
		return senha.Credencial{}, senha.ErrNaoHa
	}
	return c, nil
}

func (g *guarda) TrocarHash(_ context.Context, login, antigo, novo string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c := g.c[login]; c.Hash == antigo {
		c.Hash = novo
		g.c[login] = c
	}
	return nil
}

func TestEntrarMigraDoBcrypt(t *testing.T) {
	b, _ := bcrypt.GenerateFromPassword([]byte("segredo123"), bcrypt.MinCost)
	g := &guarda{c: map[string]senha.Credencial{"ana@x.com": {Hash: string(b), Email: "ana@x.com"}}}
	s := &senha.Senhas{Guarda: g}
	ctx := context.Background()

	id, trocado, err := s.Entrar(ctx, "ana@x.com", "segredo123")
	if err != nil || !trocado {
		t.Fatalf("trocado=%v err=%v", trocado, err)
	}
	if id.Provedor != "senha" || id.ID != "ana@x.com" || id.EmailGarantido {
		t.Fatalf("identidade: %+v", id)
	}
	if !strings.HasPrefix(g.c["ana@x.com"].Hash, "$argon2id$") {
		t.Fatalf("hash nao migrou: %s", g.c["ana@x.com"].Hash)
	}
	// Segunda vez: ja e argon2id, nada a trocar.
	if _, trocado, err := s.Entrar(ctx, "ana@x.com", "segredo123"); err != nil || trocado {
		t.Fatalf("segunda: trocado=%v err=%v", trocado, err)
	}
	if _, _, err := s.Entrar(ctx, "ana@x.com", "errada"); !errors.Is(err, kracha.ErrRecusado) {
		t.Fatalf("errada: %v", err)
	}
	if _, _, err := s.Entrar(ctx, "bia@x.com", "segredo123"); !errors.Is(err, kracha.ErrRecusado) {
		t.Fatalf("sem usuario: %v", err)
	}
}

// Login inexistente gasta o mesmo tempo que senha errada: a conferencia
// contra o hash falso tem o mesmo custo. Compara medianas, que o ruido do
// escalonador nao desloca.
func TestLatenciaSemUsuario(t *testing.T) {
	if testing.Short() {
		t.Skip("mede tempo")
	}
	s := &senha.Senhas{Guarda: &guarda{c: map[string]senha.Credencial{}}}
	h, _ := s.Gerar("senha-boa-de-verdade", "")
	s.Guarda.(*guarda).c["ana"] = senha.Credencial{Hash: h}
	ctx := context.Background()
	s.Entrar(ctx, "ninguem", "aquecer") // gera o hash falso fora da medida

	mediana := func(login string) time.Duration {
		var d []time.Duration
		for i := 0; i < 15; i++ {
			t0 := time.Now()
			s.Entrar(ctx, login, "senha-errada")
			d = append(d, time.Since(t0))
		}
		for i := range d {
			for j := i + 1; j < len(d); j++ {
				if d[j] < d[i] {
					d[i], d[j] = d[j], d[i]
				}
			}
		}
		return d[len(d)/2]
	}
	com, sem := mediana("ana"), mediana("ninguem")
	razao := float64(sem) / float64(com)
	t.Logf("com usuario %v, sem usuario %v (razao %.2f)", com, sem, razao)
	if razao < 0.7 || razao > 1.4 {
		t.Fatalf("latencias diferentes demais: com %v, sem %v", com, sem)
	}
	// E sem o hash falso, a diferenca seria gritante: confirma que a medida
	// enxerga o que diz proteger.
	if com < 2*time.Millisecond {
		t.Fatalf("argon2id rapido demais (%v): a medida nao distingue nada", com)
	}
}

func TestRegras(t *testing.T) {
	r := senha.Regras{Proibidas: []string{"12345678"}, SemLogin: true}
	casos := map[string]string{
		"curta":                  "minimo",
		"12345678":               "proibida",
		"anabeatriz2026":         "login",
		strings.Repeat("a", 129): "maximo",
		"umasenhaboa":            "",
	}
	for s, quer := range casos {
		err := r.Conferir(s, "anabeatriz@x.com")
		var f *senha.Fraca
		if quer == "" {
			if err != nil {
				t.Errorf("%q: %v", s, err)
			}
			continue
		}
		if !errors.As(err, &f) || f.Regra != quer {
			t.Errorf("%q: quero %s, veio %v", s, quer, err)
		}
	}
	exige := senha.Regras{ExigirNumero: true, ExigirMaiuscula: true, ExigirSimbolo: true}
	if err := exige.Conferir("semnumero", ""); err == nil || err.(*senha.Fraca).Regra != "numero" {
		t.Errorf("numero: %v", err)
	}
	if err := exige.Conferir("Com1numero!", ""); err != nil {
		t.Errorf("completa: %v", err)
	}
	// Mede em caracteres, nao em bytes.
	if err := (senha.Regras{}).Conferir("ção ção", ""); err == nil {
		t.Error("7 caracteres deviam ser poucos")
	}
}

func TestGerarConfereRegras(t *testing.T) {
	s := &senha.Senhas{}
	if _, err := s.Gerar("curta", ""); err == nil {
		t.Fatal("Gerar devia aplicar as regras")
	}
}
