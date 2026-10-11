package pgkatraca_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/email/emailteste"
	"github.com/Kogumelo/katraca/pgkatraca"
	"github.com/Kogumelo/katraca/senha"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// Os testes daqui precisam de um Postgres descartavel:
//
//	KATRACA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test ./pgkatraca/
//
// Sem a variavel, pulam.
func guarda(t *testing.T) *pgkatraca.Guarda {
	t.Helper()
	u := os.Getenv("KATRACA_PG_URL")
	if u == "" {
		t.Skip("KATRACA_PG_URL vazia: sem Postgres para testar")
	}
	pool, err := pgxpool.New(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	g := &pgkatraca.Guarda{Banco: pool}
	if err := g.CriarTabelas(context.Background()); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestContratoDaProva(t *testing.T) {
	g := guarda(t)
	emailteste.Contrato(t, func(*testing.T) email.Guarda { return g })
}

func TestSenhaNoBanco(t *testing.T) {
	g := guarda(t)
	ctx := context.Background()
	login := "zebra." + strings.ReplaceAll(t.Name(), "/", ".")
	b, _ := bcrypt.GenerateFromPassword([]byte("antiga-do-zebra"), bcrypt.MinCost)
	if err := g.GravarSenha(ctx, login, string(b), senha.Credencial{Email: "z@x.com", EmailGarantido: true}); err != nil {
		t.Fatal(err)
	}
	s := &senha.Senhas{Guarda: g}
	id, trocado, err := s.Entrar(ctx, login, "antiga-do-zebra")
	if err != nil || !trocado || !id.EmailGarantido {
		t.Fatalf("id=%+v trocado=%v err=%v", id, trocado, err)
	}
	c, _ := g.Credencial(ctx, login)
	if !strings.HasPrefix(c.Hash, "$argon2id$") {
		t.Fatalf("hash nao migrou: %s", c.Hash)
	}
	if _, _, err := s.Entrar(ctx, login+"-ninguem", "x"); !errors.Is(err, katraca.ErrRecusado) {
		t.Fatalf("sem usuario: %v", err)
	}
}
