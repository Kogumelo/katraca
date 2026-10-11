package pgkatraca_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/email/emailtest"
	"github.com/Kogumelo/katraca/password"
	"github.com/Kogumelo/katraca/pgkatraca"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// The tests here need a throwaway Postgres:
//
//	KATRACA_PG_URL=postgres://postgres:x@localhost:55432/postgres go test ./pgkatraca/
//
// Without the variable, they are skipped.
func store(t *testing.T) *pgkatraca.Store {
	t.Helper()
	u := os.Getenv("KATRACA_PG_URL")
	if u == "" {
		t.Skip("KATRACA_PG_URL is empty: no Postgres to test against")
	}
	pool, err := pgxpool.New(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s := &pgkatraca.Store{DB: pool}
	if err := s.CreateTables(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEmailProofContract(t *testing.T) {
	s := store(t)
	emailtest.Contract(t, func(*testing.T) email.Store { return s })
}

func TestPasswordInDB(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	login := "zebra." + strings.ReplaceAll(t.Name(), "/", ".")
	b, _ := bcrypt.GenerateFromPassword([]byte("zebra-old-one"), bcrypt.MinCost)
	if err := s.SetPassword(ctx, login, string(b), password.Credential{Email: "z@x.com", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	p := &password.Passwords{Store: s}
	id, rehashed, err := p.SignIn(ctx, login, "zebra-old-one")
	if err != nil || !rehashed || !id.EmailVerified {
		t.Fatalf("id=%+v rehashed=%v err=%v", id, rehashed, err)
	}
	c, _ := s.Credential(ctx, login)
	if !strings.HasPrefix(c.Hash, "$argon2id$") {
		t.Fatalf("hash was not migrated: %s", c.Hash)
	}
	if _, _, err := p.SignIn(ctx, login+"-nobody", "x"); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("unknown user: %v", err)
	}
}

// Replacing the hash is a compare-and-swap: if the password was reset between
// the read and the replacement, the new hash from the reset stays.
func TestReplaceHashDoesNotOverwriteReset(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	login := "cas." + time.Now().Format("150405.000000000")
	if err := s.SetPassword(ctx, login, "$2a$04$old", password.Credential{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, login, "$argon2id$reset", password.Credential{}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceHash(ctx, login, "$2a$04$old", "$argon2id$migrated"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Credential(ctx, login); c.Hash != "$argon2id$reset" {
		t.Fatalf("the migration overwrote the reset: %s", c.Hash)
	}
}
