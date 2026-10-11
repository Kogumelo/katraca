package password_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/password"
	"golang.org/x/crypto/bcrypt"
)

func TestArgon2idRoundTrip(t *testing.T) {
	h, err := password.Default.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected format: %s", h)
	}
	ok, rehash, err := password.Default.Verify(h, "correct horse battery staple")
	if err != nil || !ok || rehash {
		t.Fatalf("right: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = password.Default.Verify(h, "correct horse battery staplE")
	if err != nil || ok {
		t.Fatalf("wrong: ok=%v err=%v", ok, err)
	}
	// Two hashes of the same password differ: the salt is random.
	h2, _ := password.Default.Hash("correct horse battery staple")
	if h == h2 {
		t.Fatal("repeated salt")
	}
}

func TestBcryptVerifiesAndAsksForRehash(t *testing.T) {
	b, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	ok, rehash, err := password.Default.Verify(string(b), "secret123")
	if err != nil || !ok || !rehash {
		t.Fatalf("bcrypt right: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, rehash, err = password.Default.Verify(string(b), "secret124")
	if err != nil || ok || rehash {
		t.Fatalf("bcrypt wrong: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	// $2y$ (PHP) too.
	y := "$2y$" + string(b)[4:]
	if ok, _, err := password.Default.Verify(y, "secret123"); err != nil || !ok {
		t.Fatalf("$2y$: ok=%v err=%v", ok, err)
	}
}

func TestWeakArgon2idAsksForRehash(t *testing.T) {
	weak := password.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}
	h, _ := weak.Hash("abc")
	ok, rehash, err := password.Default.Verify(h, "abc")
	if err != nil || !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestUnknownHash(t *testing.T) {
	for _, h := range []string{"", "plain text", "$argon2id$v=19$m=1,t=1$x$y", "$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", "$1$md5"} {
		if _, _, err := password.Default.Verify(h, "x"); !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("%q: want ErrInvalidHash, got %v", h, err)
		}
	}
}

type store struct {
	mu sync.Mutex
	c  map[string]password.Credential
}

func (s *store) Credential(_ context.Context, login string) (password.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.c[login]
	if !ok {
		return password.Credential{}, password.ErrNotFound
	}
	return c, nil
}

func (s *store) ReplaceHash(_ context.Context, login, oldHash, newHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.c[login]; c.Hash == oldHash {
		c.Hash = newHash
		s.c[login] = c
	}
	return nil
}

func TestSignInMigratesFromBcrypt(t *testing.T) {
	b, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	st := &store{c: map[string]password.Credential{"ana@x.com": {Hash: string(b), Email: "ana@x.com"}}}
	p := &password.Passwords{Store: st}
	ctx := context.Background()

	id, rehashed, err := p.SignIn(ctx, "ana@x.com", "secret123")
	if err != nil || !rehashed {
		t.Fatalf("rehashed=%v err=%v", rehashed, err)
	}
	if id.Provider != "password" || id.ID != "ana@x.com" || id.EmailVerified {
		t.Fatalf("identity: %+v", id)
	}
	if !strings.HasPrefix(st.c["ana@x.com"].Hash, "$argon2id$") {
		t.Fatalf("hash did not migrate: %s", st.c["ana@x.com"].Hash)
	}
	// Second time: already argon2id, nothing to replace.
	if _, rehashed, err := p.SignIn(ctx, "ana@x.com", "secret123"); err != nil || rehashed {
		t.Fatalf("second: rehashed=%v err=%v", rehashed, err)
	}
	if _, _, err := p.SignIn(ctx, "ana@x.com", "wrong"); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("wrong: %v", err)
	}
	if _, _, err := p.SignIn(ctx, "bia@x.com", "secret123"); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("no user: %v", err)
	}
}

// A nonexistent login takes the same time as a wrong password: verification
// against the dummy hash has the same cost. It compares medians, which
// scheduler noise does not shift.
func TestLatencyWithoutUser(t *testing.T) {
	if testing.Short() {
		t.Skip("measures time")
	}
	p := &password.Passwords{Store: &store{c: map[string]password.Credential{}}}
	h, _ := p.Hash("a-really-good-password", "")
	p.Store.(*store).c["ana"] = password.Credential{Hash: h}
	ctx := context.Background()
	p.SignIn(ctx, "nobody", "warm up") // builds the dummy hash outside the measurement

	median := func(login string) time.Duration {
		var d []time.Duration
		for i := 0; i < 15; i++ {
			t0 := time.Now()
			p.SignIn(ctx, login, "wrong-password")
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
	with, without := median("ana"), median("nobody")
	ratio := float64(without) / float64(with)
	t.Logf("with user %v, without user %v (ratio %.2f)", with, without, ratio)
	if ratio < 0.7 || ratio > 1.4 {
		t.Fatalf("latencies too different: with %v, without %v", with, without)
	}
	// And without the dummy hash, the difference would be glaring: confirms
	// that the measurement sees what it claims to protect.
	if with < 2*time.Millisecond {
		t.Fatalf("argon2id too fast (%v): the measurement tells nothing apart", with)
	}
}

func TestRules(t *testing.T) {
	r := password.Rules{Forbidden: []string{"12345678"}, NoLogin: true}
	cases := map[string]password.Rule{
		"short":                  password.RuleMinLength,
		"12345678":               password.RuleForbidden,
		"anabeatriz2026":         password.RuleLogin,
		strings.Repeat("a", 129): password.RuleMaxLength,
		"agoodpassword":          "",
	}
	for pw, want := range cases {
		err := r.Check(pw, "anabeatriz@x.com")
		var w *password.Weak
		if want == "" {
			if err != nil {
				t.Errorf("%q: %v", pw, err)
			}
			continue
		}
		if !errors.As(err, &w) || w.Rule != want {
			t.Errorf("%q: want %s, got %v", pw, want, err)
		}
	}
	require := password.Rules{RequireDigit: true, RequireUpper: true, RequireSymbol: true}
	if err := require.Check("nodigithere", ""); err == nil || err.(*password.Weak).Rule != password.RuleDigit {
		t.Errorf("digit: %v", err)
	}
	if err := require.Check("With1digit!", ""); err != nil {
		t.Errorf("complete: %v", err)
	}
	// Counts characters, not bytes.
	if err := (password.Rules{}).Check("ção ção", ""); err == nil {
		t.Error("7 characters should be too few")
	}
}

func TestHashChecksRules(t *testing.T) {
	p := &password.Passwords{}
	if _, err := p.Hash("short", ""); err == nil {
		t.Fatal("Hash should apply the rules")
	}
}

// A hash with absurd parameters (written by someone who reached the database,
// or imported from another system) does not tie up the server: every sign-in
// attempt on that account, by anyone, would run the full cost.
func TestHashWithAbsurdCost(t *testing.T) {
	salt, h := "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases := map[string]string{
		"iterations":  "$argon2id$v=19$m=8,t=4000000000,p=1$" + salt + "$" + h,
		"memory":      "$argon2id$v=19$m=1048576,t=1,p=1$" + salt + "$" + h,
		"parallelism": "$argon2id$v=19$m=2048,t=1,p=255$" + salt + "$" + h,
		"length":      "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$" + strings.Repeat("A", 1<<20),
		"bcrypt 31":   "$2a$31$" + strings.Repeat("A", 53),
	}
	for name, hash := range cases {
		done := make(chan error, 1)
		go func() { _, _, err := password.Default.Verify(hash, "x"); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, password.ErrInvalidHash) {
				t.Errorf("%s: want ErrInvalidHash, got %v", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: verification took over 3 s", name)
		}
	}
	// And Hash does not produce a hash that Verify would reject.
	if _, err := (password.Params{Iterations: 1000}).Hash("x"); err == nil {
		t.Error("Hash accepted parameters above the ceiling")
	}
}
