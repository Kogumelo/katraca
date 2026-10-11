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
	"github.com/Kogumelo/katraca/email/emailtest"
)

func TestMemory(t *testing.T) {
	emailtest.Contract(t, func(*testing.T) email.Store { return email.NewMemory() })
}

func TestInvalidAddress(t *testing.T) {
	p, _ := email.New(email.NewMemory(), &emailtest.Inbox{}, testConfig())
	for _, e := range []string{"", "ana", "ana@x", "Ana <ana@x.com>", "a@x.com\r\nBcc: b@y.com", "a@x.com, b@y.com"} {
		if err := p.SendLink(context.Background(), e, email.SignIn); !errors.Is(err, katraca.ErrInvalidEmail) {
			t.Errorf("%q: want ErrInvalidEmail, got %v", e, err)
		}
	}
}

func TestUnknownPurpose(t *testing.T) {
	p, _ := email.New(email.NewMemory(), &emailtest.Inbox{}, testConfig())
	if err := p.SendLink(context.Background(), "a@b.com", "whatever"); err == nil {
		t.Fatal("unknown purpose should fail")
	}
}

// Without the server key, whoever reads the database finds the live code by
// trying the million codes against the hash. The key is required.
func TestNoKeyNoProver(t *testing.T) {
	if _, err := email.New(email.NewMemory(), &emailtest.Inbox{}, email.Config{}); !errors.Is(err, email.ErrShortKey) {
		t.Fatalf("no key: want ErrShortKey, got %v", err)
	}
	short := email.Config{Key: make([]byte, email.MinKeySize-1)}
	if _, err := email.New(email.NewMemory(), &emailtest.Inbox{}, short); !errors.Is(err, email.ErrShortKey) {
		t.Fatalf("short key: want ErrShortKey, got %v", err)
	}
}

// spy keeps the last Issuance, as the database would see it.
type spy struct {
	*email.Memory
	last email.Issuance
}

func (s *spy) Issue(ctx context.Context, x email.Issuance, max int, since time.Time) error {
	s.last = x
	return s.Memory.Issue(ctx, x, max, since)
}

// The stored hash does not come out of what is in the database alone:
// trying the million codes against sha256(id:code) finds nothing.
func TestCodeHashNeedsTheKey(t *testing.T) {
	s := &spy{Memory: email.NewMemory()}
	in := &emailtest.Inbox{}
	p, err := email.New(s, in, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.SendCode(ctx, "ana@example.com", email.SignIn); err != nil {
		t.Fatal(err)
	}
	code := in.Last(t).Code
	for i := 0; i < 1_000_000; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%06d", s.last.ID, i)))
		if bytes.Equal(h[:], s.last.Hash) {
			t.Fatalf("code %06d (sent %s) came out of the database without the key", i, code)
		}
	}
}
