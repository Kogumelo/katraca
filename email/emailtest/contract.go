// Package emailtest checks whether an email.Store honors the contract:
// expiry, single use, per-address limit, attempt limit and purpose. Whoever
// writes their own Store runs Contract against it.
package emailtest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
)

// Clock is a test clock that only moves when told to.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Inbox is a Mailer that keeps the messages instead of sending them.
type Inbox struct {
	mu       sync.Mutex
	Messages []email.Message
}

func (in *Inbox) Send(_ context.Context, m email.Message) error {
	in.mu.Lock()
	in.Messages = append(in.Messages, m)
	in.mu.Unlock()
	return nil
}

// Last returns the last message delivered.
func (in *Inbox) Last(t testing.TB) email.Message {
	t.Helper()
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.Messages) == 0 {
		t.Fatal("no message delivered")
	}
	return in.Messages[len(in.Messages)-1]
}

// Contract runs the cases against new Stores, one per subtest. The store
// may share the database between subtests: each one uses its own addresses.
func Contract(t *testing.T, newStore func(t *testing.T) email.Store) {
	ctx := context.Background()
	setup := func(t *testing.T) (*email.Prover, *Inbox, *Clock) {
		// The clock starts from the real now, rounded: a database Store
		// may stamp with its own clock, and the test should not fight
		// that.
		c := &Clock{t: time.Now().Truncate(time.Second)}
		in := &Inbox{}
		p, err := email.New(newStore(t), in, email.Config{Now: c.Now, Key: []byte("test key, never use in production")})
		if err != nil {
			t.Fatal(err)
		}
		return p, in, c
	}
	address := func(t *testing.T) string {
		return "Person." + time.Now().Format("150405.000000000") + "@Example.com"
	}

	t.Run("link is valid once and gives a verified email", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendLink(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		m := in.Last(t)
		if m.Kind != email.Link || m.Token == "" || m.Code != "" {
			t.Fatalf("wrong link message: %+v", m)
		}
		id, err := p.VerifyLink(ctx, m.Token, email.SignIn)
		if err != nil {
			t.Fatal(err)
		}
		norm, _ := katraca.NormalizeEmail(addr)
		if id.Provider != "email" || id.ID != norm || id.Email != norm || !id.EmailVerified {
			t.Fatalf("wrong identity: %+v", id)
		}
		if _, err := p.VerifyLink(ctx, m.Token, email.SignIn); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("second use: want ErrRejected, got %v", err)
		}
	})

	t.Run("expired link", func(t *testing.T) {
		p, in, c := setup(t)
		if err := p.SendLink(ctx, address(t), email.SignIn); err != nil {
			t.Fatal(err)
		}
		c.Advance(15*time.Minute + time.Second)
		_, err := p.VerifyLink(ctx, in.Last(t).Token, email.SignIn)
		if !errors.Is(err, katraca.ErrExpired) || !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
	})

	t.Run("link for another purpose is not valid", func(t *testing.T) {
		p, in, _ := setup(t)
		if err := p.SendLink(ctx, address(t), email.Confirm); err != nil {
			t.Fatal(err)
		}
		tok := in.Last(t).Token
		if _, err := p.VerifyLink(ctx, tok, email.Reset); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
		// And the wrong attempt did not consume it.
		if _, err := p.VerifyLink(ctx, tok, email.Confirm); err != nil {
			t.Fatalf("the confirm link should be valid: %v", err)
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		p, _, _ := setup(t)
		for _, tok := range []string{"", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			if _, err := p.VerifyLink(ctx, tok, email.SignIn); !errors.Is(err, katraca.ErrRejected) {
				t.Fatalf("token %q: want ErrRejected, got %v", tok, err)
			}
		}
	})

	t.Run("per-address limit adds up links and codes", func(t *testing.T) {
		p, _, c := setup(t)
		addr := address(t)
		if err := p.SendLink(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		if err := p.SendCode(ctx, addr, email.Reset); err != nil {
			t.Fatal(err)
		}
		// Different purpose, same address: the limit belongs to the address.
		if err := p.SendLink(ctx, addr, email.Confirm); err != nil {
			t.Fatal(err)
		}
		if err := p.SendLink(ctx, addr, email.SignIn); !errors.Is(err, katraca.ErrTooManyRequests) {
			t.Fatalf("fourth request: want ErrTooManyRequests, got %v", err)
		}
		// Another address is not affected.
		if err := p.SendLink(ctx, "other."+addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		c.Advance(15*time.Minute + time.Second)
		if err := p.SendLink(ctx, addr, email.SignIn); err != nil {
			t.Fatalf("after the window it should pass: %v", err)
		}
	})

	t.Run("code is valid once", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.Reset); err != nil {
			t.Fatal(err)
		}
		m := in.Last(t)
		if m.Kind != email.Code || len(m.Code) != 6 || m.Token != "" {
			t.Fatalf("wrong code message: %+v", m)
		}
		// With a space in the middle, as the person types it.
		id, err := p.VerifyCode(ctx, addr, m.Code[:3]+" "+m.Code[3:], email.Reset)
		if err != nil {
			t.Fatal(err)
		}
		if !id.EmailVerified {
			t.Fatal("the right code should verify the email")
		}
		if _, err := p.VerifyCode(ctx, addr, m.Code, email.Reset); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("second use: want ErrRejected, got %v", err)
		}
	})

	t.Run("attempt limit", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		right := in.Last(t).Code
		wrong := "000000"
		if right == wrong {
			wrong = "111111"
		}
		for i := 0; i < 6; i++ {
			if _, err := p.VerifyCode(ctx, addr, wrong, email.SignIn); !errors.Is(err, katraca.ErrRejected) {
				t.Fatalf("attempt %d: want ErrRejected, got %v", i+1, err)
			}
		}
		_, err := p.VerifyCode(ctx, addr, right, email.SignIn)
		if !errors.Is(err, katraca.ErrTooManyAttempts) {
			t.Fatalf("right code after the limit: want ErrTooManyAttempts, got %v", err)
		}
	})

	t.Run("expired code", func(t *testing.T) {
		p, in, c := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		c.Advance(15*time.Minute + time.Second)
		_, err := p.VerifyCode(ctx, addr, in.Last(t).Code, email.SignIn)
		if !errors.Is(err, katraca.ErrExpired) {
			t.Fatalf("want ErrExpired, got %v", err)
		}
	})

	t.Run("new code drops the previous one and resets attempts", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		old := in.Last(t).Code
		for i := 0; i < 5; i++ {
			p.VerifyCode(ctx, addr, "999999", email.SignIn)
		}
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		fresh := in.Last(t).Code
		if old != fresh {
			if _, err := p.VerifyCode(ctx, addr, old, email.SignIn); !errors.Is(err, katraca.ErrRejected) {
				t.Fatalf("old code: want ErrRejected, got %v", err)
			}
		}
		if _, err := p.VerifyCode(ctx, addr, fresh, email.SignIn); err != nil {
			t.Fatalf("the new code should be valid: %v", err)
		}
	})

	t.Run("code for another purpose or another address is not valid", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.Confirm); err != nil {
			t.Fatal(err)
		}
		code := in.Last(t).Code
		if _, err := p.VerifyCode(ctx, addr, code, email.SignIn); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("another purpose: want ErrRejected, got %v", err)
		}
		if _, err := p.VerifyCode(ctx, "x"+addr, code, email.Confirm); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("another address: want ErrRejected, got %v", err)
		}
	})

	t.Run("two simultaneous clicks, one wins", func(t *testing.T) {
		p, in, _ := setup(t)
		if err := p.SendLink(ctx, address(t), email.SignIn); err != nil {
			t.Fatal(err)
		}
		tok := in.Last(t).Token
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := p.VerifyLink(ctx, tok, email.SignIn); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d clicks won; want 1", ok)
		}
	})

	t.Run("limit holds with simultaneous attempts", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		right := in.Last(t).Code
		wrong := "000000"
		if right == wrong {
			wrong = "111111"
		}
		// Each attempt must see the sum of the others: with a lost count,
		// twenty guesses at the same time would pass as six.
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.VerifyCode(ctx, addr, wrong, email.SignIn)
			}()
		}
		wg.Wait()
		if _, err := p.VerifyCode(ctx, addr, right, email.SignIn); !errors.Is(err, katraca.ErrTooManyAttempts) {
			t.Fatalf("right code after 20 simultaneous guesses: want ErrTooManyAttempts, got %v", err)
		}
	})

	t.Run("simultaneous right code, one wins", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		code := in.Last(t).Code
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := p.VerifyCode(ctx, addr, code, email.SignIn); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d verifications won; want 1", ok)
		}
	})

	t.Run("daily guess limit per address", func(t *testing.T) {
		p, in, c := setup(t)
		addr := address(t)
		// Five codes, one every 16 minutes (outside the send limit
		// window), with six wrong guesses each: thirty in the day.
		for i := 0; i < 5; i++ {
			if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
				t.Fatal(err)
			}
			wrong := "000000"
			if in.Last(t).Code == wrong {
				wrong = "111111"
			}
			for j := 0; j < 6; j++ {
				p.VerifyCode(ctx, addr, wrong, email.SignIn)
			}
			c.Advance(16 * time.Minute)
		}
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		if _, err := p.VerifyCode(ctx, addr, in.Last(t).Code, email.SignIn); !errors.Is(err, katraca.ErrTooManyAttempts) {
			t.Fatalf("after 30 guesses in the day: want ErrTooManyAttempts, got %v", err)
		}
		// Once the day is over, it is valid again.
		c.Advance(24 * time.Hour)
		if err := p.SendCode(ctx, addr, email.SignIn); err != nil {
			t.Fatal(err)
		}
		if _, err := p.VerifyCode(ctx, addr, in.Last(t).Code, email.SignIn); err != nil {
			t.Fatalf("on the next day it should be valid: %v", err)
		}
	})

	t.Run("limit holds with simultaneous requests", func(t *testing.T) {
		p, in, _ := setup(t)
		addr := address(t)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.SendLink(ctx, addr, email.SignIn)
			}()
		}
		wg.Wait()
		if n := len(in.Messages); n != 3 {
			t.Fatalf("%d messages went out; the limit is 3", n)
		}
	})
}
