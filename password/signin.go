package password

import (
	"context"
	"errors"
	"sync"

	"github.com/Kogumelo/katraca"
)

// Credential is what the app stores for a password.
type Credential struct {
	Hash string
	// Email and EmailVerified pass straight into the Identity: if the login
	// is an email address the app has already confirmed (for example, with
	// email.Confirm), it says so here. A password alone proves no email.
	Email         string
	EmailVerified bool
}

// ErrNotFound is what the Store returns when the login does not exist.
var ErrNotFound = errors.New("password: login has no password")

// Store is where the app keeps the hashes. Almost always in its own users
// table.
type Store interface {
	// Credential returns what there is for the login (already normalized by
	// the app), or ErrNotFound.
	Credential(ctx context.Context, login string) (Credential, error)
	// ReplaceHash stores newHash in place of oldHash, only if the stored one is
	// still oldHash. It is called after a successful sign-in with a hash to replace.
	ReplaceHash(ctx context.Context, login, oldHash, newHash string) error
}

// Passwords ties together parameters, rules and Store.
type Passwords struct {
	Store  Store
	Params Params // zero means Default
	Rules  Rules
	// DummyHash is the hash verified when the login does not exist. Empty, it
	// is an argon2id with Params. During a migration from bcrypt, while most
	// stored hashes are still bcrypt (slower), put a bcrypt of the same cost
	// here: the dummy should cost what the typical one costs.
	DummyHash string

	dummyOnce sync.Once
	dummy     string
}

// SignIn verifies login and password. A nonexistent login and a wrong
// password give the same katraca.ErrRejected and take the same time: with a
// nonexistent login, the password is verified against a dummy hash with the
// same parameters.
//
// If the stored hash is bcrypt or weak argon2id, SignIn stores a new one
// through the Store and reports rehashed=true. A failure in that replacement
// does not block the sign-in: the login was valid, and the replacement tries
// again next time.
func (s *Passwords) SignIn(ctx context.Context, login, password string) (id katraca.Identity, rehashed bool, err error) {
	if s.Store == nil {
		return katraca.Identity{}, false, errors.New("password: Store is required")
	}
	c, err := s.Store.Credential(ctx, login)
	if errors.Is(err, ErrNotFound) {
		s.VerifyWithoutUser(password)
		return katraca.Identity{}, false, katraca.ErrRejected
	}
	if err != nil {
		return katraca.Identity{}, false, err
	}
	ok, rehash, err := s.Params.Verify(c.Hash, password)
	if err != nil {
		return katraca.Identity{}, false, err
	}
	if !ok {
		return katraca.Identity{}, false, katraca.ErrRejected
	}
	if rehash {
		if h, err := s.Params.Hash(password); err == nil {
			rehashed = s.Store.ReplaceHash(ctx, login, c.Hash, h) == nil
		}
	}
	return katraca.Identity{
		Provider:      "password",
		ID:            login,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
	}, rehashed, nil
}

// Hash checks the rules and returns the hash for the app to store (sign-up,
// password change, reset).
func (s *Passwords) Hash(password, login string) (string, error) {
	if err := s.Rules.Check(password, login); err != nil {
		return "", err
	}
	return s.Params.Hash(password)
}

// VerifyWithoutUser spends the time of a real verification. The app that
// does not use SignIn calls this when the login does not exist.
func (s *Passwords) VerifyWithoutUser(password string) {
	s.dummyOnce.Do(func() {
		s.dummy = s.DummyHash
		if s.dummy == "" {
			s.dummy, _ = s.Params.Hash("a password nobody has")
		}
	})
	s.Params.Verify(s.dummy, password)
}
