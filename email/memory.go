package email

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/Kogumelo/katraca"
)

// Memory is an in-memory Store, for tests and prototypes. It vanishes when
// the process dies, and shares nothing between two processes: do not use it
// in production.
type Memory struct {
	mu        sync.Mutex
	issuances []*memoryIssuance
}

type memoryIssuance struct {
	Issuance
	used bool
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Issue(_ context.Context, e Issuance, max int, since time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.issuances {
		if x.Email == e.Email && x.Created.After(since) {
			n++
		}
	}
	if n >= max {
		return katraca.ErrTooManyRequests
	}
	if e.Kind == Code {
		for _, x := range m.issuances {
			if x.Email == e.Email && x.Purpose == e.Purpose && x.Kind == Code {
				x.used = true
			}
		}
	}
	e.Attempts = 0
	m.issuances = append(m.issuances, &memoryIssuance{Issuance: e})
	return nil
}

func (m *Memory) ConsumeLink(_ context.Context, hash []byte, p Purpose) (Issuance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.issuances {
		if x.Kind == Link && x.Purpose == p && !x.used && subtle.ConstantTimeCompare(x.Hash, hash) == 1 {
			x.used = true
			return x.Issuance, nil
		}
	}
	return Issuance{}, ErrNotFound
}

func (m *Memory) AttemptCode(_ context.Context, email string, p Purpose, since time.Time) (Issuance, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var found *memoryIssuance
	for _, x := range m.issuances {
		if x.Kind == Code && x.Email == email && x.Purpose == p && !x.used {
			if found == nil || x.Created.After(found.Created) {
				found = x
			}
		}
	}
	if found == nil {
		return Issuance{}, 0, ErrNotFound
	}
	found.Attempts++
	today := 0
	for _, x := range m.issuances {
		if x.Kind == Code && x.Email == email && x.Created.After(since) {
			today += x.Attempts
		}
	}
	return found.Issuance, today, nil
}

func (m *Memory) Consume(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.issuances {
		if x.ID == id {
			if x.used {
				return false, nil
			}
			x.used = true
			return true, nil
		}
	}
	return false, nil
}
