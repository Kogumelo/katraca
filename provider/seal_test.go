package provider_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/provider"
)

var (
	keyA = bytes.Repeat([]byte{'a'}, 32)
	keyB = bytes.Repeat([]byte{'b'}, 32)
)

func testPending(now time.Time) provider.Pending {
	return provider.Pending{Provider: "google", State: "state", Verifier: "pkce-verifier", Nonce: "nonce", Created: now}
}

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestSealRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &provider.Sealer{Keys: [][]byte{keyA}, Now: clock(&now)}
	p := testPending(now)
	seal, err := s.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seal, "verifier") || strings.Contains(seal, "state") {
		t.Fatalf("seal reveals the pending: %s", seal)
	}
	other, _ := s.Seal(p)
	if other == seal {
		t.Fatal("two seals of the same pending came out equal: the GCM nonce does not change")
	}
	back, err := s.Open(seal)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Created.Equal(p.Created) || back.State != p.State || back.Verifier != p.Verifier ||
		back.Nonce != p.Nonce || back.Provider != p.Provider {
		t.Fatalf("got back %+v, sent %+v", back, p)
	}
}

func TestSealTampered(t *testing.T) {
	s := &provider.Sealer{Keys: [][]byte{keyA}}
	seal, err := s.Seal(testPending(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	prefix, body, _ := strings.Cut(seal, ".")
	box, _ := base64.RawURLEncoding.DecodeString(body)
	for i := range box {
		flipped := bytes.Clone(box)
		flipped[i] ^= 0x01
		_, err := s.Open(prefix + "." + base64.RawURLEncoding.EncodeToString(flipped))
		if !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("byte %d tampered: err = %v", i, err)
		}
	}
	for _, junk := range []string{"", "k1.", "k1.!!!", "k2" + seal[2:], seal[:len(seal)-4], "k1." + strings.Repeat("A", 4000)} {
		if _, err := s.Open(junk); !errors.Is(err, katraca.ErrRejected) {
			t.Fatalf("Open(%.20q): err = %v", junk, err)
		}
	}
}

func TestSealFromAnotherKey(t *testing.T) {
	seal, err := (&provider.Sealer{Keys: [][]byte{keyA}}).Seal(testPending(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&provider.Sealer{Keys: [][]byte{keyB}}).Open(seal)
	if !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestSealExpired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &provider.Sealer{Keys: [][]byte{keyA}, Now: clock(&now)}
	seal, err := s.Seal(testPending(now))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(provider.PendingTTL)
	if _, err := s.Open(seal); err != nil {
		t.Fatalf("at the last second of the deadline: %v", err)
	}
	now = now.Add(time.Second)
	_, err = s.Open(seal)
	if !errors.Is(err, katraca.ErrExpired) || !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestSealRotation(t *testing.T) {
	seal, err := (&provider.Sealer{Keys: [][]byte{keyA}}).Seal(testPending(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	rotated := &provider.Sealer{Keys: [][]byte{keyB, keyA}}
	if _, err := rotated.Open(seal); err != nil {
		t.Fatalf("seal from the old key did not open with the new list: %v", err)
	}
	// The new list seals with the first key: the old key, alone, no longer opens.
	newSeal, err := rotated.Seal(testPending(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&provider.Sealer{Keys: [][]byte{keyB}}).Open(newSeal); err != nil {
		t.Fatalf("new seal did not open with the new key: %v", err)
	}
	if _, err := (&provider.Sealer{Keys: [][]byte{keyA}}).Open(newSeal); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("new seal opened with the old key: %v", err)
	}
}

func TestSealShortKey(t *testing.T) {
	for _, keys := range [][][]byte{nil, {keyA[:31]}, {keyA, keyB[:16]}} {
		s := &provider.Sealer{Keys: keys}
		if _, err := s.Seal(testPending(time.Now())); !errors.Is(err, provider.ErrShortKey) {
			t.Fatalf("Seal with %d keys: err = %v", len(keys), err)
		}
		if _, err := s.Open("k1.anything"); !errors.Is(err, provider.ErrShortKey) {
			t.Fatalf("Open with %d keys: err = %v", len(keys), err)
		}
	}
}

func TestSealCookie(t *testing.T) {
	now := time.Now()
	s := &provider.Sealer{Keys: [][]byte{keyA}, Now: clock(&now)}
	p := testPending(now.Add(-time.Minute))

	out := httptest.NewRecorder()
	if err := s.SetCookie(out, "/callback/", p); err != nil {
		t.Fatal(err)
	}
	cs := out.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies = %v", cs)
	}
	c := cs[0]
	if c.Name != provider.CookieName || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/callback/" || c.MaxAge != int((provider.PendingTTL-time.Minute).Seconds()) {
		t.Fatalf("cookie with wrong attributes: %+v", c)
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/google?state=state", nil)
	req.AddCookie(c)
	back := httptest.NewRecorder()
	got, err := s.ReadCookie(back, req, "/callback/")
	if err != nil || got.State != p.State {
		t.Fatalf("ReadCookie = %+v, %v", got, err)
	}
	deleted := back.Result().Cookies()
	if len(deleted) != 1 || deleted[0].MaxAge >= 0 || deleted[0].Path != "/callback/" {
		t.Fatalf("ReadCookie did not delete the cookie: %+v", deleted)
	}

	noCookie := httptest.NewRequest(http.MethodGet, "/callback/google", nil)
	if _, err := s.ReadCookie(httptest.NewRecorder(), noCookie, "/callback/"); !errors.Is(err, katraca.ErrRejected) {
		t.Fatalf("callback without cookie: err = %v", err)
	}
}
