package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kogumelo/katraca"
)

// MinKeySize is the smallest size, in bytes, accepted for a Sealer key.
// Generate it with 32 bytes from crypto/rand; a typed password will not do.
const MinKeySize = 32

// ErrShortKey is an app configuration error, not a proof rejection: the
// Sealer has no key at all, or a key shorter than MinKeySize bytes.
var ErrShortKey = fmt.Errorf("provider: sealer key needs %d bytes or more", MinKeySize)

// Sealer keeps the Pending in the browser without it being readable or
// swappable: the Pending goes encrypted and authenticated (AES-256-GCM), with
// the deadline inside. The PKCE verifier and the nonce do not show in the
// cookie.
//
// Keys[0] seals; all of them open. To rotate keys, put the new one in front
// and keep the old one behind it for one PendingTTL; then remove the old one.
type Sealer struct {
	Keys [][]byte
	Now  func() time.Time
}

// sealVersion prefixes every seal and goes into the AEAD associated data: a
// seal of another format, or from another use of the same key, does not
// open here.
const sealVersion = "k1"

// maxSealSize is the largest seal Open reads. A sealed Pending is about 350
// characters; anything beyond that is garbage or an attack.
const maxSealSize = 2048

// sealed is what goes encrypted: the Pending and the end of the deadline.
type sealed struct {
	Pending
	Expires int64 `json:"x"`
}

func (s *Sealer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// aeads builds one AES-256-GCM per key. The AES key is not the app's key: it
// comes from an HMAC of it with the sealer label, so the same app key can
// serve another use without one turning into the other.
func (s *Sealer) aeads() ([]cipher.AEAD, error) {
	if len(s.Keys) == 0 {
		return nil, ErrShortKey
	}
	as := make([]cipher.AEAD, 0, len(s.Keys))
	for _, key := range s.Keys {
		if len(key) < MinKeySize {
			return nil, ErrShortKey
		}
		m := hmac.New(sha256.New, key)
		m.Write([]byte("katraca/provider/seal/" + sealVersion))
		block, err := aes.NewCipher(m.Sum(nil))
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		as = append(as, a)
	}
	return as, nil
}

// Seal encrypts p with Keys[0]. The seal expires at p.Created + PendingTTL,
// the same deadline Complete checks. The result fits in a cookie.
func (s *Sealer) Seal(p Pending) (string, error) {
	as, err := s.aeads()
	if err != nil {
		return "", err
	}
	if p.Created.IsZero() {
		p.Created = s.now()
	}
	plain, err := json.Marshal(sealed{Pending: p, Expires: p.Created.Add(PendingTTL).Unix()})
	if err != nil {
		return "", err
	}
	a := as[0]
	nonce := make([]byte, a.NonceSize())
	rand.Read(nonce)
	box := a.Seal(nonce, nonce, plain, []byte(sealVersion))
	return sealVersion + "." + base64.RawURLEncoding.EncodeToString(box), nil
}

// Open checks and decrypts a seal from Seal with any of the Keys. A seal
// that was tampered with, made with another key or of another format wraps
// katraca.ErrRejected; an expired seal returns katraca.ErrExpired, which
// wraps it too.
func (s *Sealer) Open(seal string) (Pending, error) {
	as, err := s.aeads()
	if err != nil {
		return Pending{}, err
	}
	reject := fmt.Errorf("%w: invalid pending seal", katraca.ErrRejected)
	body, ok := strings.CutPrefix(seal, sealVersion+".")
	if !ok || len(seal) > maxSealSize {
		return Pending{}, reject
	}
	box, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Pending{}, reject
	}
	// GCM checks the tag in constant time; the order of the keys only tells
	// how many attempts were made, and the attacker already knows that.
	for _, a := range as {
		n := a.NonceSize()
		if len(box) < n+a.Overhead() {
			return Pending{}, reject
		}
		plain, err := a.Open(nil, box[:n], box[n:], []byte(sealVersion))
		if err != nil {
			continue
		}
		var v sealed
		if err := json.Unmarshal(plain, &v); err != nil {
			return Pending{}, reject
		}
		if s.now().Unix() > v.Expires {
			return Pending{}, katraca.ErrExpired
		}
		return v.Pending, nil
	}
	return Pending{}, reject
}

// CookieName is the cookie SetCookie and ReadCookie use.
const CookieName = "katraca_pending"

// SetCookie seals p and sets it in an HttpOnly, Secure, SameSite=Lax cookie,
// restricted to path (the callback prefix, such as "/callback/") and living
// until the end of the deadline. SameSite=Lax lets the cookie go along on a
// GET callback; for form_post (a POST coming from the provider) it does not,
// and the app stores the seal some other way.
//
// Secure also works on http://localhost in Chrome and Firefox; Safari wants
// https even there.
func (s *Sealer) SetCookie(w http.ResponseWriter, path string, p Pending) error {
	if p.Created.IsZero() {
		p.Created = s.now()
	}
	v, err := s.Seal(p)
	if err != nil {
		return err
	}
	maxAge := int(p.Created.Add(PendingTTL).Sub(s.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: v, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// ReadCookie opens the seal in the cookie and deletes it in the browser: the
// Pending serves a single callback. path is the same one given to SetCookie.
// A callback without the cookie wraps katraca.ErrRejected.
func (s *Sealer) ReadCookie(w http.ResponseWriter, r *http.Request, path string) (Pending, error) {
	c, err := r.Cookie(CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return Pending{}, fmt.Errorf("%w: callback without pending", katraca.ErrRejected)
	}
	if err != nil {
		return Pending{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Path: path, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return s.Open(c.Value)
}
