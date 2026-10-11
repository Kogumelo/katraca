// Package email proves that the person reads a mailbox. There is a single
// proof, in two forms:
//
//   - Link: a long token goes inside a URL; whoever clicks it proves it.
//   - Code: six digits the person types; short, so it has an attempt
//     limit.
//
// And it serves three purposes: signing in, confirming a sign-up and
// resetting the password. A proof issued for one purpose is not valid for
// another.
//
// The library does not send email: it hands the Message to the app's Mailer,
// which builds the text, the link URL and the sender. Nor does it store
// anything: the Store belongs to the app (there is a reference one in
// pgkatraca). Of the secret, the Store only sees the hash.
package email

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Kogumelo/katraca"
)

// Purpose is what the proof was requested for.
type Purpose string

const (
	SignIn  Purpose = "sign_in"
	Confirm Purpose = "confirm"
	Reset   Purpose = "reset"
)

// Kind is the form the proof takes.
type Kind string

const (
	Link Kind = "link"
	Code Kind = "code"
)

// Issuance is an issued proof, as the Store sees it. No secret: only the hash.
type Issuance struct {
	ID       string // random, generated here
	Email    string // normalized
	Purpose  Purpose
	Kind     Kind
	Hash     []byte // sha256 of the token; for a code, HMAC-SHA256 with the app key of ID ":" code
	Created  time.Time
	Expires  time.Time
	Attempts int // codes only; the Store increments it in AttemptCode
}

// ErrNotFound is what the Store returns when there is no live issuance that fits.
var ErrNotFound = errors.New("email: no live issuance")

// MinKeySize is the smallest size, in bytes, accepted for Config.Key.
const MinKeySize = 32

// ErrShortKey is a configuration error: Config.Key empty or shorter than
// MinKeySize bytes.
var ErrShortKey = fmt.Errorf("email: Config.Key needs %d bytes or more", MinKeySize)

// DailyLimitWindow is the window of Config.DailyLimit.
const DailyLimitWindow = 24 * time.Hour

// Store persists issuances. Each method is atomic: that is what makes single
// use and the limits hold with two requests at the same time.
type Store interface {
	// Issue stores e. First it counts the issuances for the same email
	// created after since (any kind and purpose, used or not); if there are
	// already max, it does not store and returns katraca.ErrTooManyRequests.
	// Counting and storing are not separated. If e.Kind is Code, the unused
	// codes for the same email and purpose stop being valid.
	Issue(ctx context.Context, e Issuance, max int, since time.Time) error

	// ConsumeLink marks as used the link with the given hash and purpose, if
	// it was not yet, and returns it — expired or not; the library checks
	// the deadline. No unused link: ErrNotFound.
	ConsumeLink(ctx context.Context, hash []byte, p Purpose) (Issuance, error)

	// AttemptCode adds one attempt to the most recent unused code for the
	// email and purpose, and returns it with the attempt already added. It
	// also returns the total attempts, including this one, of the codes for
	// the same email (any purpose, used or not) created after since. Adding
	// and counting are not separated. No code: ErrNotFound.
	AttemptCode(ctx context.Context, email string, p Purpose, since time.Time) (Issuance, int, error)

	// Consume marks issuance id as used, if it was not yet. It returns false
	// if another request consumed it first.
	Consume(ctx context.Context, id string) (bool, error)
}

// Message is what the Mailer sends. Token is filled for Link, Code for
// Code. The app builds the link URL (preferably with the token in the
// fragment, "#", which never reaches any server) and the text.
type Message struct {
	To      string
	Purpose Purpose
	Kind    Kind
	Token   string // base64url, 43 characters
	Code    string // six digits
	Expires time.Time
}

// Mailer delivers the Message. It belongs to the app: SES, SMTP, whatever.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// MailerFunc lets a function serve as a Mailer.
type MailerFunc func(ctx context.Context, m Message) error

func (f MailerFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Config configures the proof. The zero value of each field means the
// default next to it.
type Config struct {
	LinkTTL time.Duration // 15 min
	CodeTTL time.Duration // 15 min
	// MaxPerWindow messages per email within Window, adding up links and
	// codes of all purposes. Without a limit, the route becomes a way to
	// flood someone's mailbox — and each message spends the domain's
	// reputation.
	MaxPerWindow int           // 3
	Window       time.Duration // 15 min
	// MaxAttempts per code. Six digits are a million possibilities; with 6
	// attempts per code and 3 codes per window, the chance of guessing right
	// is 18 in a million every 15 minutes.
	MaxAttempts int // 6
	// DailyLimit of code attempts per email in DailyLimitWindow, adding up
	// all codes and purposes. Without it, the 18 guesses every 15 minutes
	// never end: about a 5% chance of a hit in a month. Past the limit, not
	// even the right code is valid until the window moves on.
	DailyLimit int // 30
	// Key of the app, required: 32 bytes or more from crypto/rand. It goes
	// into the code hash, and without it whoever reads the database finds
	// the live code by trying the million codes. It may be the same as the
	// provider.Sealer's: each use derives its own. Changing the key drops
	// the unused codes.
	Key []byte
	// Now replaces the clock, for tests.
	Now func() time.Time
}

// Prover is the configured email proof.
type Prover struct {
	store  Store
	mailer Mailer
	cfg    Config
	key    []byte // the code key, derived from cfg.Key
}

// New builds the prover. Store, Mailer and Config.Key are required.
func New(s Store, m Mailer, cfg Config) (*Prover, error) {
	if s == nil || m == nil {
		return nil, errors.New("email: Store and Mailer are required")
	}
	if len(cfg.Key) < MinKeySize {
		return nil, ErrShortKey
	}
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = 15 * time.Minute
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 15 * time.Minute
	}
	if cfg.MaxPerWindow <= 0 {
		cfg.MaxPerWindow = 3
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 6
	}
	if cfg.DailyLimit <= 0 {
		cfg.DailyLimit = 30
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := hmac.New(sha256.New, cfg.Key)
	h.Write([]byte("katraca/email/code/k1"))
	return &Prover{store: s, mailer: m, cfg: cfg, key: h.Sum(nil)}, nil
}

func validPurpose(p Purpose) bool {
	return p == SignIn || p == Confirm || p == Reset
}

// SendLink issues a link for the address and hands it to the Mailer.
func (p *Prover) SendLink(ctx context.Context, address string, purpose Purpose) error {
	return p.send(ctx, address, purpose, Link)
}

// SendCode issues a six-digit code and hands it to the Mailer. The previous
// code for the same address and purpose stops being valid.
func (p *Prover) SendCode(ctx context.Context, address string, purpose Purpose) error {
	return p.send(ctx, address, purpose, Code)
}

func (p *Prover) send(ctx context.Context, address string, purpose Purpose, kind Kind) error {
	if !validPurpose(purpose) {
		return fmt.Errorf("email: unknown purpose %q", purpose)
	}
	addr, err := katraca.NormalizeEmail(address)
	if err != nil {
		return err
	}
	now := p.cfg.Now()
	e := Issuance{ID: newID(), Email: addr, Purpose: purpose, Kind: kind, Created: now}
	m := Message{To: addr, Purpose: purpose, Kind: kind}
	if kind == Link {
		raw := make([]byte, 32)
		rand.Read(raw)
		m.Token = base64.RawURLEncoding.EncodeToString(raw)
		h := sha256.Sum256(raw)
		e.Hash = h[:]
		e.Expires = now.Add(p.cfg.LinkTTL)
	} else {
		m.Code = newCode()
		e.Hash = p.codeHash(e.ID, m.Code)
		e.Expires = now.Add(p.cfg.CodeTTL)
	}
	m.Expires = e.Expires
	if err := p.store.Issue(ctx, e, p.cfg.MaxPerWindow, now.Add(-p.cfg.Window)); err != nil {
		return err
	}
	return p.mailer.Send(ctx, m)
}

// VerifyLink consumes the token and returns the identity of the address. The
// token is valid only once, only for the purpose it was issued for and only
// before it expires.
//
// Receive the token by POST, never by GET: email scanners that "check
// links" open GETs, and would use up the single use before the person.
func (p *Prover) VerifyLink(ctx context.Context, token string, purpose Purpose) (katraca.Identity, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 32 {
		return katraca.Identity{}, katraca.ErrRejected
	}
	h := sha256.Sum256(raw)
	e, err := p.store.ConsumeLink(ctx, h[:], purpose)
	if errors.Is(err, ErrNotFound) {
		return katraca.Identity{}, katraca.ErrRejected
	}
	if err != nil {
		return katraca.Identity{}, err
	}
	if e.Purpose != purpose || e.Kind != Link {
		return katraca.Identity{}, katraca.ErrRejected
	}
	if !p.cfg.Now().Before(e.Expires) {
		return katraca.Identity{}, katraca.ErrExpired
	}
	return identity(e.Email), nil
}

// VerifyCode checks the code typed for the address. Each call uses up one
// attempt, right or wrong; past the code's limit or the address's daily
// limit, not even the right code is valid.
func (p *Prover) VerifyCode(ctx context.Context, address, code string, purpose Purpose) (katraca.Identity, error) {
	addr, err := katraca.NormalizeEmail(address)
	if err != nil {
		return katraca.Identity{}, katraca.ErrRejected
	}
	code = cleanCode(code)
	if len(code) != 6 {
		return katraca.Identity{}, katraca.ErrRejected
	}
	now := p.cfg.Now()
	e, today, err := p.store.AttemptCode(ctx, addr, purpose, now.Add(-DailyLimitWindow))
	if errors.Is(err, ErrNotFound) {
		return katraca.Identity{}, katraca.ErrRejected
	}
	if err != nil {
		return katraca.Identity{}, err
	}
	if e.Purpose != purpose || e.Kind != Code || e.Email != addr {
		return katraca.Identity{}, katraca.ErrRejected
	}
	if e.Attempts > p.cfg.MaxAttempts || today > p.cfg.DailyLimit {
		return katraca.Identity{}, katraca.ErrTooManyAttempts
	}
	if !now.Before(e.Expires) {
		return katraca.Identity{}, katraca.ErrExpired
	}
	if subtle.ConstantTimeCompare(e.Hash, p.codeHash(e.ID, code)) != 1 {
		return katraca.Identity{}, katraca.ErrRejected
	}
	ok, err := p.store.Consume(ctx, e.ID)
	if err != nil {
		return katraca.Identity{}, err
	}
	if !ok {
		return katraca.Identity{}, katraca.ErrRejected
	}
	return identity(addr), nil
}

func identity(addr string) katraca.Identity {
	return katraca.Identity{Provider: "email", ID: addr, Email: addr, EmailVerified: true}
}

// cleanCode strips spaces and hyphens the person types or pastes ("123 456").
func cleanCode(c string) string {
	var b strings.Builder
	for _, r := range c {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '\t':
		default:
			return ""
		}
	}
	return b.String()
}

// codeHash binds the code to the issuance and to the app key. The id makes
// the same code in two issuances yield different hashes; the key, which does
// not live in the database, keeps whoever reads the database from trying the
// million codes against the hash.
func (p *Prover) codeHash(id, code string) []byte {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte(id + ":" + code))
	return m.Sum(nil)
}

func newCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err) // crypto/rand does not fail since Go 1.24
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
