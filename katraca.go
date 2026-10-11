// Package katraca proves who a person is. It does not create accounts, open
// sessions or set cookies: that belongs to the app.
//
// Every method — email proof (link or code), password, Google, GitHub or any
// OIDC or OAuth2 provider — ends in the same Identity. The app looks at it
// and decides: find the account by the (Provider, ID) pair, create a new one,
// or link it to another. Linking by email is only safe when EmailVerified is
// true; see the README.
//
// The subpackages:
//
//   - email: magic link and 6-digit code, two presentations of the same email
//     proof.
//   - password: argon2id, legacy bcrypt verification, strength rules.
//   - provider: OIDC by discovery, OAuth2 adapter, Google and GitHub.
//   - i18n: optional end-user messages for the errors, in English and
//     Portuguese.
//   - pgkatraca: reference store in Postgres with pgx (optional).
package katraca

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// Identity is what a proof establishes. The (Provider, ID) pair is fixed for
// the same person at the same provider; it is how the app finds the account.
type Identity struct {
	// Provider names the method: "email", "password", "google", "github", or
	// the name given to a configured provider.
	Provider string
	// ID is the fixed identifier within the provider: the OIDC `sub`, the
	// numeric GitHub id, the normalized address in the email proof, the
	// login in the password.
	ID string
	// Email is the address the provider reported, normalized. May be empty.
	Email string
	// EmailVerified says the provider (or the email proof) vouches that the
	// person controls Email. Without it, Email is only a claim: the app does
	// NOT link this identity to an existing account by email.
	EmailVerified bool
	// Name and Picture are cosmetic and may be empty.
	Name    string
	Picture string
	// Extra holds what is specific to a provider and the app may want (for
	// example, Apple's "private_email"). May be nil.
	Extra map[string]string
}

// The proof errors. All rejections wrap ErrRejected, so the app handles "not
// proven" in one place and, if it wants, tells the reason apart.
var (
	// ErrRejected: the proof is not valid (wrong password, unknown user, used
	// link, wrong code, mismatched state). The app answers without saying
	// which.
	ErrRejected = errors.New("katraca: proof rejected")
	// ErrExpired: the proof was valid, but its time ran out.
	ErrExpired = fmt.Errorf("%w: expired", ErrRejected)
	// ErrTooManyAttempts: the code used up its attempt limit.
	ErrTooManyAttempts = fmt.Errorf("%w: too many attempts", ErrRejected)
	// ErrTooManyRequests: the address already got the most messages allowed
	// in the window.
	ErrTooManyRequests = errors.New("katraca: too many requests for this address")
	// ErrInvalidEmail: the address is not a bare, valid email address.
	ErrInvalidEmail = errors.New("katraca: invalid email address")
)

// NormalizeEmail accepts only the bare address ("ana@example.com"), with no
// display name, no line break and nothing that would become a second
// recipient, and returns it in lowercase. The local part is, per the spec,
// case sensitive; in practice no major provider treats it that way, and two
// accounts for "Ana@" and "ana@" would be worse than the rare opposite case.
func NormalizeEmail(raw string) (string, error) {
	e := strings.TrimSpace(raw)
	if e == "" || len(e) > 254 || strings.ContainsAny(e, "\r\n<>\",; \t") {
		return "", ErrInvalidEmail
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return "", ErrInvalidEmail
	}
	at := strings.LastIndex(e, "@")
	if at < 1 || !strings.Contains(e[at+1:], ".") {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(e), nil
}
