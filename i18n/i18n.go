// Package i18n turns the library's errors into short messages for the person
// signing in, in English or Brazilian Portuguese.
//
// It is optional. The library proves and the app decides, and that includes
// what the screen says: an app with its own texts ignores this package and
// switches on the errors itself. The messages never tell which part of a
// rejection failed (unknown user or wrong password): ErrRejected has a single
// text on purpose.
//
//	lang := i18n.Match(r.Header.Get("Accept-Language"))
//	http.Error(w, i18n.Message(lang, err), http.StatusUnauthorized)
//
// To add a language, write a catalog like en.go, register it in catalogs and
// Languages, and teach Match its tag. TestCatalogsComplete fails while a key
// is missing.
package i18n

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/password"
	"github.com/Kogumelo/katraca/provider"
)

// Lang is a BCP 47 language tag the catalogs know.
type Lang string

const (
	English    Lang = "en"
	Portuguese Lang = "pt-BR"
)

// Languages are the supported languages; the first one is the fallback.
var Languages = []Lang{English, Portuguese}

// Key names a message in the catalogs. Apps can show the texts on their own
// with Text.
type Key string

const (
	KeyRejected            Key = "rejected"
	KeyExpired             Key = "expired"
	KeyTooManyAttempts     Key = "too_many_attempts"
	KeyTooManyRequests     Key = "too_many_requests"
	KeyInvalidEmail        Key = "invalid_email"
	KeyCancelled           Key = "cancelled"
	KeyProviderUnavailable Key = "provider_unavailable"
	KeyUnexpected          Key = "unexpected"
)

// WeakKey is the key of the message for a broken password rule. Its text may
// take the rule's limit as a %d verb.
func WeakKey(r password.Rule) Key { return Key("weak_" + string(r)) }

var catalogs = map[Lang]map[Key]string{
	English:    en,
	Portuguese: ptBR,
}

// Text returns the message for key in lang, formatted with args when the text
// has a verb for them (the limit of a password rule). A language
// the catalogs do not know falls back to English, and so does a key missing
// from its catalog; an unknown key returns the key itself.
func Text(lang Lang, key Key, args ...any) string {
	s, ok := catalogs[lang][key]
	if !ok {
		s, ok = catalogs[English][key]
	}
	if !ok {
		return string(key)
	}
	if len(args) > 0 && strings.Contains(s, "%") {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Message returns the text for err in lang, or "" for a nil err. Errors the
// library does not produce (a database down, a misconfiguration) get
// KeyUnexpected, without details: those go to the log, not to the screen.
func Message(lang Lang, err error) string {
	if err == nil {
		return ""
	}
	var weak *password.Weak
	var perr *provider.ProviderError
	switch {
	case errors.As(err, &weak):
		return Text(lang, WeakKey(weak.Rule), weak.Limit)
	case errors.Is(err, katraca.ErrTooManyAttempts):
		return Text(lang, KeyTooManyAttempts)
	case errors.Is(err, katraca.ErrExpired):
		return Text(lang, KeyExpired)
	case errors.As(err, &perr) && perr.Code == "access_denied":
		return Text(lang, KeyCancelled)
	case errors.Is(err, katraca.ErrRejected):
		return Text(lang, KeyRejected)
	case errors.Is(err, katraca.ErrTooManyRequests):
		return Text(lang, KeyTooManyRequests)
	case errors.Is(err, katraca.ErrInvalidEmail):
		return Text(lang, KeyInvalidEmail)
	}
	return Text(lang, KeyUnexpected)
}

// Match picks the language from an Accept-Language header ("pt-BR,pt;q=0.9,
// en;q=0.8") or from a single tag ("pt"). Any Portuguese tag gets Portuguese;
// with nothing that matches, it returns English.
func Match(accept string) Lang {
	type choice struct {
		tag string
		q   float64
	}
	var choices []choice
	for _, part := range strings.Split(accept, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if tag != "" && q > 0 {
			choices = append(choices, choice{strings.ToLower(strings.TrimSpace(tag)), q})
		}
	}
	sort.SliceStable(choices, func(i, j int) bool { return choices[i].q > choices[j].q })
	for _, c := range choices {
		switch {
		case c.tag == "pt" || strings.HasPrefix(c.tag, "pt-") || strings.HasPrefix(c.tag, "pt_"):
			return Portuguese
		case c.tag == "en" || strings.HasPrefix(c.tag, "en-") || strings.HasPrefix(c.tag, "en_") || c.tag == "*":
			return English
		}
	}
	return English
}
