package i18n_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/i18n"
	"github.com/Kogumelo/katraca/password"
	"github.com/Kogumelo/katraca/provider"
)

var keys = []i18n.Key{
	i18n.KeyRejected, i18n.KeyExpired, i18n.KeyTooManyAttempts, i18n.KeyTooManyRequests,
	i18n.KeyInvalidEmail, i18n.KeyCancelled, i18n.KeyProviderUnavailable, i18n.KeyUnexpected,
}

var rules = []password.Rule{
	password.RuleMinLength, password.RuleMaxLength, password.RuleLetter, password.RuleDigit,
	password.RuleUpper, password.RuleSymbol, password.RuleForbidden, password.RuleLogin,
}

// Every key has a text of its own in every language: a missing one would fall
// back to English in the middle of a Portuguese screen.
func TestCatalogsComplete(t *testing.T) {
	all := append([]i18n.Key{}, keys...)
	for _, r := range rules {
		all = append(all, i18n.WeakKey(r))
	}
	for _, k := range all {
		seen := map[string]i18n.Lang{}
		for _, l := range i18n.Languages {
			s := i18n.Text(l, k, 8)
			if s == string(k) || s == "" || strings.Contains(s, "%!") {
				t.Errorf("%s: %s has no proper text: %q", l, k, s)
			}
			if other, dup := seen[s]; dup {
				t.Errorf("%s: %s in %s is the same as in %s: %q", l, k, l, other, s)
			}
			seen[s] = l
		}
	}
}

func TestMessage(t *testing.T) {
	cases := []struct {
		err    error
		key    i18n.Key
		args   []any
		reason string
	}{
		{katraca.ErrRejected, i18n.KeyRejected, nil, "rejected"},
		{fmt.Errorf("%w: state mismatch", katraca.ErrRejected), i18n.KeyRejected, nil, "wrapped rejection"},
		{katraca.ErrExpired, i18n.KeyExpired, nil, "expired"},
		{katraca.ErrTooManyAttempts, i18n.KeyTooManyAttempts, nil, "attempts"},
		{katraca.ErrTooManyRequests, i18n.KeyTooManyRequests, nil, "requests"},
		{katraca.ErrInvalidEmail, i18n.KeyInvalidEmail, nil, "email"},
		{&provider.ProviderError{Code: "access_denied"}, i18n.KeyCancelled, nil, "cancelled"},
		{&provider.ProviderError{Code: "server_error"}, i18n.KeyRejected, nil, "provider refusal"},
		{&password.Weak{Rule: password.RuleMinLength, Limit: 10}, i18n.WeakKey(password.RuleMinLength), []any{10}, "weak"},
		{fmt.Errorf("signup: %w", &password.Weak{Rule: password.RuleForbidden}), i18n.WeakKey(password.RuleForbidden), nil, "wrapped weak"},
		{errors.New("pq: connection refused"), i18n.KeyUnexpected, nil, "unknown"},
	}
	for _, l := range i18n.Languages {
		for _, c := range cases {
			if got, want := i18n.Message(l, c.err), i18n.Text(l, c.key, c.args...); got != want {
				t.Errorf("%s, %s: got %q, want %q", l, c.reason, got, want)
			}
		}
		if i18n.Message(l, nil) != "" {
			t.Errorf("%s: nil error should have no message", l)
		}
	}
	if got := i18n.Message(i18n.Portuguese, &password.Weak{Rule: password.RuleMinLength, Limit: 10}); got != "Use pelo menos 10 caracteres." {
		t.Errorf("limit not formatted: %q", got)
	}
}

func TestMatch(t *testing.T) {
	cases := map[string]i18n.Lang{
		"":                           i18n.English,
		"pt-BR":                      i18n.Portuguese,
		"pt":                         i18n.Portuguese,
		"pt-PT,pt;q=0.9":             i18n.Portuguese,
		"pt_BR":                      i18n.Portuguese,
		"en-US,en;q=0.9":             i18n.English,
		"en;q=0.5, pt-BR;q=0.8":      i18n.Portuguese,
		"fr-FR,fr;q=0.9,pt;q=0.4":    i18n.Portuguese,
		"de, *;q=0.1":                i18n.English,
		"es":                         i18n.English,
		"pt-BR;q=0, en":              i18n.English,
		"PT-br":                      i18n.Portuguese,
		"en-GB;q=0.9, pt-BR;q=0.900": i18n.English,
	}
	for accept, want := range cases {
		if got := i18n.Match(accept); got != want {
			t.Errorf("Match(%q) = %s, want %s", accept, got, want)
		}
	}
}

func TestUnknownLanguageFallsBackToEnglish(t *testing.T) {
	if got, want := i18n.Text("fr", i18n.KeyRejected), i18n.Text(i18n.English, i18n.KeyRejected); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
