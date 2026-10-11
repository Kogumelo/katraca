package password

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rules are strength rules. The zero value works: at least 8 characters, at
// most 128.
//
// The current recommendation (NIST SP 800-63B) is to require length and
// reject known passwords, not to require a mix of character classes; the
// class requirements are here because some apps want them, and they are off
// by default.
type Rules struct {
	MinLength int // characters; 0 means 8
	// MaxLength in characters; 0 means 128. There is a ceiling because the
	// hash takes time proportional to the length, and a one-megabyte password
	// is an attack.
	MaxLength     int
	RequireLetter bool
	RequireDigit  bool
	RequireUpper  bool
	RequireSymbol bool
	// Forbidden: rejected passwords, case-insensitive ("12345678",
	// "password123", the app's name).
	Forbidden []string
	// NoLogin rejects a password that contains the login (or the local part
	// of the email address), case-insensitive.
	NoLogin bool
}

// Rule names the rule a password broke.
type Rule string

// The rules Check can report in Weak.
const (
	RuleMinLength Rule = "min_length"
	RuleMaxLength Rule = "max_length"
	RuleLetter    Rule = "letter"
	RuleDigit     Rule = "digit"
	RuleUpper     Rule = "upper"
	RuleSymbol    Rule = "symbol"
	RuleForbidden Rule = "forbidden"
	RuleLogin     Rule = "login"
)

// Weak is the error from Check: it says which rule the password broke, so
// the app can write the message in its own language.
type Weak struct {
	Rule  Rule
	Limit int // the limit, for the length rules
}

func (w *Weak) Error() string { return "password: weak (" + string(w.Rule) + ")" }

// Check returns nil if password meets the rules, or *Weak with the first
// rule broken.
func (r Rules) Check(password, login string) error {
	min, max := r.MinLength, r.MaxLength
	if min <= 0 {
		min = 8
	}
	if max <= 0 {
		max = 128
	}
	n := utf8.RuneCountInString(password)
	if n < min {
		return &Weak{Rule: RuleMinLength, Limit: min}
	}
	if n > max {
		return &Weak{Rule: RuleMaxLength, Limit: max}
	}
	var letter, digit, upper, symbol bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			upper, letter = true, true
		case unicode.IsLetter(c):
			letter = true
		case unicode.IsDigit(c):
			digit = true
		default:
			symbol = true
		}
	}
	switch {
	case r.RequireLetter && !letter:
		return &Weak{Rule: RuleLetter}
	case r.RequireDigit && !digit:
		return &Weak{Rule: RuleDigit}
	case r.RequireUpper && !upper:
		return &Weak{Rule: RuleUpper}
	case r.RequireSymbol && !symbol:
		return &Weak{Rule: RuleSymbol}
	}
	lower := strings.ToLower(password)
	for _, f := range r.Forbidden {
		if lower == strings.ToLower(f) {
			return &Weak{Rule: RuleForbidden}
		}
	}
	if r.NoLogin && login != "" {
		l := strings.ToLower(login)
		if i := strings.Index(l, "@"); i > 0 {
			l = l[:i]
		}
		if len(l) >= 3 && strings.Contains(lower, l) {
			return &Weak{Rule: RuleLogin}
		}
	}
	return nil
}
