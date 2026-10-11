package i18n

import "github.com/Kogumelo/katraca/password"

var en = map[Key]string{
	KeyRejected:            "Sign-in failed. Check your details and try again.",
	KeyExpired:             "This link or code has expired. Request a new one.",
	KeyTooManyAttempts:     "Too many attempts. Wait a while and request a new code.",
	KeyTooManyRequests:     "Too many messages were sent to this address. Wait a few minutes and try again.",
	KeyInvalidEmail:        "Enter a valid email address.",
	KeyCancelled:           "Sign-in was cancelled.",
	KeyProviderUnavailable: "The sign-in service is unavailable right now. Try again later.",
	KeyUnexpected:          "Something went wrong. Try again.",

	WeakKey(password.RuleMinLength): "Use at least %d characters.",
	WeakKey(password.RuleMaxLength): "Use at most %d characters.",
	WeakKey(password.RuleLetter):    "Include at least one letter.",
	WeakKey(password.RuleDigit):     "Include at least one number.",
	WeakKey(password.RuleUpper):     "Include at least one uppercase letter.",
	WeakKey(password.RuleSymbol):    "Include at least one symbol.",
	WeakKey(password.RuleForbidden): "This password is too common. Choose another one.",
	WeakKey(password.RuleLogin):     "The password cannot contain your login.",
}
