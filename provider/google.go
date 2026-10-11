package provider

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/Kogumelo/katraca"
)

// Google configures sign-in with Google.
type Google struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Issuer replaces accounts.google.com (tests). Empty means the public one.
	Issuer string
	// HostedDomain restricts sign-in to one Google Workspace ("hd"). Empty
	// accepts everyone.
	HostedDomain string
	Client       *http.Client
}

// NewGoogle builds Google as just another OIDC provider. No
// access_type=offline: sign-in does not need a refresh token, and asking for
// one only makes Google keep a grant nobody uses.
//
// EmailVerified is the id_token's email_verified. A Google account with an
// outside email (not a Gmail one, but an "ana@company.com" registered with
// Google) may come with it false.
func NewGoogle(c Google) (*OIDC, error) {
	issuer := c.Issuer
	if issuer == "" {
		issuer = "https://accounts.google.com"
	}
	cfg := OIDCConfig{
		Name:         "google",
		Issuer:       issuer,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Client:       c.Client,
		// Google sometimes issues the iss without the https.
		AcceptIssuer: func(iss string) bool {
			return iss == issuer || "https://"+iss == issuer
		},
	}
	if c.HostedDomain != "" {
		cfg.ExtraParams = map[string]string{"hd": c.HostedDomain}
		// The "hd" in the URL is only a hint; what guarantees it is the claim.
		cfg.Customize = func(cl Claims, _ url.Values, _ *katraca.Identity) error {
			if cl.String("hd") != c.HostedDomain {
				return fmt.Errorf("%w: account outside domain %s", katraca.ErrRejected, c.HostedDomain)
			}
			return nil
		}
	}
	return NewOIDC(cfg)
}
