package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Kogumelo/katraca"
	"golang.org/x/oauth2"
)

// OAuth2 is the adapter for a provider that is not OIDC (GitHub, Meta): the
// authorization flow is the standard one, and what knows how to read the
// person is Identify, a small function that queries the provider's API.
type OAuth2 struct {
	ProviderName string
	ClientID     string
	ClientSecret string
	RedirectURL  string // callback URL, registered with the provider
	Scopes       []string
	AuthURL      string
	TokenURL     string
	// DisablePKCE turns PKCE off, for a provider that rejects it. On by
	// default.
	DisablePKCE bool
	// ExtraParams go in the authorization URL.
	ExtraParams map[string]string
	// Identify reads the person from the provider's API. api already carries
	// the token in the header, a timeout and a size limit.
	Identify func(ctx context.Context, api *API) (katraca.Identity, error)
	Client   *http.Client // nil means DefaultClient
	Now      func() time.Time
}

func (o *OAuth2) Name() string { return o.ProviderName }

func (o *OAuth2) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
		Endpoint:     oauth2.Endpoint{AuthURL: o.AuthURL, TokenURL: o.TokenURL},
	}
}

func (o *OAuth2) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OAuth2) Begin(ctx context.Context) (string, Pending, error) {
	if o.ClientID == "" || o.RedirectURL == "" || o.Identify == nil {
		return "", Pending{}, fmt.Errorf("provider %s: ClientID, RedirectURL and Identify are required", o.ProviderName)
	}
	pend := Pending{Provider: o.ProviderName, State: random(), Created: o.now()}
	var opts []oauth2.AuthCodeOption
	if !o.DisablePKCE {
		pend.Verifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pend.Verifier))
	}
	for k, v := range o.ExtraParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return o.config().AuthCodeURL(pend.State, opts...), pend, nil
}

func (o *OAuth2) Complete(ctx context.Context, pend Pending, response url.Values) (katraca.Identity, error) {
	code, err := checkCallback(o.ProviderName, pend, response, o.now())
	if err != nil {
		return katraca.Identity{}, err
	}
	var opts []oauth2.AuthCodeOption
	if pend.Verifier != "" {
		opts = append(opts, oauth2.VerifierOption(pend.Verifier))
	}
	tok, err := o.config().Exchange(withClient(ctx, o.Client), code, opts...)
	if err != nil {
		return katraca.Identity{}, fmt.Errorf("%w: code exchange: %v", katraca.ErrRejected, err)
	}
	id, err := o.Identify(ctx, &API{Client: o.Client, Token: tok})
	if err != nil {
		return katraca.Identity{}, err
	}
	if id.ID == "" {
		return katraca.Identity{}, fmt.Errorf("provider %s: identity without ID", o.ProviderName)
	}
	id.Provider = o.ProviderName
	if id.Email != "" {
		if e, err := katraca.NormalizeEmail(id.Email); err == nil {
			id.Email = e
		} else {
			id.Email, id.EmailVerified = "", false
		}
	} else {
		id.EmailVerified = false
	}
	return id, nil
}
