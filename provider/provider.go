// Package provider proves identity through an external provider — Google,
// GitHub, any OIDC provider by configuration, any OAuth2 provider through an
// adapter.
//
// The flow has two halves, and between them the person goes to the provider
// and comes back:
//
//	url, pend, err := p.Begin(ctx)
//	// the app stores pend (Sealer.SetCookie, or the session) and redirects
//	...
//	// on the callback, with the parameters the provider sent (r.Form):
//	id, err := p.Complete(ctx, pend, r.Form)
//
// Pending carries the state, the PKCE verifier and the nonce. Storing it is
// the app's job, and it is what ties the callback to whoever left: without
// it, Complete rejects. Sealer encrypts it with the app's key so it can go in
// a cookie.
package provider

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Kogumelo/katraca"
	"golang.org/x/oauth2"
)

// Provider is a way of proving identity with a round trip to a third party.
type Provider interface {
	// Name is what goes in Identity.Provider ("google", "github", ...).
	Name() string
	// Begin returns the provider's URL and what the app stores until the
	// callback.
	Begin(ctx context.Context) (string, Pending, error)
	// Complete checks the callback against the Pending and returns the
	// identity. response holds the callback parameters: the query on GET,
	// the body on form_post (r.Form covers both).
	Complete(ctx context.Context, pend Pending, response url.Values) (katraca.Identity, error)
}

// Pending is what the app stores between Begin and Complete. It is not a
// long-term secret, but whoever holds it completes the login in the person's
// place: store it with Sealer (encrypted, HttpOnly, short-lived cookie) or in
// the server session.
type Pending struct {
	Provider string    `json:"p"`
	State    string    `json:"s"`
	Verifier string    `json:"v,omitempty"` // PKCE
	Nonce    string    `json:"n,omitempty"` // OIDC
	Created  time.Time `json:"c"`
}

// ProviderError is the rejection the provider itself sent on the callback
// (?error=access_denied, for example), with the state already checked. It
// wraps katraca.ErrRejected. Description is free text from the provider: the
// app does not render it as HTML.
type ProviderError struct {
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("provider: %s (%s)", e.Code, e.Description)
}
func (e *ProviderError) Unwrap() error { return katraca.ErrRejected }

// PendingTTL is how long the person has to go to the provider and come back.
const PendingTTL = 10 * time.Minute

// MaxResponseSize is the maximum size read from any provider response.
const MaxResponseSize = 1 << 20

// DefaultClient is the HTTP client used when the configuration gives none.
// It has a timeout: a slow provider does not hold up the person's request.
var DefaultClient = &http.Client{Timeout: 10 * time.Second}

func random() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// checkCallback is the common part of Complete: provider, deadline, state,
// provider error and presence of the code.
func checkCallback(name string, pend Pending, response url.Values, now time.Time) (string, error) {
	if pend.Provider != name || pend.State == "" {
		return "", fmt.Errorf("%w: pending from another provider", katraca.ErrRejected)
	}
	if now.Sub(pend.Created) > PendingTTL || now.Before(pend.Created.Add(-time.Minute)) {
		return "", katraca.ErrExpired
	}
	// The state comes before the error: the provider returns the state on a
	// rejection too, and without checking it anyone can put whatever
	// error_description they like on the callback.
	if subtle.ConstantTimeCompare([]byte(response.Get("state")), []byte(pend.State)) != 1 {
		return "", fmt.Errorf("%w: state mismatch", katraca.ErrRejected)
	}
	if e := response.Get("error"); e != "" {
		return "", &ProviderError{Code: e, Description: response.Get("error_description")}
	}
	code := response.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w: callback without code", katraca.ErrRejected)
	}
	return code, nil
}

// API calls the provider's API with the access token in the Authorization
// header — never in the URL, where it would end up in logs.
type API struct {
	Client *http.Client
	Token  *oauth2.Token
}

// JSON does a GET on endpoint and decodes the response into dest. It reads at
// most MaxResponseSize bytes.
func (a *API) JSON(ctx context.Context, endpoint string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if a.Token != nil {
		req.Header.Set("Authorization", "Bearer "+a.Token.AccessToken)
	}
	return readJSON(a.Client, req, dest)
}

func readJSON(c *http.Client, req *http.Request, dest any) error {
	if c == nil {
		c = DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return err
	}
	if len(body) > MaxResponseSize {
		return fmt.Errorf("provider: response from %s exceeds %d bytes", req.URL.Host, MaxResponseSize)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("provider: %s answered %d", req.URL.Host, resp.StatusCode)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("provider: unreadable response from %s: %w", req.URL.Host, err)
	}
	return nil
}

// withClient puts the client in the context, which is where x/oauth2 looks
// for it.
func withClient(ctx context.Context, c *http.Client) context.Context {
	if c == nil {
		c = DefaultClient
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}
