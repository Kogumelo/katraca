package provider

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kogumelo/katraca"
)

// GitHub configures sign-in with GitHub (OAuth App or GitHub App).
type GitHub struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// BaseURL and APIURL replace github.com and api.github.com (GitHub
	// Enterprise, tests). Empty means the public ones.
	BaseURL string
	APIURL  string
	Client  *http.Client
}

// NewGitHub builds the adapter. It asks only for read:user and user:email:
// enough to know who the person is and which email GitHub has already
// verified.
//
// The ID is the account number, which does not change; the login does change
// and goes in Extra["login"]. The email is the primary one, and
// EmailVerified is the "verified" flag GitHub gives it.
func NewGitHub(c GitHub) *OAuth2 {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://github.com"
	}
	api := strings.TrimRight(c.APIURL, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	return &OAuth2{
		ProviderName: "github",
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Scopes:       []string{"read:user", "user:email"},
		AuthURL:      base + "/login/oauth/authorize",
		TokenURL:     base + "/login/oauth/access_token",
		Client:       c.Client,
		Identify: func(ctx context.Context, a *API) (katraca.Identity, error) {
			var u struct {
				ID        int64  `json:"id"`
				Login     string `json:"login"`
				Name      string `json:"name"`
				AvatarURL string `json:"avatar_url"`
			}
			if err := a.JSON(ctx, api+"/user", &u); err != nil {
				return katraca.Identity{}, err
			}
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := a.JSON(ctx, api+"/user/emails", &emails); err != nil {
				return katraca.Identity{}, err
			}
			id := katraca.Identity{
				ID:      strconv.FormatInt(u.ID, 10),
				Name:    u.Name,
				Picture: u.AvatarURL,
				Extra:   map[string]string{"login": u.Login},
			}
			if u.ID == 0 {
				id.ID = ""
			}
			if id.Name == "" {
				id.Name = u.Login
			}
			for _, e := range emails {
				if e.Primary {
					id.Email, id.EmailVerified = e.Email, e.Verified
				}
			}
			return id, nil
		},
	}
}
