// A minimal net/http app that wires up magic link, Google and GitHub. It
// shows what stays on the app's side: keeping the Pending, sending the email,
// finding the account, and what the screen says. Store in memory and a
// "mailer" that writes to the log — only to watch the flow run.
//
//	PUBLIC_URL=http://localhost:8080 go run ./example
//
// Error messages follow the browser's Accept-Language, in English or
// Portuguese, through package i18n.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/i18n"
	"github.com/Kogumelo/katraca/provider"
)

func main() {
	base := os.Getenv("PUBLIC_URL")
	if base == "" {
		base = "http://localhost:8080"
	}

	// The app key: 32 bytes or more, in base64 in .env
	// (openssl rand -base64 32). It serves the email code and the Pending
	// seal; each derives its own. Without it, the example draws a random one,
	// and a restart drops the codes and the sign-ins halfway through.
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("KATRACA_KEY"))
	if len(key) == 0 {
		key = make([]byte, 32)
		rand.Read(key)
	}

	// The mailer belongs to the app: here it only writes the link to the log.
	mailer := email.MailerFunc(func(_ context.Context, m email.Message) error {
		if m.Kind == email.Link {
			log.Printf("to %s: %s/#signin=%s", m.To, base, m.Token)
		} else {
			log.Printf("to %s: code %s", m.To, m.Code)
		}
		return nil
	})
	prover, err := email.New(email.NewMemory(), mailer, email.Config{Key: key})
	if err != nil {
		log.Fatal(err)
	}

	// Each provider is only enabled if .env has its key.
	providers := map[string]provider.Provider{}
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		g, err := provider.NewGoogle(provider.Google{
			ClientID: id, ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"), RedirectURL: base + "/callback/google",
		})
		if err != nil {
			log.Fatal(err)
		}
		providers["google"] = g
	}
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		providers["github"] = provider.NewGitHub(provider.GitHub{
			ClientID: id, ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"), RedirectURL: base + "/callback/github",
		})
	}

	sealer := &provider.Sealer{Keys: [][]byte{key}}
	if _, err := sealer.Seal(provider.Pending{}); err != nil {
		log.Fatal(err) // short key
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /link", func(w http.ResponseWriter, r *http.Request) {
		if err := prover.SendLink(r.Context(), r.FormValue("email"), email.SignIn); err != nil {
			fail(w, r, err)
		}
	})
	mux.HandleFunc("POST /signin", func(w http.ResponseWriter, r *http.Request) {
		id, err := prover.VerifyLink(r.Context(), r.FormValue("token"), email.SignIn)
		respond(w, r, id, err)
	})
	mux.HandleFunc("GET /login/{p}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := providers[r.PathValue("p")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		target, pend, err := p.Begin(r.Context())
		if err != nil {
			log.Printf("%s: %v", p.Name(), err)
			lang := i18n.Match(r.Header.Get("Accept-Language"))
			http.Error(w, i18n.Text(lang, i18n.KeyProviderUnavailable), http.StatusBadGateway)
			return
		}
		if err := sealer.SetCookie(w, "/callback/", pend); err != nil {
			fail(w, r, err)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("/callback/{p}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := providers[r.PathValue("p")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		pend, err := sealer.ReadCookie(w, r, "/callback/")
		if err != nil {
			fail(w, r, err)
			return
		}
		r.ParseForm()
		id, err := p.Complete(r.Context(), pend, r.Form)
		respond(w, r, id, err)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// respond is where the app decides. The rule that matters: only link to an
// existing account by email if EmailVerified.
func respond(w http.ResponseWriter, r *http.Request, id katraca.Identity, err error) {
	if err != nil {
		fail(w, r, err)
		return
	}
	fmt.Fprintf(w, "provider=%s id=%s email=%s verified=%v\n", id.Provider, id.ID, id.Email, id.EmailVerified)
}

// fail answers with the message in the browser's language. The details of an
// unexpected error go to the log, never to the screen.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	lang := i18n.Match(r.Header.Get("Accept-Language"))
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, katraca.ErrRejected):
		status = http.StatusUnauthorized
	case errors.Is(err, katraca.ErrTooManyRequests):
		status = http.StatusTooManyRequests
	case errors.Is(err, katraca.ErrInvalidEmail):
		status = http.StatusBadRequest
	default:
		log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
	}
	http.Error(w, i18n.Message(lang, err), status)
}
