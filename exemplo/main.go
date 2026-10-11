// Um app minimo com net/http que liga link magico, Google e GitHub. Mostra o
// que fica do lado do app: guardar o Pendente, mandar o e-mail, achar a
// conta. Guarda em memoria e "carteiro" que escreve no log — so para ver o
// fluxo rodar.
//
//	ENDERECO_PUBLICO=http://localhost:8080 go run ./exemplo
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Kogumelo/acesso"
	"github.com/Kogumelo/acesso/email"
	"github.com/Kogumelo/acesso/provedor"
)

func main() {
	base := os.Getenv("ENDERECO_PUBLICO")
	if base == "" {
		base = "http://localhost:8080"
	}

	// O carteiro e do app: aqui ele so escreve o link no log.
	carteiro := email.CarteiroFunc(func(_ context.Context, m email.Mensagem) error {
		if m.Forma == email.Link {
			log.Printf("para %s: %s/#entrar=%s", m.Para, base, m.Token)
		} else {
			log.Printf("para %s: codigo %s", m.Para, m.Codigo)
		}
		return nil
	})
	prova, err := email.Nova(email.NovaMemoria(), carteiro, email.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Cada provedor so liga se o .env tem a chave.
	provedores := map[string]provedor.Provedor{}
	if id := os.Getenv("GOOGLE_CLIENTE_ID"); id != "" {
		g, err := provedor.NovoGoogle(provedor.Google{
			ClienteID: id, Segredo: os.Getenv("GOOGLE_SEGREDO"), Retorno: base + "/volta/google",
		})
		if err != nil {
			log.Fatal(err)
		}
		provedores["google"] = g
	}
	if id := os.Getenv("GITHUB_CLIENTE_ID"); id != "" {
		provedores["github"] = provedor.NovoGitHub(provedor.GitHub{
			ClienteID: id, Segredo: os.Getenv("GITHUB_SEGREDO"), Retorno: base + "/volta/github",
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /link", func(w http.ResponseWriter, r *http.Request) {
		err := prova.EnviarLink(r.Context(), r.FormValue("email"), email.Entrar)
		switch {
		case errors.Is(err, acesso.ErrMuitosPedidos):
			http.Error(w, "espere alguns minutos", http.StatusTooManyRequests)
		case err != nil:
			http.Error(w, "nao deu", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("POST /entrar", func(w http.ResponseWriter, r *http.Request) {
		id, err := prova.ConferirLink(r.Context(), r.FormValue("token"), email.Entrar)
		responder(w, id, err)
	})
	mux.HandleFunc("GET /ir/{p}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := provedores[r.PathValue("p")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		destino, pend, err := p.Iniciar(r.Context())
		if err != nil {
			http.Error(w, "provedor fora do ar", http.StatusBadGateway)
			return
		}
		// Num app de verdade, este cookie e ASSINADO (HMAC com segredo do
		// app); aqui vai cru para o exemplo caber numa tela.
		b, _ := json.Marshal(pend)
		http.SetCookie(w, &http.Cookie{Name: "pendente", Value: base64.RawURLEncoding.EncodeToString(b),
			Path: "/volta/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		http.Redirect(w, r, destino, http.StatusFound)
	})
	mux.HandleFunc("/volta/{p}", func(w http.ResponseWriter, r *http.Request) {
		p, ok := provedores[r.PathValue("p")]
		c, err := r.Cookie("pendente")
		if !ok || err != nil {
			http.Error(w, "volta sem ida", http.StatusBadRequest)
			return
		}
		var pend provedor.Pendente
		b, _ := base64.RawURLEncoding.DecodeString(c.Value)
		json.Unmarshal(b, &pend)
		r.ParseForm()
		id, err := p.Concluir(r.Context(), pend, r.Form)
		responder(w, id, err)
	})
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// responder e onde o app decide. A regra que importa: so juntar com uma
// conta existente pelo e-mail se EmailGarantido.
func responder(w http.ResponseWriter, id acesso.Identidade, err error) {
	if errors.Is(err, acesso.ErrRecusado) {
		http.Error(w, "nao foi possivel entrar", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "erro", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "provedor=%s id=%s email=%s garantido=%v\n", id.Provedor, id.ID, id.Email, id.EmailGarantido)
}
