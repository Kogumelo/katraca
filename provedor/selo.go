package provedor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kogumelo/katraca"
)

// TamanhoMinimoDaChave e o menor tamanho, em bytes, aceito para uma chave do
// Selo. Gere com 32 bytes de crypto/rand; senha digitada nao serve.
const TamanhoMinimoDaChave = 32

// ErrChaveCurta e erro de configuracao do app, nao recusa de prova: o Selo
// sem chave nenhuma ou com uma chave de menos de TamanhoMinimoDaChave bytes.
var ErrChaveCurta = fmt.Errorf("provedor: chave do selo precisa de %d bytes ou mais", TamanhoMinimoDaChave)

// Selo guarda o Pendente no navegador sem que ele possa ser lido nem
// trocado: o Pendente vai cifrado e autenticado (AES-256-GCM), com o prazo
// dentro. O verificador PKCE e o nonce nao aparecem no cookie.
//
// Chaves[0] sela; todas abrem. Para trocar de chave, ponha a nova na frente
// e mantenha a antiga atras por um PrazoDoInicio; depois tire a antiga.
type Selo struct {
	Chaves [][]byte
	Agora  func() time.Time
}

// versaoDoSelo abre todo selo e entra no dado associado do AEAD: um selo de
// outro formato, ou de outro uso da mesma chave, nao abre aqui.
const versaoDoSelo = "k1"

// limiteDoSelo e o maior selo que Abrir le. Um Pendente selado tem cerca de
// 350 caracteres; o resto e lixo ou ataque.
const limiteDoSelo = 2048

// selado e o que vai cifrado: o Pendente e o fim do prazo.
type selado struct {
	Pendente
	Expira int64 `json:"x"`
}

func (s *Selo) agora() time.Time {
	if s.Agora != nil {
		return s.Agora()
	}
	return time.Now()
}

// aeads monta um AES-256-GCM por chave. A chave do AES nao e a do app: sai
// de um HMAC dela com o rotulo do selo, para a mesma chave do app poder
// servir a outro uso sem que um vire o outro.
func (s *Selo) aeads() ([]cipher.AEAD, error) {
	if len(s.Chaves) == 0 {
		return nil, ErrChaveCurta
	}
	as := make([]cipher.AEAD, 0, len(s.Chaves))
	for _, chave := range s.Chaves {
		if len(chave) < TamanhoMinimoDaChave {
			return nil, ErrChaveCurta
		}
		m := hmac.New(sha256.New, chave)
		m.Write([]byte("katraca/provedor/selo/" + versaoDoSelo))
		bloco, err := aes.NewCipher(m.Sum(nil))
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(bloco)
		if err != nil {
			return nil, err
		}
		as = append(as, a)
	}
	return as, nil
}

// Selar cifra p com Chaves[0]. O selo vence em p.Criado + PrazoDoInicio, o
// mesmo prazo que Concluir confere. O resultado cabe num cookie.
func (s *Selo) Selar(p Pendente) (string, error) {
	as, err := s.aeads()
	if err != nil {
		return "", err
	}
	if p.Criado.IsZero() {
		p.Criado = s.agora()
	}
	claro, err := json.Marshal(selado{Pendente: p, Expira: p.Criado.Add(PrazoDoInicio).Unix()})
	if err != nil {
		return "", err
	}
	a := as[0]
	nonce := make([]byte, a.NonceSize())
	rand.Read(nonce)
	caixa := a.Seal(nonce, nonce, claro, []byte(versaoDoSelo))
	return versaoDoSelo + "." + base64.RawURLEncoding.EncodeToString(caixa), nil
}

// Abrir confere e decifra um selo de Selar com qualquer das Chaves. Selo
// adulterado, de outra chave ou de outro formato embrulha
// katraca.ErrRecusado; selo vencido devolve katraca.ErrExpirado, que tambem
// o embrulha.
func (s *Selo) Abrir(selo string) (Pendente, error) {
	as, err := s.aeads()
	if err != nil {
		return Pendente{}, err
	}
	recusa := fmt.Errorf("%w: selo do pendente invalido", katraca.ErrRecusado)
	corpo, ok := strings.CutPrefix(selo, versaoDoSelo+".")
	if !ok || len(selo) > limiteDoSelo {
		return Pendente{}, recusa
	}
	caixa, err := base64.RawURLEncoding.DecodeString(corpo)
	if err != nil {
		return Pendente{}, recusa
	}
	// O GCM confere a etiqueta em tempo constante; a ordem das chaves so
	// diz quantas tentativas, e isso o atacante ja sabe.
	for _, a := range as {
		n := a.NonceSize()
		if len(caixa) < n+a.Overhead() {
			return Pendente{}, recusa
		}
		claro, err := a.Open(nil, caixa[:n], caixa[n:], []byte(versaoDoSelo))
		if err != nil {
			continue
		}
		var v selado
		if err := json.Unmarshal(claro, &v); err != nil {
			return Pendente{}, recusa
		}
		if s.agora().Unix() > v.Expira {
			return Pendente{}, katraca.ErrExpirado
		}
		return v.Pendente, nil
	}
	return Pendente{}, recusa
}

// NomeDoCookie e o cookie que PlantarCookie e LerCookie usam.
const NomeDoCookie = "katraca_pendente"

// PlantarCookie sela p e o planta num cookie HttpOnly, Secure,
// SameSite=Lax, restrito a caminho (o prefixo das voltas, como "/volta/") e
// com vida ate o fim do prazo. SameSite=Lax deixa o cookie ir na volta por
// GET; para form_post (POST vindo do provedor), ele nao vai, e o app guarda o
// selo de outro jeito.
//
// Secure vale tambem em http://localhost no Chrome e no Firefox; o Safari
// pede https mesmo ali.
func (s *Selo) PlantarCookie(w http.ResponseWriter, caminho string, p Pendente) error {
	if p.Criado.IsZero() {
		p.Criado = s.agora()
	}
	v, err := s.Selar(p)
	if err != nil {
		return err
	}
	vida := int(p.Criado.Add(PrazoDoInicio).Sub(s.agora()).Seconds())
	if vida < 1 {
		vida = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: NomeDoCookie, Value: v, Path: caminho, MaxAge: vida,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// LerCookie abre o selo do cookie e o apaga no navegador: o Pendente serve
// a uma volta so. caminho e o mesmo dado a PlantarCookie. Volta sem cookie
// embrulha katraca.ErrRecusado.
func (s *Selo) LerCookie(w http.ResponseWriter, r *http.Request, caminho string) (Pendente, error) {
	c, err := r.Cookie(NomeDoCookie)
	if errors.Is(err, http.ErrNoCookie) {
		return Pendente{}, fmt.Errorf("%w: volta sem pendente", katraca.ErrRecusado)
	}
	if err != nil {
		return Pendente{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: NomeDoCookie, Path: caminho, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return s.Abrir(c.Value)
}
