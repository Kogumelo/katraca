package provedor_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/provedor"
)

var (
	chaveA = bytes.Repeat([]byte{'a'}, 32)
	chaveB = bytes.Repeat([]byte{'b'}, 32)
)

func pendenteDeTeste(agora time.Time) provedor.Pendente {
	return provedor.Pendente{Provedor: "google", Estado: "estado", Verificador: "verificador-pkce", Nonce: "nonce", Criado: agora}
}

func relogio(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestSeloIdaEVolta(t *testing.T) {
	agora := time.Unix(1_800_000_000, 0)
	s := &provedor.Selo{Chaves: [][]byte{chaveA}, Agora: relogio(&agora)}
	p := pendenteDeTeste(agora)
	selo, err := s.Selar(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(selo, "verificador") || strings.Contains(selo, "estado") {
		t.Fatalf("selo deixa ver o pendente: %s", selo)
	}
	outro, _ := s.Selar(p)
	if outro == selo {
		t.Fatal("dois selos do mesmo pendente sairam iguais: o nonce do GCM nao muda")
	}
	volta, err := s.Abrir(selo)
	if err != nil {
		t.Fatal(err)
	}
	if !volta.Criado.Equal(p.Criado) || volta.Estado != p.Estado || volta.Verificador != p.Verificador ||
		volta.Nonce != p.Nonce || volta.Provedor != p.Provedor {
		t.Fatalf("voltou %+v, foi %+v", volta, p)
	}
}

func TestSeloAdulterado(t *testing.T) {
	s := &provedor.Selo{Chaves: [][]byte{chaveA}}
	selo, err := s.Selar(pendenteDeTeste(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	prefixo, corpo, _ := strings.Cut(selo, ".")
	caixa, _ := base64.RawURLEncoding.DecodeString(corpo)
	for i := range caixa {
		mexido := bytes.Clone(caixa)
		mexido[i] ^= 0x01
		_, err := s.Abrir(prefixo + "." + base64.RawURLEncoding.EncodeToString(mexido))
		if !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("byte %d adulterado: err = %v", i, err)
		}
	}
	for _, lixo := range []string{"", "k1.", "k1.!!!", "k2" + selo[2:], selo[:len(selo)-4], "k1." + strings.Repeat("A", 4000)} {
		if _, err := s.Abrir(lixo); !errors.Is(err, katraca.ErrRecusado) {
			t.Fatalf("Abrir(%.20q): err = %v", lixo, err)
		}
	}
}

func TestSeloDeOutraChave(t *testing.T) {
	selo, err := (&provedor.Selo{Chaves: [][]byte{chaveA}}).Selar(pendenteDeTeste(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&provedor.Selo{Chaves: [][]byte{chaveB}}).Abrir(selo)
	if !errors.Is(err, katraca.ErrRecusado) {
		t.Fatalf("err = %v", err)
	}
}

func TestSeloVencido(t *testing.T) {
	agora := time.Unix(1_800_000_000, 0)
	s := &provedor.Selo{Chaves: [][]byte{chaveA}, Agora: relogio(&agora)}
	selo, err := s.Selar(pendenteDeTeste(agora))
	if err != nil {
		t.Fatal(err)
	}
	agora = agora.Add(provedor.PrazoDoInicio)
	if _, err := s.Abrir(selo); err != nil {
		t.Fatalf("no ultimo segundo do prazo: %v", err)
	}
	agora = agora.Add(time.Second)
	_, err = s.Abrir(selo)
	if !errors.Is(err, katraca.ErrExpirado) || !errors.Is(err, katraca.ErrRecusado) {
		t.Fatalf("err = %v", err)
	}
}

func TestSeloRotacao(t *testing.T) {
	selo, err := (&provedor.Selo{Chaves: [][]byte{chaveA}}).Selar(pendenteDeTeste(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	nova := &provedor.Selo{Chaves: [][]byte{chaveB, chaveA}}
	if _, err := nova.Abrir(selo); err != nil {
		t.Fatalf("selo da chave antiga nao abriu com a lista nova: %v", err)
	}
	// A lista nova sela com a primeira: a chave antiga, sozinha, ja nao abre.
	seloNovo, err := nova.Selar(pendenteDeTeste(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&provedor.Selo{Chaves: [][]byte{chaveB}}).Abrir(seloNovo); err != nil {
		t.Fatalf("selo novo nao abriu com a chave nova: %v", err)
	}
	if _, err := (&provedor.Selo{Chaves: [][]byte{chaveA}}).Abrir(seloNovo); !errors.Is(err, katraca.ErrRecusado) {
		t.Fatalf("selo novo abriu com a chave antiga: %v", err)
	}
}

func TestSeloChaveCurta(t *testing.T) {
	for _, chaves := range [][][]byte{nil, {chaveA[:31]}, {chaveA, chaveB[:16]}} {
		s := &provedor.Selo{Chaves: chaves}
		if _, err := s.Selar(pendenteDeTeste(time.Now())); !errors.Is(err, provedor.ErrChaveCurta) {
			t.Fatalf("Selar com %d chaves: err = %v", len(chaves), err)
		}
		if _, err := s.Abrir("k1.qualquer"); !errors.Is(err, provedor.ErrChaveCurta) {
			t.Fatalf("Abrir com %d chaves: err = %v", len(chaves), err)
		}
	}
}

func TestSeloCookie(t *testing.T) {
	agora := time.Now()
	s := &provedor.Selo{Chaves: [][]byte{chaveA}, Agora: relogio(&agora)}
	p := pendenteDeTeste(agora.Add(-time.Minute))

	ida := httptest.NewRecorder()
	if err := s.PlantarCookie(ida, "/volta/", p); err != nil {
		t.Fatal(err)
	}
	cs := ida.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies = %v", cs)
	}
	c := cs[0]
	if c.Name != provedor.NomeDoCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/volta/" || c.MaxAge != int((provedor.PrazoDoInicio-time.Minute).Seconds()) {
		t.Fatalf("cookie com atributos errados: %+v", c)
	}

	req := httptest.NewRequest(http.MethodGet, "/volta/google?state=estado", nil)
	req.AddCookie(c)
	volta := httptest.NewRecorder()
	got, err := s.LerCookie(volta, req, "/volta/")
	if err != nil || got.Estado != p.Estado {
		t.Fatalf("LerCookie = %+v, %v", got, err)
	}
	apaga := volta.Result().Cookies()
	if len(apaga) != 1 || apaga[0].MaxAge >= 0 || apaga[0].Path != "/volta/" {
		t.Fatalf("LerCookie nao apagou o cookie: %+v", apaga)
	}

	semCookie := httptest.NewRequest(http.MethodGet, "/volta/google", nil)
	if _, err := s.LerCookie(httptest.NewRecorder(), semCookie, "/volta/"); !errors.Is(err, katraca.ErrRecusado) {
		t.Fatalf("volta sem cookie: err = %v", err)
	}
}
