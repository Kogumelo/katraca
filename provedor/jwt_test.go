package provedor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// A assinatura ES256 tem r e s em [1, N-1]. Fora disso, recusa — mesmo que
// a conta modular "feche".
func TestES256ForaDoIntervalo(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assinado := "cab.corpo"
	h := sha256.Sum256([]byte(assinado))
	r, s, _ := ecdsa.Sign(rand.Reader, k, h[:])
	n := elliptic.P256().Params().N
	junta := func(r, s *big.Int) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	if err := conferirAssinatura("ES256", &k.PublicKey, assinado, junta(r, s)); err != nil {
		t.Fatalf("assinatura boa recusada: %v", err)
	}
	zero := new(big.Int)
	casos := map[string][]byte{
		"r zero":         junta(zero, s),
		"s zero":         junta(r, zero),
		"r igual a N":    junta(n, s),
		"s igual a N":    junta(r, n),
		"r mais N":       junta(new(big.Int).Add(r, n).Mod(new(big.Int).Add(r, n), new(big.Int).Lsh(big.NewInt(1), 256)), s),
		"curta":          junta(r, s)[:63],
		"longa":          append(junta(r, s), 0),
		"r e s trocados": junta(s, r),
	}
	for nome, ass := range casos {
		if err := conferirAssinatura("ES256", &k.PublicKey, assinado, ass); err == nil {
			t.Errorf("%s: aceita", nome)
		}
	}
}

// RS256 com chave curta, expoente 1 ou expoente par nao confere nada.
func TestRS256ChaveFraca(t *testing.T) {
	assinado := "cab.corpo"
	h := sha256.Sum256([]byte(assinado))
	curta, _ := rsa.GenerateKey(rand.Reader, 1024)
	ass, _ := rsa.SignPKCS1v15(rand.Reader, curta, crypto.SHA256, h[:])
	if err := conferirAssinatura("RS256", &curta.PublicKey, assinado, ass); err == nil {
		t.Error("chave de 1024 bits aceita")
	}
	boa, _ := rsa.GenerateKey(rand.Reader, 2048)
	ass, _ = rsa.SignPKCS1v15(rand.Reader, boa, crypto.SHA256, h[:])
	for _, e := range []int{0, 1, 2, 65536} {
		pub := &rsa.PublicKey{N: boa.N, E: e}
		if err := conferirAssinatura("RS256", pub, assinado, ass); err == nil {
			t.Errorf("expoente %d aceito", e)
		}
	}
}

// O alg do cabecalho nao escolhe a chave: RS256 com chave EC, ES256 com
// chave RSA, none e HS256 sao recusados.
func TestAlgTrocado(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	casos := []struct {
		alg   string
		chave crypto.PublicKey
	}{
		{"RS256", &ec.PublicKey}, {"ES256", &rs.PublicKey},
		{"none", &rs.PublicKey}, {"HS256", &rs.PublicKey}, {"rs256", &rs.PublicKey}, {"", &rs.PublicKey},
	}
	for _, c := range casos {
		if err := conferirAssinatura(c.alg, c.chave, "a.b", make([]byte, 256)); err == nil {
			t.Errorf("alg %q com %T aceito", c.alg, c.chave)
		}
	}
}
