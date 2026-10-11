package provider

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

// An ES256 signature has r and s in [1, N-1]. Outside that range, reject —
// even if the modular arithmetic "works out".
func TestES256OutOfRange(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signed := "head.body"
	h := sha256.Sum256([]byte(signed))
	r, s, _ := ecdsa.Sign(rand.Reader, k, h[:])
	n := elliptic.P256().Params().N
	join := func(r, s *big.Int) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	if err := verifySignature("ES256", &k.PublicKey, signed, join(r, s)); err != nil {
		t.Fatalf("good signature rejected: %v", err)
	}
	zero := new(big.Int)
	cases := map[string][]byte{
		"r zero":          join(zero, s),
		"s zero":          join(r, zero),
		"r equals N":      join(n, s),
		"s equals N":      join(r, n),
		"r plus N":        join(new(big.Int).Add(r, n).Mod(new(big.Int).Add(r, n), new(big.Int).Lsh(big.NewInt(1), 256)), s),
		"short":           join(r, s)[:63],
		"long":            append(join(r, s), 0),
		"r and s swapped": join(s, r),
	}
	for name, sig := range cases {
		if err := verifySignature("ES256", &k.PublicKey, signed, sig); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// RS256 with a short key, exponent 1 or an even exponent verifies nothing.
func TestRS256WeakKey(t *testing.T) {
	signed := "head.body"
	h := sha256.Sum256([]byte(signed))
	short, _ := rsa.GenerateKey(rand.Reader, 1024)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, short, crypto.SHA256, h[:])
	if err := verifySignature("RS256", &short.PublicKey, signed, sig); err == nil {
		t.Error("1024-bit key accepted")
	}
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	sig, _ = rsa.SignPKCS1v15(rand.Reader, good, crypto.SHA256, h[:])
	for _, e := range []int{0, 1, 2, 65536} {
		pub := &rsa.PublicKey{N: good.N, E: e}
		if err := verifySignature("RS256", pub, signed, sig); err == nil {
			t.Errorf("exponent %d accepted", e)
		}
	}
}

// The header's alg does not pick the key: RS256 with an EC key, ES256 with
// an RSA key, none and HS256 are rejected.
func TestAlgSwapped(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		alg string
		key crypto.PublicKey
	}{
		{"RS256", &ec.PublicKey}, {"ES256", &rs.PublicKey},
		{"none", &rs.PublicKey}, {"HS256", &rs.PublicKey}, {"rs256", &rs.PublicKey}, {"", &rs.PublicKey},
	}
	for _, c := range cases {
		if err := verifySignature(c.alg, c.key, "a.b", make([]byte, 256)); err == nil {
			t.Errorf("alg %q with %T accepted", c.alg, c.key)
		}
	}
}
