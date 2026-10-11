package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Minimal verification of compact JWS: only what an OIDC id_token uses —
// RS256 (Google, Microsoft, Apple) and ES256. The library accepts neither
// "none" nor HS*: the key has to come from the issuer's JWKS.

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (k jwk) public() (crypto.PublicKey, error) {
	b64 := base64.RawURLEncoding
	switch k.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			return nil, errors.New("unreadable RSA jwk")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("unreadable EC jwk")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC jwk not on the curve")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// splitJWT splits the token and reads the header, without checking anything.
func splitJWT(token string) (jwtHeader, []byte, []byte, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtHeader{}, nil, nil, "", errors.New("malformed jwt")
	}
	b64 := base64.RawURLEncoding
	head, err1 := b64.DecodeString(parts[0])
	body, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return jwtHeader{}, nil, nil, "", errors.New("malformed jwt")
	}
	var h jwtHeader
	if err := json.Unmarshal(head, &h); err != nil {
		return jwtHeader{}, nil, nil, "", errors.New("jwt with unreadable header")
	}
	return h, body, sig, parts[0] + "." + parts[1], nil
}

func verifySignature(alg string, key crypto.PublicKey, signed string, sig []byte) error {
	h := sha256.Sum256([]byte(signed))
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("alg RS256 with a non-RSA key")
		}
		if pub.N.BitLen() < 2048 {
			return errors.New("RSA key too short")
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("alg ES256 with a non-EC key")
		}
		if len(sig) != 64 {
			return errors.New("ES256 signature with wrong size")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, h[:], r, s) {
			return errors.New("ES256 signature mismatch")
		}
		return nil
	}
	return fmt.Errorf("alg %q not accepted", alg)
}
