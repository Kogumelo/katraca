package provedor

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

// Conferencia minima de JWS compacto: so o que um id_token OIDC usa — RS256
// (Google, Microsoft, Apple) e ES256. A biblioteca nao aceita "none" nem HS*:
// a chave tem de vir do JWKS do emissor.

type chaveJWK struct {
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
	Keys []chaveJWK `json:"keys"`
}

func (k chaveJWK) publica() (crypto.PublicKey, error) {
	b64 := base64.RawURLEncoding
	switch k.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			return nil, errors.New("jwk RSA ilegivel")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("curva %q nao suportada", k.Crv)
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("jwk EC ilegivel")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("jwk EC fora da curva")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("tipo de chave %q nao suportado", k.Kty)
}

type cabecalhoJWT struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// partirJWT separa o token e le o cabecalho, sem conferir nada.
func partirJWT(token string) (cabecalhoJWT, []byte, []byte, string, error) {
	partes := strings.Split(token, ".")
	if len(partes) != 3 {
		return cabecalhoJWT{}, nil, nil, "", errors.New("jwt malformado")
	}
	b64 := base64.RawURLEncoding
	cab, err1 := b64.DecodeString(partes[0])
	corpo, err2 := b64.DecodeString(partes[1])
	ass, err3 := b64.DecodeString(partes[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return cabecalhoJWT{}, nil, nil, "", errors.New("jwt malformado")
	}
	var c cabecalhoJWT
	if err := json.Unmarshal(cab, &c); err != nil {
		return cabecalhoJWT{}, nil, nil, "", errors.New("jwt com cabecalho ilegivel")
	}
	return c, corpo, ass, partes[0] + "." + partes[1], nil
}

func conferirAssinatura(alg string, chave crypto.PublicKey, assinado string, ass []byte) error {
	h := sha256.Sum256([]byte(assinado))
	switch alg {
	case "RS256":
		pub, ok := chave.(*rsa.PublicKey)
		if !ok {
			return errors.New("alg RS256 com chave que nao e RSA")
		}
		if pub.N.BitLen() < 2048 {
			return errors.New("chave RSA curta demais")
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], ass)
	case "ES256":
		pub, ok := chave.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("alg ES256 com chave que nao e EC")
		}
		if len(ass) != 64 {
			return errors.New("assinatura ES256 com tamanho errado")
		}
		r := new(big.Int).SetBytes(ass[:32])
		s := new(big.Int).SetBytes(ass[32:])
		if !ecdsa.Verify(pub, h[:], r, s) {
			return errors.New("assinatura ES256 nao confere")
		}
		return nil
	}
	return fmt.Errorf("alg %q nao aceito", alg)
}
