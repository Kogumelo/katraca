// Package senha guarda e confere senhas.
//
// Hash novo e sempre argon2id, no formato PHC
// ("$argon2id$v=19$m=...,t=...,p=...$sal$hash"). Hash antigo em bcrypt
// ("$2a$", "$2b$", "$2y$") ainda confere — e o caminho de quem migra, como o
// Zebra de Chapeu —, mas a conferencia avisa que e hora de trocar. Avisa
// tambem quando o argon2id foi gerado com parametros mais fracos que os de
// agora.
//
// A conferencia sem usuario gasta o mesmo tempo que com usuario: quem mede o
// tempo da resposta nao descobre quais logins existem.
package senha

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Parametros do argon2id. O padrao e o minimo da OWASP (2024): 19 MiB, duas
// passadas, uma via. Servidor com folga de memoria pode subir Memoria.
type Parametros struct {
	Memoria  uint32 // KiB
	Passadas uint32
	Vias     uint8
	Sal      uint32 // bytes
	Tamanho  uint32 // bytes do hash
}

// Padrao sao os parametros usados quando o app nao escolhe outros.
var Padrao = Parametros{Memoria: 19 * 1024, Passadas: 2, Vias: 1, Sal: 16, Tamanho: 32}

// ErrHashInvalido: o texto guardado nao e um hash que esta biblioteca conheca.
var ErrHashInvalido = errors.New("senha: hash em formato desconhecido")

// Os tetos do custo. O hash vem do banco, e qualquer pessoa que tente entrar
// naquela conta paga o custo dele no servidor: um hash com 4 GiB ou bilhoes
// de passadas, gravado por quem alcancou o banco ou importado de outro
// sistema, derrubaria o app a cada tentativa. Acima disto, ErrHashInvalido.
// Os tetos ficam muito acima de qualquer recomendacao para login na web
// (OWASP: 19 a 46 MiB; RFC 9106: 64 MiB, t=3).
const (
	tetoMemoria  = 256 * 1024 // KiB
	tetoPassadas = 32
	tetoVias     = 16
	tetoSal      = 64 // bytes
	tetoTamanho  = 64 // bytes
	tetoBcrypt   = 15 // custo; o padrao do Go e 10
)

func (p Parametros) acimaDoTeto() bool {
	return p.Memoria > tetoMemoria || p.Passadas > tetoPassadas || p.Vias > tetoVias ||
		p.Sal > tetoSal || p.Tamanho > tetoTamanho
}

// Gerar devolve o hash argon2id da senha. Nao confere regras: isso e Regras.
// Parametros acima dos tetos de Conferir dao erro: o hash nao serviria.
func (p Parametros) Gerar(senha string) (string, error) {
	p = p.completar()
	if p.acimaDoTeto() {
		return "", fmt.Errorf("senha: parametros acima do teto (memoria %d KiB, %d passadas, %d vias, sal e hash de %d bytes)",
			tetoMemoria, tetoPassadas, tetoVias, tetoTamanho)
	}
	sal := make([]byte, p.Sal)
	rand.Read(sal)
	h := argon2.IDKey([]byte(senha), sal, p.Passadas, p.Memoria, p.Vias, p.Tamanho)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memoria, p.Passadas, p.Vias, b64.EncodeToString(sal), b64.EncodeToString(h)), nil
}

func (p Parametros) completar() Parametros {
	if p.Memoria == 0 {
		p.Memoria = Padrao.Memoria
	}
	if p.Passadas == 0 {
		p.Passadas = Padrao.Passadas
	}
	if p.Vias == 0 {
		p.Vias = Padrao.Vias
	}
	if p.Sal == 0 {
		p.Sal = Padrao.Sal
	}
	if p.Tamanho == 0 {
		p.Tamanho = Padrao.Tamanho
	}
	return p
}

// Conferir diz se senha bate com hash e, se bate, se o hash deve ser trocado
// por um novo (Gerar) — porque e bcrypt ou argon2id com parametros abaixo dos
// de p. O app que recebe trocar=true grava o hash novo; sem isso, quem veio do
// bcrypt nunca sai dele. Hash com custo acima dos tetos (argon2id com mais de
// 256 MiB, 32 passadas ou 16 vias; bcrypt com custo acima de 15) da
// ErrHashInvalido sem ser calculado.
func (p Parametros) Conferir(hash, senha string) (ok, trocar bool, err error) {
	p = p.completar()
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		lido, sal, h, err := lerArgon2id(hash)
		if err != nil {
			return false, false, err
		}
		calc := argon2.IDKey([]byte(senha), sal, lido.Passadas, lido.Memoria, lido.Vias, uint32(len(h)))
		if subtle.ConstantTimeCompare(calc, h) != 1 {
			return false, false, nil
		}
		trocar = lido.Memoria < p.Memoria || lido.Passadas < p.Passadas || lido.Vias < p.Vias || uint32(len(h)) < p.Tamanho
		return true, trocar, nil
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		if custo, err := bcrypt.Cost([]byte(hash)); err != nil || custo > tetoBcrypt {
			return false, false, ErrHashInvalido
		}
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(senha))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}
		if err != nil {
			return false, false, fmt.Errorf("%w: %v", ErrHashInvalido, err)
		}
		return true, true, nil
	}
	return false, false, ErrHashInvalido
}

func lerArgon2id(hash string) (Parametros, []byte, []byte, error) {
	partes := strings.Split(hash, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", sal, hash
	if len(partes) != 6 {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	var v int
	if _, err := fmt.Sscanf(partes[2], "v=%d", &v); err != nil || v != argon2.Version {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	var p Parametros
	if _, err := fmt.Sscanf(partes[3], "m=%d,t=%d,p=%d", &p.Memoria, &p.Passadas, &p.Vias); err != nil {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	if p.Memoria == 0 || p.Passadas == 0 || p.Vias == 0 {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	b64 := base64.RawStdEncoding
	sal, err1 := b64.DecodeString(partes[4])
	h, err2 := b64.DecodeString(partes[5])
	if err1 != nil || err2 != nil || len(sal) < 8 || len(h) < 16 {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	p.Sal, p.Tamanho = uint32(len(sal)), uint32(len(h))
	if p.acimaDoTeto() {
		return Parametros{}, nil, nil, ErrHashInvalido
	}
	return p, sal, h, nil
}
