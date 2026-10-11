// Package password stores and verifies passwords.
//
// New hashes are always argon2id, in PHC format
// ("$argon2id$v=19$m=...,t=...,p=...$salt$hash"). Old bcrypt hashes
// ("$2a$", "$2b$", "$2y$") still verify — that is the path for apps migrating,
// like Zebra de Chapeu —, but verification signals that it is time to
// rehash. It also signals when the argon2id hash was made with weaker
// parameters than the current ones.
//
// Verification without a user takes the same time as with a user: whoever
// measures the response time cannot learn which logins exist.
package password

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

// Params are the argon2id parameters. The default is the OWASP minimum
// (2024): 19 MiB, two iterations, one lane. A server with spare memory can
// raise Memory.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32 // bytes
	KeyLen      uint32 // bytes of the hash
}

// Default are the parameters used when the app does not choose others.
var Default = Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}

// ErrInvalidHash means the stored text is not a hash this library knows.
var ErrInvalidHash = errors.New("password: unknown hash format")

// The cost ceilings. The hash comes from the database, and anyone who tries
// to sign in to that account pays its cost on the server: a hash with 4 GiB
// or billions of iterations, written by someone who reached the database or
// imported from another system, would bring the app down on every attempt.
// Above these, ErrInvalidHash. The ceilings sit far above any recommendation
// for web login (OWASP: 19 to 46 MiB; RFC 9106: 64 MiB, t=3).
const (
	maxMemory      = 256 * 1024 // KiB
	maxIterations  = 32
	maxParallelism = 16
	maxSaltLen     = 64 // bytes
	maxKeyLen      = 64 // bytes
	maxBcryptCost  = 15 // Go's default is 10
)

func (p Params) aboveCeiling() bool {
	return p.Memory > maxMemory || p.Iterations > maxIterations || p.Parallelism > maxParallelism ||
		p.SaltLen > maxSaltLen || p.KeyLen > maxKeyLen
}

// Hash returns the argon2id hash of password. It does not check rules: that
// is Rules. Parameters above the ceilings of Verify return an error: the hash
// would be useless.
func (p Params) Hash(password string) (string, error) {
	p = p.withDefaults()
	if p.aboveCeiling() {
		return "", fmt.Errorf("password: parameters above the ceiling (memory %d KiB, %d iterations, %d lanes, salt and hash of %d bytes)",
			maxMemory, maxIterations, maxParallelism, maxKeyLen)
	}
	salt := make([]byte, p.SaltLen)
	rand.Read(salt)
	h := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(h)), nil
}

func (p Params) withDefaults() Params {
	if p.Memory == 0 {
		p.Memory = Default.Memory
	}
	if p.Iterations == 0 {
		p.Iterations = Default.Iterations
	}
	if p.Parallelism == 0 {
		p.Parallelism = Default.Parallelism
	}
	if p.SaltLen == 0 {
		p.SaltLen = Default.SaltLen
	}
	if p.KeyLen == 0 {
		p.KeyLen = Default.KeyLen
	}
	return p
}

// Verify reports whether password matches hash and, if it does, whether the
// hash should be replaced by a new one (Hash) — because it is bcrypt or
// argon2id with parameters below those of p. The app that gets rehash=true
// stores the new hash; without that, whoever came from bcrypt never leaves
// it. A hash with cost above the ceilings (argon2id with more than 256 MiB,
// 32 iterations or 16 lanes; bcrypt with cost above 15) returns
// ErrInvalidHash without being computed.
func (p Params) Verify(hash, password string) (ok, rehash bool, err error) {
	p = p.withDefaults()
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		parsed, salt, h, err := parseArgon2id(hash)
		if err != nil {
			return false, false, err
		}
		calc := argon2.IDKey([]byte(password), salt, parsed.Iterations, parsed.Memory, parsed.Parallelism, uint32(len(h)))
		if subtle.ConstantTimeCompare(calc, h) != 1 {
			return false, false, nil
		}
		rehash = parsed.Memory < p.Memory || parsed.Iterations < p.Iterations || parsed.Parallelism < p.Parallelism || uint32(len(h)) < p.KeyLen
		return true, rehash, nil
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost > maxBcryptCost {
			return false, false, ErrInvalidHash
		}
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, false, nil
		}
		if err != nil {
			return false, false, fmt.Errorf("%w: %v", ErrInvalidHash, err)
		}
		return true, true, nil
	}
	return false, false, ErrInvalidHash
}

func parseArgon2id(hash string) (Params, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	h, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(h) < 16 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(h))
	if p.aboveCeiling() {
		return Params{}, nil, nil, ErrInvalidHash
	}
	return p, salt, h, nil
}
