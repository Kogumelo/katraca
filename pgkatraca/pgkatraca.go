// Package pgkatraca is the reference Store in Postgres, with pgx. It serves
// the email proof (email.Store) and the password (password.Store).
//
// It is optional: the library core does not import pgx, and an app with
// lib/pq or database/sql writes its own Store — the SQL here and the contract
// in email/emailtest show what it needs to do.
package pgkatraca

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/password"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Schema is the SQL of the tables. Idempotent (IF NOT EXISTS).
//
//go:embed schema.sql
var Schema string

// DB is what the Store uses from pgx: *pgxpool.Pool and *pgx.Conn both fit.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store keeps proofs and passwords in the tables of Schema.
type Store struct {
	DB DB
}

var (
	_ email.Store    = (*Store)(nil)
	_ password.Store = (*Store)(nil)
)

// CreateTables runs Schema. For those without migrations of their own.
func (s *Store) CreateTables(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, Schema)
	return err
}

func (s *Store) Issue(ctx context.Context, e email.Issuance, max int, since time.Time) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// The per-address lock ties counting and storing together: two
	// simultaneous requests for the same email wait for each other, and the
	// limit holds.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('katraca_proof:' || $1, 0))`, e.Email); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM katraca_proof WHERE email = $1 AND created_at > $2`,
		e.Email, since).Scan(&n); err != nil {
		return err
	}
	if n >= max {
		return katraca.ErrTooManyRequests
	}
	if e.Kind == email.Code {
		if _, err := tx.Exec(ctx, `
			UPDATE katraca_proof SET used_at = $3
			 WHERE email = $1 AND purpose = $2 AND kind = 'code' AND used_at IS NULL`,
			e.Email, string(e.Purpose), e.Created); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO katraca_proof (id, email, purpose, kind, hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.Email, string(e.Purpose), string(e.Kind), e.Hash, e.Created, e.Expires); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const columns = `id, email, purpose, kind, hash, created_at, expires_at, attempts`

func scan(row pgx.Row) (email.Issuance, error) {
	var e email.Issuance
	var purpose, kind string
	err := row.Scan(&e.ID, &e.Email, &purpose, &kind, &e.Hash, &e.Created, &e.Expires, &e.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return email.Issuance{}, email.ErrNotFound
	}
	e.Purpose, e.Kind = email.Purpose(purpose), email.Kind(kind)
	return e, err
}

func (s *Store) ConsumeLink(ctx context.Context, hash []byte, p email.Purpose) (email.Issuance, error) {
	// Check and consume in the same statement: of two clicks, only one finds
	// used_at null.
	return scan(s.DB.QueryRow(ctx, `
		UPDATE katraca_proof SET used_at = now()
		 WHERE kind = 'link' AND hash = $1 AND purpose = $2 AND used_at IS NULL
		RETURNING `+columns, hash, string(p)))
}

func (s *Store) AttemptCode(ctx context.Context, address string, p email.Purpose, since time.Time) (email.Issuance, int, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return email.Issuance{}, 0, err
	}
	defer tx.Rollback(ctx)
	// The same lock as Issue: adding the attempt and counting the day's
	// attempts are not separated, and two simultaneous attempts do not count
	// one without the other.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('katraca_proof:' || $1, 0))`, address); err != nil {
		return email.Issuance{}, 0, err
	}
	e, err := scan(tx.QueryRow(ctx, `
		UPDATE katraca_proof SET attempts = attempts + 1
		 WHERE id = (SELECT id FROM katraca_proof
		              WHERE kind = 'code' AND email = $1 AND purpose = $2 AND used_at IS NULL
		              ORDER BY created_at DESC LIMIT 1
		              FOR UPDATE)
		RETURNING `+columns, address, string(p)))
	if err != nil {
		return email.Issuance{}, 0, err
	}
	var inWindow int
	if err := tx.QueryRow(ctx, `
		SELECT coalesce(sum(attempts), 0) FROM katraca_proof
		 WHERE kind = 'code' AND email = $1 AND created_at > $2`,
		address, since).Scan(&inWindow); err != nil {
		return email.Issuance{}, 0, err
	}
	return e, inWindow, tx.Commit(ctx)
}

func (s *Store) Consume(ctx context.Context, id string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE katraca_proof SET used_at = now() WHERE id = $1 AND used_at IS NULL`, id)
	return tag.RowsAffected() == 1, err
}

// Purge deletes the proofs that expired before before. Run it now and then
// (once a day is enough); before must be at least email.DailyLimitWindow
// (24 hours) back from now, or the daily attempt limit and the sending
// limit forget what they still count.
func (s *Store) Purge(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM katraca_proof WHERE expires_at < $1 AND created_at < $1`, before)
	return tag.RowsAffected(), err
}

func (s *Store) Credential(ctx context.Context, login string) (password.Credential, error) {
	var c password.Credential
	err := s.DB.QueryRow(ctx, `
		SELECT hash, email, email_verified FROM katraca_password WHERE login = $1`, login).
		Scan(&c.Hash, &c.Email, &c.EmailVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return password.Credential{}, password.ErrNotFound
	}
	return c, err
}

func (s *Store) ReplaceHash(ctx context.Context, login, oldHash, newHash string) error {
	_, err := s.DB.Exec(ctx, `
		UPDATE katraca_password SET hash = $3, updated_at = now() WHERE login = $1 AND hash = $2`,
		login, oldHash, newHash)
	return err
}

// SetPassword creates or replaces the password of login (sign-up, reset). The
// hash comes from password.Passwords.Hash.
func (s *Store) SetPassword(ctx context.Context, login, hash string, c password.Credential) error {
	_, err := s.DB.Exec(ctx, `
		INSERT INTO katraca_password (login, hash, email, email_verified) VALUES ($1, $2, $3, $4)
		ON CONFLICT (login) DO UPDATE
		   SET hash = EXCLUDED.hash, email = EXCLUDED.email,
		       email_verified = EXCLUDED.email_verified, updated_at = now()`,
		login, hash, c.Email, c.EmailVerified)
	return err
}
