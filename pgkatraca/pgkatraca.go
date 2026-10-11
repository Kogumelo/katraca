// Package pgkatraca e a Guarda de referencia em Postgres, com pgx. Serve a
// prova por e-mail (email.Guarda) e a senha (senha.Guarda).
//
// E opcional: o nucleo da biblioteca nao importa pgx, e um app com lib/pq ou
// database/sql escreve a propria Guarda — o SQL daqui e o contrato em
// email/emailteste mostram o que ela precisa fazer.
package pgkatraca

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/Kogumelo/katraca"
	"github.com/Kogumelo/katraca/email"
	"github.com/Kogumelo/katraca/senha"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Esquema e o SQL das tabelas. Idempotente (IF NOT EXISTS).
//
//go:embed esquema.sql
var Esquema string

// Banco e o que a Guarda usa do pgx: *pgxpool.Pool e *pgx.Conn servem.
type Banco interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Guarda guarda provas e senhas nas tabelas de Esquema.
type Guarda struct {
	Banco Banco
}

var (
	_ email.Guarda = (*Guarda)(nil)
	_ senha.Guarda = (*Guarda)(nil)
)

// CriarTabelas roda Esquema. Para quem nao tem migracoes proprias.
func (g *Guarda) CriarTabelas(ctx context.Context) error {
	_, err := g.Banco.Exec(ctx, Esquema)
	return err
}

func (g *Guarda) Emitir(ctx context.Context, e email.Emissao, maximo int, desde time.Time) error {
	tx, err := g.Banco.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// A trava por endereco junta contar e guardar: dois pedidos simultaneos
	// para o mesmo e-mail esperam um pelo outro, e o limite vale.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('katraca_prova:' || $1, 0))`, e.Email); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM katraca_prova WHERE email = $1 AND criada_em > $2`,
		e.Email, desde).Scan(&n); err != nil {
		return err
	}
	if n >= maximo {
		return katraca.ErrMuitosPedidos
	}
	if e.Forma == email.Codigo {
		if _, err := tx.Exec(ctx, `
			UPDATE katraca_prova SET usada_em = $3
			 WHERE email = $1 AND finalidade = $2 AND forma = 'codigo' AND usada_em IS NULL`,
			e.Email, string(e.Finalidade), e.Criada); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO katraca_prova (id, email, finalidade, forma, hash, criada_em, expira_em)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.Email, string(e.Finalidade), string(e.Forma), e.Hash, e.Criada, e.Expira); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const colunas = `id, email, finalidade, forma, hash, criada_em, expira_em, tentativas`

func ler(row pgx.Row) (email.Emissao, error) {
	var e email.Emissao
	var f, forma string
	err := row.Scan(&e.ID, &e.Email, &f, &forma, &e.Hash, &e.Criada, &e.Expira, &e.Tentativas)
	if errors.Is(err, pgx.ErrNoRows) {
		return email.Emissao{}, email.ErrNaoHa
	}
	e.Finalidade, e.Forma = email.Finalidade(f), email.Forma(forma)
	return e, err
}

func (g *Guarda) GastarLink(ctx context.Context, hash []byte, f email.Finalidade) (email.Emissao, error) {
	// Conferir e gastar na mesma instrucao: de dois cliques, so um acha
	// usada_em nulo.
	return ler(g.Banco.QueryRow(ctx, `
		UPDATE katraca_prova SET usada_em = now()
		 WHERE forma = 'link' AND hash = $1 AND finalidade = $2 AND usada_em IS NULL
		RETURNING `+colunas, hash, string(f)))
}

func (g *Guarda) TentarCodigo(ctx context.Context, endereco string, f email.Finalidade) (email.Emissao, error) {
	return ler(g.Banco.QueryRow(ctx, `
		UPDATE katraca_prova SET tentativas = tentativas + 1
		 WHERE id = (SELECT id FROM katraca_prova
		              WHERE forma = 'codigo' AND email = $1 AND finalidade = $2 AND usada_em IS NULL
		              ORDER BY criada_em DESC LIMIT 1
		              FOR UPDATE)
		RETURNING `+colunas, endereco, string(f)))
}

func (g *Guarda) Gastar(ctx context.Context, id string) (bool, error) {
	tag, err := g.Banco.Exec(ctx, `UPDATE katraca_prova SET usada_em = now() WHERE id = $1 AND usada_em IS NULL`, id)
	return tag.RowsAffected() == 1, err
}

// Limpar apaga as provas vencidas antes de antes. Rode de vez em quando
// (uma vez por dia basta); antes deve ficar alem da janela do limite por
// endereco, ou o limite esquece pedidos recentes.
func (g *Guarda) Limpar(ctx context.Context, antes time.Time) (int64, error) {
	tag, err := g.Banco.Exec(ctx, `DELETE FROM katraca_prova WHERE expira_em < $1 AND criada_em < $1`, antes)
	return tag.RowsAffected(), err
}

func (g *Guarda) Credencial(ctx context.Context, login string) (senha.Credencial, error) {
	var c senha.Credencial
	err := g.Banco.QueryRow(ctx, `
		SELECT hash, email, email_garantido FROM katraca_senha WHERE login = $1`, login).
		Scan(&c.Hash, &c.Email, &c.EmailGarantido)
	if errors.Is(err, pgx.ErrNoRows) {
		return senha.Credencial{}, senha.ErrNaoHa
	}
	return c, err
}

func (g *Guarda) TrocarHash(ctx context.Context, login, antigo, novo string) error {
	_, err := g.Banco.Exec(ctx, `
		UPDATE katraca_senha SET hash = $3, trocada_em = now() WHERE login = $1 AND hash = $2`,
		login, antigo, novo)
	return err
}

// GravarSenha cria ou troca a senha de login (cadastro, redefinicao). O hash
// vem de senha.Senhas.Gerar.
func (g *Guarda) GravarSenha(ctx context.Context, login, hash string, c senha.Credencial) error {
	_, err := g.Banco.Exec(ctx, `
		INSERT INTO katraca_senha (login, hash, email, email_garantido) VALUES ($1, $2, $3, $4)
		ON CONFLICT (login) DO UPDATE
		   SET hash = EXCLUDED.hash, email = EXCLUDED.email,
		       email_garantido = EXCLUDED.email_garantido, trocada_em = now()`,
		login, hash, c.Email, c.EmailGarantido)
	return err
}
