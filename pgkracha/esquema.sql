-- Esquema de referencia da biblioteca kracha, em Postgres. O app pode
-- copia-lo para as migracoes dele como esta, adapta-lo, ou ignora-lo e
-- escrever a propria Guarda.

-- Provas por e-mail emitidas (links e codigos). Do segredo, so o hash.
CREATE TABLE IF NOT EXISTS kracha_prova (
    id          text        PRIMARY KEY,
    email       text        NOT NULL,
    finalidade  text        NOT NULL CHECK (finalidade IN ('entrar', 'confirmar', 'redefinir')),
    forma       text        NOT NULL CHECK (forma IN ('link', 'codigo')),
    hash        bytea       NOT NULL,
    criada_em   timestamptz NOT NULL,
    expira_em   timestamptz NOT NULL,
    usada_em    timestamptz,
    tentativas  integer     NOT NULL DEFAULT 0
);

-- O link e achado pelo hash; dois links com o mesmo hash seriam um token
-- repetido, e o indice o recusa.
CREATE UNIQUE INDEX IF NOT EXISTS kracha_prova_link ON kracha_prova (hash) WHERE forma = 'link';
-- O limite por endereco e o codigo vigente sao achados pelo e-mail.
CREATE INDEX IF NOT EXISTS kracha_prova_email ON kracha_prova (email, criada_em);

-- Hashes de senha. Num app com tabela de usuarios, o hash costuma morar la;
-- esta tabela e para quem nao tem onde, e para mostrar o que a Guarda pede.
CREATE TABLE IF NOT EXISTS kracha_senha (
    login           text        PRIMARY KEY,
    hash            text        NOT NULL,
    email           text        NOT NULL DEFAULT '',
    email_garantido boolean     NOT NULL DEFAULT false,
    trocada_em      timestamptz NOT NULL DEFAULT now()
);
