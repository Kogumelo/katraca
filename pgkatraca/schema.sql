-- Reference schema of the katraca library, in Postgres. The app may copy it
-- into its own migrations as is, adapt it, or ignore it and write its own
-- Store.

-- Issued email proofs (links and codes). Of the secret, only the hash.
CREATE TABLE IF NOT EXISTS katraca_proof (
    id          text        PRIMARY KEY,
    email       text        NOT NULL,
    purpose     text        NOT NULL CHECK (purpose IN ('sign_in', 'confirm', 'reset')),
    kind        text        NOT NULL CHECK (kind IN ('link', 'code')),
    hash        bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    attempts    integer     NOT NULL DEFAULT 0
);

-- A link is found by its hash; two links with the same hash would be a
-- repeated token, and the index rejects it.
CREATE UNIQUE INDEX IF NOT EXISTS katraca_proof_link ON katraca_proof (hash) WHERE kind = 'link';
-- The per-address limit and the current code are found by the email.
CREATE INDEX IF NOT EXISTS katraca_proof_email ON katraca_proof (email, created_at);

-- Password hashes. In an app with a users table, the hash usually lives
-- there; this table is for whoever has nowhere else, and to show what the
-- Store needs.
CREATE TABLE IF NOT EXISTS katraca_password (
    login           text        PRIMARY KEY,
    hash            text        NOT NULL,
    email           text        NOT NULL DEFAULT '',
    email_verified  boolean     NOT NULL DEFAULT false,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
