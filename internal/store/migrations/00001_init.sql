-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id                  text PRIMARY KEY,
    email               citext UNIQUE NOT NULL,
    email_verified_at   timestamptz,
    phone               text UNIQUE,
    phone_verified_at   timestamptz,
    password_hash       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    disabled_at         timestamptz
);

CREATE TABLE identities (
    id              text PRIMARY KEY,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        text NOT NULL,
    subject         text NOT NULL,
    email           text,
    email_verified  boolean NOT NULL DEFAULT false,
    raw_profile     jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX identities_user_id_idx ON identities (user_id);

CREATE TABLE app_clients (
    id              text PRIMARY KEY,
    name            text NOT NULL,
    secret_hash     text NOT NULL,
    redirect_uris   text[] NOT NULL DEFAULT '{}',
    audience        text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          text PRIMARY KEY,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES app_clients(id),
    family_id   text NOT NULL,
    parent_id   text,
    token_hash  bytea NOT NULL UNIQUE,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz,
    user_agent  text,
    ip          text
);
CREATE INDEX sessions_family_idx  ON sessions (family_id);
CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- every refresh is an UPDATE plus an INSERT; dead tuples pile up fast here
ALTER TABLE sessions SET (autovacuum_vacuum_scale_factor = 0.02);

CREATE TABLE auth_codes (
    code_hash    bytea PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    text NOT NULL REFERENCES app_clients(id),
    redirect_uri text NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz
);

CREATE TABLE otp_codes (
    id          text PRIMARY KEY,
    identifier  text NOT NULL,
    code_hash   bytea NOT NULL,
    purpose     text NOT NULL,
    attempts    int NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX otp_codes_identifier_idx ON otp_codes (identifier, purpose);

-- +goose Down
DROP TABLE otp_codes;
DROP TABLE auth_codes;
DROP TABLE sessions;
DROP TABLE app_clients;
DROP TABLE identities;
DROP TABLE users;
