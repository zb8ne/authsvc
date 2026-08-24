-- +goose Up
-- One row per in-flight OAuth round trip. State is server-side rather than a
-- signed cookie so it can be enforced single-use (replay protection) and so the
-- flow survives the redirect without depending on cookie behaviour across the
-- provider's domain.
CREATE TABLE oauth_flows (
    state_hash    bytea PRIMARY KEY,
    provider      text NOT NULL,
    client_id     text NOT NULL REFERENCES app_clients(id),
    redirect_uri  text NOT NULL,
    app_state     text NOT NULL DEFAULT '',
    code_verifier text NOT NULL,
    link_user_id  text REFERENCES users(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz
);
CREATE INDEX oauth_flows_expires_idx ON oauth_flows (expires_at);

-- +goose Down
DROP TABLE oauth_flows;
