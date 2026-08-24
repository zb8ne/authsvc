-- +goose Up
-- Fixed-window counters. Postgres is sufficient at this scale; no Redis.
CREATE TABLE rate_limits (
    bucket       text NOT NULL,
    window_start timestamptz NOT NULL,
    count        int NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, window_start)
);
CREATE INDEX rate_limits_window_idx ON rate_limits (window_start);

-- +goose Down
DROP TABLE rate_limits;
