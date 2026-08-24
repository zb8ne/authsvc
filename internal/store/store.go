// Package store is the Postgres persistence layer.
package store

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var Migrations embed.FS

var (
	ErrNotFound = errors.New("store: not found")
	// ErrTokenReuse is returned when a refresh token that was already spent is
	// presented again. The caller must treat this as a compromise, not a retry.
	ErrTokenReuse = errors.New("store: refresh token reuse detected")
)

type DB struct {
	Pool *pgxpool.Pool
	now  func() time.Time
}

func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{Pool: pool, now: time.Now}, nil
}

func (db *DB) Close() { db.Pool.Close() }

// Health verifies actual DB connectivity, not just process liveness.
func (db *DB) Health(ctx context.Context) error {
	var one int
	return db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one)
}

func norows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
