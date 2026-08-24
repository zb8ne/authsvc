package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// migrateLockID is an arbitrary but fixed key for the advisory lock that
// serialises migrations. Any value works as long as it never changes.
const migrateLockID int64 = 8148291374520011

// Migrate applies all pending migrations.
//
// In production this runs as a release command, never in-process on boot: a bad
// migration should fail the deploy rather than crashloop the service.
//
// It holds a Postgres advisory lock for the duration, so concurrent callers
// serialise instead of racing. Without it, two instances starting at once — a
// rolling deploy, or parallel test packages — can both decide the same
// migration is pending and collide on CREATE TABLE.
func Migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// One connection means the advisory lock and the migrations necessarily
	// share a session, which is what makes the lock cover the whole run.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrateLockID); err != nil {
		return fmt.Errorf("store: acquire migration lock: %w", err)
	}
	defer func() {
		// The lock is session-scoped and dies with the connection regardless,
		// so a failure to release cannot strand it.
		_, _ = db.ExecContext(context.WithoutCancel(ctx),
			"SELECT pg_advisory_unlock($1)", migrateLockID)
	}()

	goose.SetBaseFS(Migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.UpContext(ctx, db, "migrations")
}
