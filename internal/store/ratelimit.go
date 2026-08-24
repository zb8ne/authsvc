package store

import (
	"context"
	"time"
)

// Allow implements a fixed-window counter keyed on bucket. It returns false once
// the window's count exceeds limit.
//
// Buckets should be namespaced by both action and subject, e.g.
// "login:ip:1.2.3.4" and "login:id:user@example.com", so a distributed attempt
// against one account and a single IP spraying many accounts are both caught.
func (db *DB) Allow(ctx context.Context, bucket string, limit int, window time.Duration) (bool, error) {
	start := db.now().Truncate(window)
	var count int
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO rate_limits (bucket, window_start, count)
		VALUES ($1, $2, 1)
		ON CONFLICT (bucket, window_start)
		DO UPDATE SET count = rate_limits.count + 1
		RETURNING count`, bucket, start).Scan(&count)
	if err != nil {
		return false, err
	}
	return count <= limit, nil
}

// PruneRateLimits drops windows that have rolled over.
func (db *DB) PruneRateLimits(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM rate_limits WHERE window_start < $1`, db.now().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
