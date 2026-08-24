package store

import (
	"context"
	"os"
	"sync"
	"testing"
)

// Two instances deploying at once must not race on CREATE TABLE. This is the
// production case (a rolling deploy) as much as the test one.
func TestConcurrentMigrationsSerialise(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = Migrate(context.Background(), dsn)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent migration %d failed: %v", i, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Migrate(ctx, dsn); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}
