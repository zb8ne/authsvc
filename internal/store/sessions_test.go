package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// fixture creates an isolated user + client so tests don't collide.
func fixture(t *testing.T, db *DB) (userID, clientID string) {
	t.Helper()
	ctx := context.Background()
	suffix := ulid.Make().String()
	u, err := db.CreateUser(ctx, "u-"+suffix+"@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientID = "c-" + suffix
	if err := db.CreateClient(ctx, Client{
		ID: clientID, Name: "test", SecretHash: "x",
		RedirectURIs: []string{"https://app.test/cb"}, Audience: clientID,
	}); err != nil {
		t.Fatal(err)
	}
	return u.ID, clientID
}

func TestCreateSessionStartsItsOwnFamily(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	a, err := db.CreateSession(ctx, uid, cid, SessionMeta{IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.CreateSession(ctx, uid, cid, SessionMeta{IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Session.FamilyID == b.Session.FamilyID {
		t.Fatal("two separate logins share a family; revoking one would kill the other")
	}
	if a.Session.FamilyID != a.Session.ID {
		t.Fatal("a fresh login should root its own family")
	}
	if a.RefreshToken == "" || a.RefreshToken == b.RefreshToken {
		t.Fatal("refresh tokens are empty or not unique")
	}
}

func TestRawRefreshTokenIsNeverStored(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	iss, err := db.CreateSession(ctx, uid, cid, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE encode(token_hash,'escape') = $1`, iss.RefreshToken).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("raw refresh token found in sessions.token_hash")
	}
}

func TestRotateIssuesNewTokenInSameFamily(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	first, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	second, err := db.Rotate(ctx, first.RefreshToken, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same token")
	}
	if second.Session.FamilyID != first.Session.FamilyID {
		t.Fatal("rotation started a new family; lineage is broken")
	}
	if second.Session.ParentID == nil || *second.Session.ParentID != first.Session.ID {
		t.Fatal("parent_id does not point at the spent session")
	}

	old, err := db.SessionByID(ctx, first.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.UsedAt == nil {
		t.Fatal("spent session was not stamped used_at")
	}
}

func TestRotateChainWorksRepeatedly(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	cur, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	family := cur.Session.FamilyID
	for i := 0; i < 5; i++ {
		next, err := db.Rotate(ctx, cur.RefreshToken, SessionMeta{})
		if err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
		cur = next
	}
	rows, err := db.SessionsForFamily(ctx, family)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		t.Fatalf("family has %d rows after 5 rotations, want 6", len(rows))
	}
}

// This is the test the spec demands before anything downstream is written.
func TestReplayingUsedTokenRevokesEntireFamily(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	first, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	family := first.Session.FamilyID

	second, err := db.Rotate(ctx, first.RefreshToken, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	third, err := db.Rotate(ctx, second.RefreshToken, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}

	// The attacker replays the very first token, which was already spent.
	if _, err := db.Rotate(ctx, first.RefreshToken, SessionMeta{}); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("replay returned %v, want ErrTokenReuse", err)
	}

	rows, err := db.SessionsForFamily(ctx, family)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("family is empty")
	}
	for _, s := range rows {
		if s.RevokedAt == nil {
			t.Errorf("session %s in family %s was not revoked after reuse detection", s.ID, family)
		}
	}

	// And the currently-live token must be dead too — that's the whole point.
	if _, err := db.Rotate(ctx, third.RefreshToken, SessionMeta{}); err == nil {
		t.Fatal("the live token still rotates after its family was revoked")
	}
}

func TestReuseDetectionDoesNotTouchOtherFamilies(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	victim, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	bystander, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})

	if _, err := db.Rotate(ctx, victim.RefreshToken, SessionMeta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Rotate(ctx, victim.RefreshToken, SessionMeta{}); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("want ErrTokenReuse, got %v", err)
	}

	if _, err := db.Rotate(ctx, bystander.RefreshToken, SessionMeta{}); err != nil {
		t.Fatalf("an unrelated session was collaterally revoked: %v", err)
	}
}

func TestRotateRejectsUnknownToken(t *testing.T) {
	db := testDB(t)
	if _, err := db.Rotate(context.Background(), "not-a-real-token", SessionMeta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRotateRejectsExpiredToken(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	db.now = func() time.Time { return time.Now().Add(-RefreshTTL - time.Hour) }
	old, err := db.CreateSession(ctx, uid, cid, SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	db.now = time.Now

	if _, err := db.Rotate(ctx, old.RefreshToken, SessionMeta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token rotated: %v", err)
	}
}

func TestRotateRejectsRevokedToken(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	iss, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	if err := db.RevokeFamily(ctx, iss.Session.FamilyID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Rotate(ctx, iss.RefreshToken, SessionMeta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token rotated: %v", err)
	}
}

// Two clients racing the same token must not both walk away with a valid
// session; the loser must trip reuse detection.
func TestConcurrentRotationOfSameTokenYieldsExactlyOneWinner(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	iss, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})

	const n = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		reuses   int
		othererr error
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := db.Rotate(ctx, iss.RefreshToken, SessionMeta{})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrTokenReuse):
				reuses++
			default:
				othererr = err
			}
		}()
	}
	close(start)
	wg.Wait()

	if othererr != nil {
		t.Fatalf("unexpected error during race: %v", othererr)
	}
	if wins != 1 {
		t.Fatalf("%d goroutines rotated the same token successfully, want exactly 1", wins)
	}
	if reuses != n-1 {
		t.Fatalf("got %d reuse detections, want %d", reuses, n-1)
	}
}

func TestRevokeAllForUser(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	a, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	b, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	if err := db.RevokeAllForUser(ctx, uid); err != nil {
		t.Fatal(err)
	}
	for _, iss := range []*IssuedSession{a, b} {
		if _, err := db.Rotate(ctx, iss.RefreshToken, SessionMeta{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session still live after logout-all: %v", err)
		}
	}
}

func TestRevokeByTokenKillsTheWholeLineage(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	first, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	second, _ := db.Rotate(ctx, first.RefreshToken, SessionMeta{})

	if err := db.RevokeByToken(ctx, second.RefreshToken); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.SessionsForFamily(ctx, first.Session.FamilyID)
	for _, s := range rows {
		if s.RevokedAt == nil {
			t.Errorf("session %s survived logout", s.ID)
		}
	}
}

func TestActiveSessionsForUserExcludesSpentAndRevoked(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	live, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	spent, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	rotated, _ := db.Rotate(ctx, spent.RefreshToken, SessionMeta{})

	got, err := db.ActiveSessionsForUser(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range got {
		ids[s.ID] = true
	}
	if !ids[live.Session.ID] || !ids[rotated.Session.ID] {
		t.Fatal("a live session is missing from the active list")
	}
	if ids[spent.Session.ID] {
		t.Fatal("a spent session is listed as active")
	}
}

func TestPruneRemovesOnlyLongExpiredRows(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	uid, cid := fixture(t, db)

	db.now = func() time.Time { return time.Now().Add(-RefreshTTL - 60*24*time.Hour) }
	stale, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})
	db.now = time.Now
	fresh, _ := db.CreateSession(ctx, uid, cid, SessionMeta{})

	if _, err := db.PruneSessions(ctx, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionByID(ctx, stale.Session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("long-expired session survived the prune")
	}
	if _, err := db.SessionByID(ctx, fresh.Session.ID); err != nil {
		t.Fatalf("prune removed a live session: %v", err)
	}
}
