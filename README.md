# authsvc

Standalone authentication service. Deployed once at a fixed domain; every future
project consumes it through a small Go SDK.

Google and GitHub OAuth apps are registered **once**, against one callback URL
(`https://auth.zb8ne.lol/v1/oauth/{provider}/callback`). Onboarding a new app is
then: create a client row, put the secret in env, three lines of SDK. No console
work.

## Quick start

```sh
make db-up          # postgres on :5434
make migrate
make test           # requires the db to be up
```

Or the whole thing in Docker:

```sh
docker compose up --build
```

## Onboarding a new app

```sh
curl -X POST https://auth.zb8ne.lol/v1/admin/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -d '{"id":"dayflow","name":"Dayflow","redirect_uris":["https://dayflow.vercel.app/auth/callback"]}'
```

The response contains `client_secret` **once**; only its hash is stored. Put it
in the app's env as `AUTH_CLIENT_SECRET`.

Redirect URIs are matched **exactly** — no prefixes, no wildcards. Vercel preview
deployments each need their URL registered, or point previews at one stable
callback. Loose matching here is an open redirect that hands over the auth code.

## Using it from an app

```go
auth, _ := authsdk.New(authsdk.Config{
    BaseURL:      "https://auth.zb8ne.lol",
    FallbackURL:  "https://auth-standby.zb8ne.lol",
    ClientID:     "dayflow",
    ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
    Audience:     "dayflow",
})
defer auth.Close()

mux.Handle("GET /me", auth.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    u, _ := authsdk.UserFrom(r.Context())
    fmt.Fprint(w, u.Email)
})))

mux.Handle("GET /admin", auth.RequireUser(auth.RequireRole("admin")(adminHandler)))

// Send the browser here to start a login.
// auth.StartURL("google", "https://dayflow.vercel.app/auth/callback", state)

mux.Handle("GET /auth/callback", auth.HandleCallback(
    func(w http.ResponseWriter, r *http.Request, s *authsdk.Session) {
        // s.AccessToken, s.RefreshToken — set your own cookie, then redirect.
    }))
```

`RequireUser` verifies locally against a cached JWKS. It makes **no network call
on the request path**, so an authsvc outage cannot take down apps that depend on
it — only login and refresh, which are interactive anyway, need the service up.

Cached keys are trusted for at most `JWKSMaxStale` (default **7 days**) after
refreshes start failing. That bounds how long a compromised signing key stays
trusted by an app that cannot reach authsvc; without a bound, rotating a leaked
key out would mean redeploying every dependent app. Past the limit the SDK fails
closed with 503.

### Failed sign-ins

Pass `SignInURL` and the default callback handler renders a readable explanation
instead of an error code. The one that matters is `manual_link_required` — a
user who registered with a password and later clicks "Sign in with Google" hits
it, and it tells them to sign in with their password and link from settings.
Supply your own via `HandleCallbackWithError` to match your design;
`CallbackError.Message()` gives you the wording, `Retryable()` says whether
offering "try again" makes sense.

## How the OAuth handoff works

The callback lands on `auth.zb8ne.lol` and cannot set a cookie for
`someapp.vercel.app`. So:

1. the callback issues a one-time `auth_code` (60s TTL)
2. it redirects to the app's registered `redirect_uri?code=...`
3. the app's **backend** calls `/v1/token/exchange` and sets its own cookie

A `Domain=.zb8ne.lol` cookie would break on Vercel preview URLs, which is exactly
where hackathon demos live. `HandleCallback` does steps 2–3 for you.

## Tokens

**Access** — Ed25519 (`EdDSA`), `kid` in header, 1 hour TTL. 1h rather than 15m
cuts session write volume 4x and means a brief outage does not log everyone out.
The accepted cost: **role changes go stale for up to an hour**, and a revoked
session keeps passing *local* SDK verification until the token expires. authsvc's
own endpoints reject it immediately. For a permission that must revoke instantly,
check it against your own database.

### Revocation is asymmetric — know what `disabled_at` actually means

authsvc's own `requireUser` checks that the session behind a token is still
live, so logout, `disabled_at`, and reuse-detection take effect there
**immediately**. The SDK verifies locally and does not, so a revoked user keeps
working in consuming apps **for up to the access-token TTL — one hour**.

Disabling a compromised account therefore kills authsvc access instantly and
Dayflow access within the hour. That is the deliberate cost of offline
verification: the alternative is a network call on every request, which
reintroduces exactly the coupling the SDK exists to remove.

If you need instant revocation for a specific action, check it against your own
database at the point of use. `internal/e2e` pins this behaviour in a test so a
future change is a decision, not a surprise.

**Refresh** — not a JWT. 32 random bytes, stored only as sha256. httpOnly,
Secure, SameSite=Lax, `Path=/v1/token`, 30-day TTL, rotated on every use.

### Reuse detection

Every refresh inserts a new `sessions` row with the same `family_id` and stamps
`used_at` on the old one. If a token arrives whose row already has `used_at` set,
it was cloned, and **the entire family is revoked**. The legitimate user is
logged out too; that is the intended cost.

Rotation runs in one transaction with `SELECT … FOR UPDATE` on the presented
row, so two concurrent refreshes cannot both succeed.

## Identity linking

An OAuth login links to an existing user **only** when both hold:

1. the provider reports `email_verified = true`, **and**
2. that email is already verified on the target user

Otherwise a new user is created — or, when the address is already taken and the
link would be unsafe, the login is refused with `manual_link_required`. The user
signs in by their existing method and links from settings, which proves control
of both sides.

> `users.email` is `UNIQUE`, so a second account cannot hold a taken address.
> The remaining options were to link anyway (account takeover) or to take the
> address from its current owner. Refusing is the only safe resolution.

`internal/linking` is isolated because it is the only place a bug becomes an
account takeover. Every combination of {provider verified, unverified} × {user
exists verified, exists unverified, doesn't exist} × {already linked, not} is
covered by a table-driven test.

## Ops

**Migrations run as a release command, not on boot** — a bad migration should
fail the deploy, not crashloop the service.

```sh
authsvc -migrate     # Railway: set as preDeployCommand (see railway.json)
```

**Signing keys.** `go run ./cmd/genkey` prints one. Keep both
`ED25519_PRIVATE_KEY` and `ED25519_PRIVATE_KEY_NEXT` set: both are published in
JWKS, only the first signs, so rotation is promoting NEXT and generating a new
one — no flag day.

**Backups.** `pg_dump` on cron to R2/B2. This DB holds every account for every
app.

**Rate limits** are per-IP and per-identifier on login, OTP request, and password
reset. Fixed-window counters in Postgres; no Redis at this scale.

**Pruning** runs at startup and then every 6h, clearing sessions past
`expires_at + 30d` plus expired codes, OAuth flows, and rate-limit windows. The
startup run is deliberate: a platform that redeploys more often than the tick
interval would otherwise never prune. `sessions` is the only table that grows
with traffic rather than users — one row per refresh — so this is what stands
between the service and unbounded storage growth. `sessions` has `autovacuum_vacuum_scale_factor = 0.02` because every
refresh is an UPDATE plus an INSERT.

Set a usage limit and alert on Railway.

## Env

```
PORT                         # default 8080
ISSUER                       # must be https outside DEV; must match `iss` exactly
DATABASE_URL
ED25519_PRIVATE_KEY          # + ED25519_PRIVATE_KEY_NEXT for rotation
ACCESS_TTL                   # default 1h
GOOGLE_CLIENT_ID / _SECRET   # provider 404s if unset
GITHUB_CLIENT_ID / _SECRET
SMTP_HOST / _PORT / _USER / _PASS / _FROM
ADMIN_API_KEY
DEV                          # relaxes cookie Secure; logs codes instead of emailing
```

`DATABASE_URL`, `ED25519_PRIVATE_KEY`, and `ADMIN_API_KEY` are required; startup
fails fast without them. Nothing reads `RAILWAY_*`.

## Routes

```
GET  /.well-known/jwks.json
GET  /healthz                        -- checks DB connectivity, not just liveness

POST /v1/auth/register               {client_id, email, password}
POST /v1/auth/login                  {client_id, email, password}
POST /v1/auth/email/verify           {token}
POST /v1/auth/password/forgot        {email}
POST /v1/auth/password/reset         {token, new_password}

POST /v1/auth/otp/request            {client_id, email}
POST /v1/auth/otp/verify             {client_id, email, code}

GET  /v1/oauth/{provider}/start?client_id=&redirect_uri=&state=
GET  /v1/oauth/{provider}/callback   -- the ONE URL registered with Google/GitHub

POST /v1/token/exchange              {code, client_id, client_secret}
POST /v1/token/refresh               cookie, or {refresh_token} for server-side callers
POST /v1/auth/logout                 bearer
POST /v1/auth/logout-all             bearer

GET    /v1/me
GET    /v1/sessions
DELETE /v1/sessions/{id}
GET    /v1/me/link/{provider}/start

POST /v1/admin/clients               static bearer key from env
GET  /v1/admin/clients
```

### Deviations from the original spec

- `/v1/auth/otp/verify` also takes `client_id`. Codes are stored under
  `client_id|email`, so an OTP issued for one app cannot buy a token for
  another.
- `logout` authenticates by bearer token, not the refresh cookie — with
  `Path=/v1/token` the browser never sends that cookie to `/v1/auth/logout`.
- Unsafe auto-links are refused (`manual_link_required`) rather than creating a
  duplicate-email user, which the schema forbids. See above.

## Layout

```
cmd/authsvc/      server; -migrate applies migrations and exits
cmd/genkey/       prints an Ed25519 signing key
internal/
  config/         env → struct, fail fast on missing
  store/          pgx + migrations/
  token/          ed25519 signing, JWKS, refresh mint/hash
  password/       argon2id
  linking/        identity resolution — SECURITY CRITICAL
  oauth/          Provider iface + google.go, github.go
  notify/         Sender iface + smtp.go
  httpapi/        handlers, middleware, routing
  e2e/            the real SDK against the real server
sdk/go/           separate module, so consumers don't inherit pgx
```
