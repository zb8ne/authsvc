module github.com/yash-sharma-dev/authsvc

go 1.26.4

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/lestrrat-go/jwx/v2 v2.1.7
	github.com/oklog/ulid/v2 v2.1.2
	github.com/pressly/goose/v3 v3.27.3
	golang.org/x/crypto v0.55.0
	golang.org/x/oauth2 v0.36.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	github.com/yash-sharma-dev/authsvc/sdk/go v0.0.0
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/yash-sharma-dev/authsvc/sdk/go => ./sdk/go
