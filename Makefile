PG_DSN ?= postgres://authsvc:authsvc@localhost:5434/authsvc?sslmode=disable

.PHONY: test test-sdk db-up db-down migrate build genkey docker
db-up:   ; docker run -d --name authsvc-pg -e POSTGRES_PASSWORD=authsvc -e POSTGRES_USER=authsvc -e POSTGRES_DB=authsvc -p 5434:5432 postgres:16-alpine
db-down: ; docker rm -f authsvc-pg
test:    ; TEST_DATABASE_URL="$(PG_DSN)" go test ./... -count=1 -race
	cd sdk/go && go test ./... -count=1 -race
genkey:  ; @go run ./cmd/genkey
docker:  ; docker build -t authsvc .
build:   ; go build -o bin/authsvc ./cmd/authsvc
migrate: ; DATABASE_URL="$(PG_DSN)" go run ./cmd/authsvc -migrate
