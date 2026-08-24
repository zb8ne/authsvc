# Build
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache deps separately from source. The SDK is a nested module and is not part
# of the server binary, so it is not copied here.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authsvc ./cmd/authsvc

# Run
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 authsvc
USER authsvc
COPY --from=build /out/authsvc /usr/local/bin/authsvc

# PORT is read from the environment; this is documentation, not a binding.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/authsvc"]
