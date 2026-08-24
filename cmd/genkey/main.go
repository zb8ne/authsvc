// Command genkey prints a fresh Ed25519 signing key for ED25519_PRIVATE_KEY.
//
//	go run ./cmd/genkey
//
// Keep two keys configured at all times (ED25519_PRIVATE_KEY and
// ED25519_PRIVATE_KEY_NEXT) so a rotation is a config change, not a flag day:
// both are published in JWKS, only the first one signs.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(priv.Seed()))
}
