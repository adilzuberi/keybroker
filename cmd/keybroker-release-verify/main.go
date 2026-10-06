// This bootstrap verifier accepts a public verification key, never a signing key.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	key, e := hex.DecodeString(os.Args[1])
	if e != nil || len(key) != ed25519.PublicKeySize {
		os.Exit(2)
	}
	sig, e := hex.DecodeString(os.Args[2])
	if e != nil || len(sig) != ed25519.SignatureSize {
		os.Exit(2)
	}
	msg, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if e != nil || len(msg) > 65536 || !ed25519.Verify(key, msg, sig) {
		os.Exit(3)
	}
}
