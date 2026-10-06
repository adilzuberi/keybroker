package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVerifierAcceptsSignedBytesAndDeniesTampering(t *testing.T) {
	// All keys and messages here are synthetic; no signing key leaves this test.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("synthetic release metadata")
	sig := ed25519.Sign(key, msg)
	binary := filepath.Join(t.TempDir(), "verifier")
	goBin := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if os.Getenv("GOROOT") == "" {
		goBin = "go"
	}
	if output, err := exec.Command(goBin, "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, tc := range []struct {
		name      string
		input     []byte
		signature []byte
		code      int
	}{
		{"authentic", msg, sig, 0}, {"changed-bytes", []byte("changed"), sig, 3}, {"oversized", bytes.Repeat([]byte("x"), 65537), sig, 3},
		{"bad-signature", msg, make([]byte, 64), 3}, {"truncated-signature", msg, sig[:10], 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, hex.EncodeToString(pub), hex.EncodeToString(tc.signature))
			cmd.Stdin = bytes.NewReader(tc.input)
			err := cmd.Run()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code {
				t.Fatalf("code=%d want=%d", code, tc.code)
			}
		})
	}
}
