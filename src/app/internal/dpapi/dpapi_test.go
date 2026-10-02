//go:build windows

package dpapi

import (
	"bytes"
	"testing"
)

func TestRoundTripAndNoPlaintext(t *testing.T) {
	secret := []byte("synthetic-secret-0000")
	enc, err := Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, secret) {
		t.Fatal("ciphertext contains the plaintext")
	}
	dec, err := Unprotect(enc)
	if err != nil || !bytes.Equal(dec, secret) {
		t.Fatalf("round trip failed: %v %q", err, dec)
	}
	enc[len(enc)-1] ^= 0xff
	if _, err := Unprotect(enc); err == nil {
		t.Fatal("tampered blob was accepted")
	}
}
