// Package vapidtest makes VAPID authorizations for tests: a sender key and
// its signed headers.
package vapidtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sender is a VAPID key pair.
type Sender struct {
	key *ecdsa.PrivateKey
	// Public is the public key, base64url of the uncompressed point: the
	// application server key a client subscribes with.
	Public string
}

// New is a fresh sender.
func New(tb testing.TB) Sender {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	raw, err := key.PublicKey.Bytes()
	if err != nil {
		tb.Fatal(err)
	}

	return Sender{key: key, Public: base64.RawURLEncoding.EncodeToString(raw)}
}

// Header is "vapid t=<jwt>, k=<key>" for audience, valid for an hour.
func (s Sender) Header(tb testing.TB, audience string) string {
	tb.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": audience, "exp": time.Now().Add(time.Hour).Unix(), "sub": "mailto:test@example.com",
	}).SignedString(s.key)
	if err != nil {
		tb.Fatal(err)
	}

	return "vapid t=" + token + ", k=" + s.Public
}

// PrivateKey is the private key, base64url of its scalar, as webpush
// libraries take it.
func (s Sender) PrivateKey(tb testing.TB) string {
	tb.Helper()

	raw, err := s.key.Bytes()
	if err != nil {
		tb.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}
