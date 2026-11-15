package vapid_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/backplane-labs/backplane-pushgate/internal/vapid"
)

const audience = "https://push.example.com"

type signer struct {
	key *ecdsa.PrivateKey
	pub string
}

func newSigner(tb testing.TB) signer {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	raw, err := key.PublicKey.Bytes()
	if err != nil {
		tb.Fatal(err)
	}

	return signer{key: key, pub: base64.RawURLEncoding.EncodeToString(raw)}
}

func (s signer) token(tb testing.TB, claims jwt.MapClaims) string {
	tb.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(s.key)
	if err != nil {
		tb.Fatal(err)
	}

	return token
}

// hs256 is a token a VAPID key cannot have made.
func hs256(tb testing.TB, claims jwt.MapClaims) string {
	tb.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("shared secret"))
	if err != nil {
		tb.Fatal(err)
	}

	return token
}

func TestVerify(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	sender, other := newSigner(t), newSigner(t)
	claims := func(aud string, exp time.Time, sub string) jwt.MapClaims {
		return jwt.MapClaims{"aud": aud, "exp": exp.Unix(), "sub": sub}
	}
	good := sender.token(t, claims(audience, now.Add(12*time.Hour), "mailto:ops@example.com"))

	tests := []struct {
		name   string
		header string
		err    error
	}{
		{name: "valid", header: "vapid t=" + good + ", k=" + sender.pub},
		{name: "parameters reversed", header: "vapid k=" + sender.pub + ",t=" + good},
		{name: "https subject", header: "vapid t=" + sender.token(t,
			claims(audience, now.Add(time.Hour), "https://example.com/contact")) + ", k=" + sender.pub},
		{name: "no header", header: "", err: vapid.ErrMissing},
		{name: "other scheme", header: "WebPush " + good, err: vapid.ErrMissing},
		{name: "no key", header: "vapid t=" + good, err: vapid.ErrMissing},
		{name: "another key", header: "vapid t=" + good + ", k=" + other.pub, err: vapid.ErrInvalid},
		{name: "bad key", header: "vapid t=" + good + ", k=AAAA", err: vapid.ErrInvalid},
		{name: "another audience", header: "vapid t=" + sender.token(t,
			claims("https://evil.example", now.Add(time.Hour), "mailto:a@b.c")) + ", k=" + sender.pub, err: vapid.ErrInvalid},
		{name: "expired", header: "vapid t=" + sender.token(t,
			claims(audience, now.Add(-time.Minute), "mailto:a@b.c")) + ", k=" + sender.pub, err: vapid.ErrInvalid},
		{name: "too far ahead", header: "vapid t=" + sender.token(t,
			claims(audience, now.Add(25*time.Hour), "mailto:a@b.c")) + ", k=" + sender.pub, err: vapid.ErrInvalid},
		{name: "no exp", header: "vapid t=" + sender.token(t,
			jwt.MapClaims{"aud": audience, "sub": "mailto:a@b.c"}) + ", k=" + sender.pub, err: vapid.ErrInvalid},
		{name: "no subject", header: "vapid t=" + sender.token(t,
			claims(audience, now.Add(time.Hour), "")) + ", k=" + sender.pub, err: vapid.ErrInvalid},
		{name: "not ES256", header: "vapid t=" + hs256(t, claims(audience, now.Add(time.Hour), "mailto:a@b.c")) +
			", k=" + sender.pub, err: vapid.ErrInvalid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, err := vapid.Verify(tc.header, audience, now)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err %v, want %v", err, tc.err)
			}

			if tc.err == nil && key != sender.pub {
				t.Fatalf("key %q, want %q", key, sender.pub)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	now := time.Unix(1_800_000_000, 0)
	sender := newSigner(b)
	header := "vapid t=" + sender.token(b,
		jwt.MapClaims{"aud": audience, "exp": now.Add(time.Hour).Unix(), "sub": "mailto:a@b.c"}) + ", k=" + sender.pub

	for b.Loop() {
		_, _ = vapid.Verify(header, audience, now)
	}
}
