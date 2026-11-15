package domain_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
)

func TestVerifyHello(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nonce := domain.Nonce()
	signature := ed25519.Sign(priv, domain.HelloMessage(nonce))

	tests := []struct {
		name      string
		key       []byte
		signature []byte
		nonce     []byte
		err       error
	}{
		{name: "proven", key: pub, signature: signature, nonce: nonce},
		{name: "another key", key: other, signature: signature, nonce: nonce, err: domain.ErrHello},
		{name: "another nonce", key: pub, signature: signature, nonce: domain.Nonce(), err: domain.ErrHello},
		{name: "signed without the context", key: pub, signature: ed25519.Sign(priv, nonce), nonce: nonce, err: domain.ErrHello},
		{name: "short key", key: pub[:31], signature: signature, nonce: nonce, err: domain.ErrHello},
		{name: "short signature", key: pub, signature: signature[:63], nonce: nonce, err: domain.ErrHello},
		{name: "short nonce", key: pub, signature: signature, nonce: nonce[:31], err: domain.ErrHello},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			channel, err := domain.VerifyHello(tc.key, tc.signature, tc.nonce)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err %v, want %v", err, tc.err)
			}

			if tc.err == nil && channel != domain.ChannelOf(pub) {
				t.Fatalf("channel %q, want %q", channel, domain.ChannelOf(pub))
			}
		})
	}
}

func TestChannelOf(t *testing.T) {
	t.Parallel()

	key := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	// SHA-256 of 32 zero bytes, base64url without padding.
	if got, want := domain.ChannelOf(key), domain.Channel("Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU"); got != want {
		t.Fatalf("channel %q, want %q", got, want)
	}
}

func TestSubscriptionID(t *testing.T) {
	t.Parallel()

	fresh := domain.NewSubscriptionID()

	tests := []struct {
		name string
		id   string
		err  error
	}{
		{name: "fresh", id: string(fresh)},
		{name: "empty", id: "", err: domain.ErrSubscriptionID},
		{name: "too short", id: "AAAA", err: domain.ErrSubscriptionID},
		{name: "not base64url", id: "!!!!!!!!!!!!!!!!!!!!!!", err: domain.ErrSubscriptionID},
		{name: "padded", id: string(fresh) + "==", err: domain.ErrSubscriptionID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := domain.ParseSubscriptionID(tc.id); !errors.Is(err, tc.err) {
				t.Fatalf("err %v, want %v", err, tc.err)
			}
		})
	}

	if domain.NewSubscriptionID() == fresh {
		t.Fatal("two ids are equal")
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	raw := priv.PublicKey().Bytes()
	canonical := base64.RawURLEncoding.EncodeToString(raw)

	tests := []struct {
		name string
		key  string
		want string
		err  error
	}{
		{name: "canonical", key: canonical, want: canonical},
		{name: "padded", key: base64.URLEncoding.EncodeToString(raw), want: canonical},
		{name: "compressed point", key: base64.RawURLEncoding.EncodeToString(append([]byte{2}, raw[1:33]...)), err: domain.ErrKey},
		{name: "not on the curve", key: base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)), err: domain.ErrKey},
		{name: "not base64url", key: "+/+/", err: domain.ErrKey},
		{name: "empty", key: "", err: domain.ErrKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := domain.ParseKey(tc.key)
			if !errors.Is(err, tc.err) || got != tc.want {
				t.Fatalf("ParseKey = %q, %v; want %q, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestHeaders(t *testing.T) {
	t.Parallel()

	week := 7 * 24 * time.Hour

	ttls := []struct {
		in   string
		want time.Duration
		err  error
	}{
		{in: "0", want: 0},
		{in: "60", want: time.Minute},
		{in: "99999999", want: week},
		{in: "", err: domain.ErrTTL},
		{in: "-1", err: domain.ErrTTL},
		{in: "1.5", err: domain.ErrTTL},
	}
	for _, tc := range ttls {
		if got, err := domain.ParseTTL(tc.in, week); !errors.Is(err, tc.err) || got != tc.want {
			t.Errorf("ParseTTL(%q) = %v, %v; want %v, %v", tc.in, got, err, tc.want, tc.err)
		}
	}

	topics := []struct {
		in  string
		err error
	}{
		{in: ""},
		{in: "call-1_A"},
		{in: strings.Repeat("a", 32)},
		{in: strings.Repeat("a", 33), err: domain.ErrTopic},
		{in: "a.b", err: domain.ErrTopic},
		{in: "a b", err: domain.ErrTopic},
	}
	for _, tc := range topics {
		if _, err := domain.ParseTopic(tc.in); !errors.Is(err, tc.err) {
			t.Errorf("ParseTopic(%q) = %v, want %v", tc.in, err, tc.err)
		}
	}

	urgencies := []struct {
		in   string
		want domain.Urgency
		err  error
	}{
		{in: "", want: domain.Normal},
		{in: "very-low", want: domain.VeryLow},
		{in: "high", want: domain.High},
		{in: "urgent", err: domain.ErrUrgency},
	}
	for _, tc := range urgencies {
		if got, err := domain.ParseUrgency(tc.in); !errors.Is(err, tc.err) || got != tc.want {
			t.Errorf("ParseUrgency(%q) = %q, %v; want %q, %v", tc.in, got, err, tc.want, tc.err)
		}
	}

	bodies := []struct {
		encoding string
		size     int
		err      error
	}{
		{encoding: "aes128gcm", size: 4096},
		{encoding: "", size: 0},
		{encoding: "aes128gcm", size: 4097, err: domain.ErrTooLarge},
		{encoding: "aesgcm", size: 10, err: domain.ErrEncoding},
	}
	for _, tc := range bodies {
		if err := domain.CheckBody(tc.encoding, tc.size); !errors.Is(err, tc.err) {
			t.Errorf("CheckBody(%q, %d) = %v, want %v", tc.encoding, tc.size, err, tc.err)
		}
	}
}

func TestSlot(t *testing.T) {
	t.Parallel()

	if got := (domain.Message{Topic: "call-1"}).Slot(); got != "tcall-1" {
		t.Fatalf("topic slot %q", got)
	}

	a, b := domain.Message{}.Slot(), domain.Message{}.Slot()
	if a == b || !strings.HasPrefix(a, "m") {
		t.Fatalf("slots without a topic %q, %q: want distinct m-slots", a, b)
	}
}

func BenchmarkVerifyHello(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	nonce := domain.Nonce()
	signature := ed25519.Sign(priv, domain.HelloMessage(nonce))

	for b.Loop() {
		_, _ = domain.VerifyHello(pub, signature, nonce)
	}
}

func BenchmarkParseKey(b *testing.B) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	key := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	for b.Loop() {
		_, _ = domain.ParseKey(key)
	}
}

func BenchmarkParseHeaders(b *testing.B) {
	for b.Loop() {
		_, _ = domain.ParseTTL("86400", time.Hour)
		_, _ = domain.ParseTopic("call-1")
		_, _ = domain.ParseUrgency("high")
	}
}
