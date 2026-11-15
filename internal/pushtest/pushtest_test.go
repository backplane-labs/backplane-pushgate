package pushtest_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/backplane-labs/backplane-pushgate/internal/pushtest"
	"github.com/backplane-labs/backplane-pushgate/internal/vapid/vapidtest"
)

// What webpush-go (the library courier sends with) encrypts, Decrypt opens;
// other keys or a tampered body do not.
func TestDecrypt(t *testing.T) {
	t.Parallel()

	keys, other := pushtest.NewKeys(t), pushtest.NewKeys(t)
	sender := vapidtest.New(t)

	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	res, err := webpush.SendNotificationWithContext(t.Context(), []byte("When I grow up, I want to be a watermelon"),
		&webpush.Subscription{Endpoint: srv.URL, Keys: webpush.Keys{P256dh: keys.P256dh(), Auth: keys.Auth()}},
		&webpush.Options{
			Subscriber: "mailto:test@example.com", VAPIDPublicKey: sender.Public,
			VAPIDPrivateKey: sender.PrivateKey(t), TTL: 60,
		})
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()

	plain, err := keys.Decrypt(body)
	if err != nil || string(plain) != "When I grow up, I want to be a watermelon" {
		t.Fatalf("Decrypt = %q, %v", plain, err)
	}

	if _, err := other.Decrypt(body); err == nil {
		t.Fatal("other keys opened the message")
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 1

	if _, err := keys.Decrypt(tampered); err == nil {
		t.Fatal("a tampered message opened")
	}

	if _, err := keys.Decrypt(body[:10]); err == nil {
		t.Fatal("a truncated message opened")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	keys, sender := pushtest.NewKeys(b), vapidtest.New(b)

	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	b.Cleanup(srv.Close)

	res, err := webpush.SendNotificationWithContext(b.Context(), make([]byte, 1024),
		&webpush.Subscription{Endpoint: srv.URL, Keys: webpush.Keys{P256dh: keys.P256dh(), Auth: keys.Auth()}},
		&webpush.Options{
			Subscriber: "mailto:test@example.com", VAPIDPublicKey: sender.Public,
			VAPIDPrivateKey: sender.PrivateKey(b), TTL: 60,
		})
	if err != nil {
		b.Fatal(err)
	}

	_ = res.Body.Close()

	for b.Loop() {
		_, _ = keys.Decrypt(body)
	}
}
