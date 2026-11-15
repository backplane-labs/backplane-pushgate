package tests_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats/natstest"

	"github.com/backplane-labs/backplane-pushgate/internal/vapid/vapidtest"
)

// The TypeScript client (client/dist, built by `make client`) connects over
// Node's WebSocket, proves its key, subscribes, and opens what webpush-go
// (courier's library) sent: the client package speaks the real service.
func TestTypeScriptClient(t *testing.T) {
	t.Parallel()

	script, err := filepath.Abs("../client/e2e/device.mjs")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat("../client/dist/index.js"); err != nil {
		t.Fatalf("client/dist is missing: run make client first (%v)", err)
	}

	in := start(t, natstest.Start(t).ClientURL(), nil)
	sender := vapidtest.New(t)

	cmd := exec.CommandContext(t.Context(), "node", script, in.ws, sender.Public)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	lines := bufio.NewScanner(stdout)

	var address struct {
		Subscribed struct {
			Endpoint string `json:"endpoint"`
			P256dh   string `json:"p256dh"`
			Auth     string `json:"auth"`
		} `json:"subscribed"`
	}

	if !lines.Scan() || json.Unmarshal(lines.Bytes(), &address) != nil || address.Subscribed.Endpoint == "" {
		t.Fatalf("no address from the client: %q", lines.Text())
	}

	res, err := webpush.SendNotificationWithContext(t.Context(), []byte("from courier"),
		&webpush.Subscription{
			Endpoint: address.Subscribed.Endpoint,
			Keys:     webpush.Keys{P256dh: address.Subscribed.P256dh, Auth: address.Subscribed.Auth},
		},
		&webpush.Options{
			Subscriber: "mailto:ops@example.com", VAPIDPublicKey: sender.Public, VAPIDPrivateKey: sender.PrivateKey(t),
			TTL: 60, Topic: "call", Urgency: webpush.UrgencyHigh,
		})
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		t.Fatalf("send: %d", res.StatusCode)
	}

	var got struct {
		Plaintext string `json:"plaintext"`
		Topic     string `json:"topic"`
		Urgency   string `json:"urgency"`
	}

	if !lines.Scan() || json.Unmarshal(lines.Bytes(), &got) != nil {
		t.Fatalf("no message from the client: %q", lines.Text())
	}

	if got.Plaintext != "from courier" || got.Topic != "call" || got.Urgency != "high" {
		t.Fatalf("the client got %+v", got)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the client exited: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client did not exit")
	}
}
