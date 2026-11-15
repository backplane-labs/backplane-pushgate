// Package tests runs pushgate whole, in-process, against a real NATS with
// JetStream: senders post with webpush-go (the library backplane-courier's
// webpush channel sends with), desktop clients connect with pushtest.
package tests_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats/natstest"

	pushgate "github.com/backplane-labs/backplane-pushgate"
	"github.com/backplane-labs/backplane-pushgate/internal/pushtest"
	"github.com/backplane-labs/backplane-pushgate/internal/sender"
	"github.com/backplane-labs/backplane-pushgate/internal/session"
	"github.com/backplane-labs/backplane-pushgate/internal/vapid/vapidtest"
	clientv1 "github.com/backplane-labs/backplane-pushgate/proto/pushgate/client/v1"
)

// instance is one running pushgate.
type instance struct {
	h   *backplanetest.Harness
	url string // public URL, http
	// client is the server's own: a server Close elsewhere never breaks it.
	client *http.Client
	ws     string // client WebSocket URL
}

// start runs pushgate on natsURL; vars override its configuration.
func start(tb testing.TB, natsURL string, vars map[string]string) instance {
	tb.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	tb.Cleanup(srv.Close)

	all := map[string]string{"PUBLIC_URL": srv.URL, "NATS_URL": natsURL, "MAILBOX_ACK_WAIT": "2s"}
	for k, v := range vars {
		all[k] = v
	}

	cfg := backplanetest.Config[pushgate.Config](tb, all)
	h := backplanetest.New(tb, backplanetest.Name("pushgate"))

	st, err := pushgate.New(h.Root(), &cfg)
	if err != nil {
		tb.Fatal(err)
	}

	mux.Handle(sender.Path, st.Sender)
	mux.Handle(session.Path, st.Sessions)
	h.Start()

	return instance{h: h, url: srv.URL, client: srv.Client(), ws: "ws" + strings.TrimPrefix(srv.URL, "http") + session.Path}
}

// device is a desktop client's keys: its identity and one subscription's
// content keys.
type device struct {
	key  []byte
	keys pushtest.Keys
}

func newDevice(tb testing.TB) device {
	tb.Helper()

	return device{key: pushtest.DeviceKey(tb), keys: pushtest.NewKeys(tb)}
}

func (d device) dial(tb testing.TB, in instance) *pushtest.Client {
	tb.Helper()

	return pushtest.Dial(tb, in.ws, d.key)
}

// send posts plaintext to sub as sender does, through webpush-go: the
// status and the answer's TTL.
func send(tb testing.TB, s vapidtest.Sender, d device, sub *clientv1.Subscription, plaintext string, o webpush.Options) (int, string) {
	tb.Helper()

	o.Subscriber, o.VAPIDPublicKey, o.VAPIDPrivateKey = "mailto:ops@example.com", s.Public, s.PrivateKey(tb)
	if o.TTL == 0 && o.Topic == "" && o.Urgency == "" {
		o.TTL = 60
	}

	res, err := webpush.SendNotificationWithContext(tb.Context(), []byte(plaintext),
		&webpush.Subscription{Endpoint: sub.GetEndpoint(), Keys: webpush.Keys{P256dh: d.keys.P256dh(), Auth: d.keys.Auth()}}, &o)
	if err != nil {
		tb.Fatal(err)
	}

	defer res.Body.Close()

	_, _ = io.Copy(io.Discard, res.Body)

	return res.StatusCode, res.Header.Get("TTL")
}

func (d device) open(tb testing.TB, n *clientv1.Notification) string {
	tb.Helper()

	plain, err := d.keys.Decrypt(n.GetData())
	if err != nil {
		tb.Fatal(err)
	}

	return string(plain)
}

// A sender posts as courier does; a connected desktop client receives the
// message, opens it, acknowledges it and does not get it again.
func TestDelivery(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), nil)
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, refused := c.Subscribe(t, sender.Public)

	if refused != nil {
		t.Fatalf("subscribe refused %v", refused)
	}

	if status, ttl := send(t, sender, d, sub, "incoming call", webpush.Options{TTL: 30, Urgency: webpush.UrgencyHigh, Topic: "call-1"}); status != http.StatusCreated || ttl != "30" {
		t.Fatalf("send: %d TTL %s", status, ttl)
	}

	n := c.Notification(t)
	if d.open(t, n) != "incoming call" || n.GetTopic() != "call-1" || n.GetUrgency() != "high" || n.GetSubscription() != sub.GetId() {
		t.Fatalf("notification %v", n)
	}

	c.Ack(t, n.GetId())
	c.Close()

	again := d.dial(t, in)
	if len(again.Welcome().GetSubscriptions()) != 1 {
		t.Fatalf("welcome after reconnect %v", again.Welcome())
	}

	again.Quiet(t, 3*time.Second) // past ack_wait: nothing comes back
}

// Messages wait for an offline client: a topic keeps the newest, a TTL 0
// message is dropped, the mailbox keeps the newest max_per_channel.
func TestOffline(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), map[string]string{"MAILBOX_MAX_PER_CHANNEL": "3"})
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)
	c.Close()

	for _, m := range []struct {
		text string
		o    webpush.Options
	}{
		{"old status", webpush.Options{TTL: 60, Topic: "status"}},
		{"new status", webpush.Options{TTL: 60, Topic: "status"}},
		{"now or never", webpush.Options{Urgency: webpush.UrgencyHigh}}, // TTL 0
		{"first", webpush.Options{TTL: 60}},
		{"second", webpush.Options{TTL: 60}},
		{"third", webpush.Options{TTL: 60}},
	} {
		if status, _ := send(t, sender, d, sub, m.text, m.o); status != http.StatusCreated {
			t.Fatalf("send %q: %d", m.text, status)
		}
	}

	c = d.dial(t, in)

	var got []string

	for range 3 {
		n := c.Notification(t)
		got = append(got, d.open(t, n))
		c.Ack(t, n.GetId())
	}

	if strings.Join(got, ",") != "first,second,third" {
		t.Fatalf("delivered %v: want the newest three", got)
	}

	c.Quiet(t, time.Second)
}

// A message not acknowledged comes again on the next connection.
func TestRedeliveryOnReconnect(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), nil)
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)
	send(t, sender, d, sub, "unacked", webpush.Options{TTL: 60})

	first := c.Notification(t)
	c.Close()

	again := d.dial(t, in).Notification(t)
	if again.GetId() != first.GetId() || d.open(t, again) != "unacked" {
		t.Fatalf("redelivered %v, want %v", again, first)
	}
}

// A sender gets the RFC 8030 answers: another key 403, no subscription
// 410, a malformed endpoint 404, an oversized body 413.
func TestSenderRefusals(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), nil)
	sender, other, d := vapidtest.New(t), vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)

	if status, _ := send(t, other, d, sub, "spoofed", webpush.Options{TTL: 60}); status != http.StatusForbidden {
		t.Fatalf("another sender's key: %d", status)
	}

	// webpush-go refuses an oversized payload itself: post one directly.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sub.GetEndpoint(), strings.NewReader(strings.Repeat("x", 4097)))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", sender.Header(t, in.url))
	req.Header.Set("TTL", "60")
	req.Header.Set("Content-Encoding", "aes128gcm")

	res, err := in.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	_ = res.Body.Close()

	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", res.StatusCode)
	}

	broken := &clientv1.Subscription{Endpoint: in.url + endpointPath("nope")}
	if status, _ := send(t, sender, d, broken, "x", webpush.Options{TTL: 60}); status != http.StatusNotFound {
		t.Fatalf("malformed endpoint: %d", status)
	}

	if r := c.Unsubscribe(t, sub.GetId()); r != nil {
		t.Fatalf("unsubscribe refused %v", r)
	}

	if status, _ := send(t, sender, d, sub, "late", webpush.Options{TTL: 60}); status != http.StatusGone {
		t.Fatalf("after unsubscribe: %d", status)
	}

	c.Quiet(t, time.Second)
}

// endpointPath is the endpoint path of a subscription id.
func endpointPath(id string) string { return sender.Path + id }

// A client may hold subscriptions up to the limit, one per sender key.
func TestSubscriptionLimit(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), map[string]string{"SUBSCRIPTIONS_MAX_PER_CHANNEL": "2"})
	c := newDevice(t).dial(t, in)

	for range 2 {
		if _, r := c.Subscribe(t, vapidtest.New(t).Public); r != nil {
			t.Fatalf("subscribe refused %v", r)
		}
	}

	if _, r := c.Subscribe(t, vapidtest.New(t).Public); r.GetCode() != clientv1.RefusalCode_REFUSAL_CODE_LIMIT {
		t.Fatalf("over the limit: %v", r)
	}
}

// Two replicas on one NATS: a message posted to one reaches the client
// connected to the other; a newer connection on either replaces the older.
func TestReplicas(t *testing.T) {
	t.Parallel()

	url := natstest.Start(t).ClientURL()
	a, b := start(t, url, nil), start(t, url, nil)
	sender, d := vapidtest.New(t), newDevice(t)

	onB := d.dial(t, b)
	sub, _ := onB.Subscribe(t, sender.Public)

	// The endpoint names replica b's host; post to replica a instead.
	viaA := &clientv1.Subscription{Endpoint: strings.Replace(sub.GetEndpoint(), b.url, a.url, 1)}
	if status, _ := send(t, sender, d, viaA, "across", webpush.Options{TTL: 60}); status != http.StatusCreated {
		t.Fatalf("send via a: %d", status)
	}

	if n := onB.Notification(t); d.open(t, n) != "across" {
		t.Fatalf("delivered %v", n)
	}

	onA := d.dial(t, a)
	if code := onB.Closed(t); code != session.CodeReplaced {
		t.Fatalf("older connection closed with %d, want %d", code, session.CodeReplaced)
	}

	send(t, sender, d, sub, "to the newer", webpush.Options{TTL: 60})

	if n := onA.Notification(t); d.open(t, n) != "to the newer" {
		t.Fatalf("delivered %v", n)
	}
}

// A channel that does not connect for idle_expiry loses its
// subscriptions: its endpoint answers 410.
func TestIdleExpiry(t *testing.T) {
	t.Parallel()

	in := start(t, natstest.Start(t).ClientURL(), map[string]string{"SUBSCRIPTIONS_IDLE_EXPIRY": "2s"})
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)
	c.Close()

	time.Sleep(4 * time.Second)

	if status, _ := send(t, sender, d, sub, "too late", webpush.Options{TTL: 60}); status != http.StatusGone {
		t.Fatalf("after idle expiry: %d", status)
	}

	if subs := d.dial(t, in).Welcome().GetSubscriptions(); len(subs) != 0 {
		t.Fatalf("expired subscriptions listed %v", subs)
	}
}

// The service survives a NATS cluster node going down: with replicas 3,
// subscriptions and messages keep working.
func TestChaosNodeDown(t *testing.T) {
	t.Parallel()

	cluster := natstest.StartCluster(t, 3)
	urls := cluster.URL(0) + "," + cluster.URL(1) + "," + cluster.URL(2)
	in := start(t, urls, map[string]string{"MAILBOX_REPLICAS": "3"})
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)

	for i := range 3 {
		cluster.Stop(i)

		waitFor(t, "a send through the remaining nodes", func() bool {
			status, _ := send(t, sender, d, sub, "survived "+strconv.Itoa(i), webpush.Options{TTL: 60})

			return status == http.StatusCreated
		})

		n := c.Notification(t)
		if d.open(t, n) != "survived "+strconv.Itoa(i) {
			t.Fatalf("delivered %q", d.open(t, n))
		}

		c.Ack(t, n.GetId())
		cluster.Restart(t, i)
	}
}

// With NATS gone entirely (every node of the cluster down), a sender gets
// 500 (it retries) and readiness fails; once NATS is back, both recover
// and the stored subscription still works.
func TestChaosNATSDown(t *testing.T) {
	t.Parallel()

	cluster := natstest.StartCluster(t, 3)
	urls := cluster.URL(0) + "," + cluster.URL(1) + "," + cluster.URL(2)
	in := start(t, urls, map[string]string{"MAILBOX_REPLICAS": "3"})
	sender, d := vapidtest.New(t), newDevice(t)

	c := d.dial(t, in)
	sub, _ := c.Subscribe(t, sender.Public)

	for i := range 3 {
		cluster.Stop(i)
	}

	if status, _ := send(t, sender, d, sub, "lost", webpush.Options{TTL: 60}); status != http.StatusInternalServerError {
		t.Fatalf("send with NATS down: %d", status)
	}

	waitFor(t, "readiness to fail", func() bool { return backplanetest.Ready(in.h) != nil })

	for i := range 3 {
		cluster.Restart(t, i)
	}

	waitFor(t, "readiness to recover", func() bool { return backplanetest.Ready(in.h) == nil })

	waitFor(t, "a send after recovery", func() bool {
		status, _ := send(t, sender, d, sub, "back", webpush.Options{TTL: 60})

		return status == http.StatusCreated
	})

	if n := d.dial(t, in).Notification(t); d.open(t, n) != "back" {
		t.Fatalf("delivered %v", n)
	}
}

func waitFor(tb testing.TB, what string, cond func() bool) {
	tb.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("not reached: %s", what)
		}

		time.Sleep(200 * time.Millisecond)
	}
}
