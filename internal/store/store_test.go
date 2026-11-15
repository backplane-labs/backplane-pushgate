package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats/natstest"
	natsgo "github.com/nats-io/nats.go"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	"github.com/backplane-labs/backplane-pushgate/internal/store"
)

// open is a store on its own in-process NATS server with JetStream.
func open(tb testing.TB, s store.Settings) *store.Store {
	tb.Helper()

	srv := natstest.Start(tb)

	conn, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(conn.Close)

	st, err := store.Open(tb.Context(), conn, nats.Config{URL: config.Secret(srv.ClientURL())}, s)
	if err != nil {
		tb.Fatal(err)
	}

	return st
}

func settings() store.Settings {
	return store.Settings{Replicas: 1, IdleExpiry: time.Hour, MaxTTL: time.Hour, AckWait: time.Second}
}

func subscription(channel domain.Channel) domain.Subscription {
	return domain.Subscription{ID: domain.NewSubscriptionID(), Channel: channel, Key: "key", CreatedAt: time.Now().UTC()}
}

// Subscriptions are created up to the channel's limit, found by id, listed
// by Touch, deleted only by their own channel.
func TestSubscriptions(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()
	first, second := subscription("chan-a"), subscription("chan-a")

	for _, sub := range []domain.Subscription{first, second} {
		if err := st.Create(ctx, sub, 2); err != nil {
			t.Fatal(err)
		}
	}

	if err := st.Create(ctx, subscription("chan-a"), 2); !errors.Is(err, domain.ErrLimit) {
		t.Fatalf("third subscription: %v, want ErrLimit", err)
	}

	got, err := st.Get(ctx, first.ID)
	if err != nil || got.Channel != "chan-a" || got.Key != "key" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	listed, err := st.Touch(ctx, "chan-a")
	if err != nil || len(listed) != 2 {
		t.Fatalf("Touch = %v, %v", listed, err)
	}

	if err := st.Delete(ctx, "chan-b", first.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete by another channel: %v, want ErrNotFound", err)
	}

	if err := st.Delete(ctx, "chan-a", first.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Get(ctx, first.ID); !errors.Is(err, domain.ErrGone) {
		t.Fatalf("deleted subscription: %v, want ErrGone", err)
	}

	if left, err := st.Touch(ctx, "chan-a"); err != nil || len(left) != 1 || left[0].ID != second.ID {
		t.Fatalf("Touch after delete = %v, %v", left, err)
	}

	// The freed place takes a new subscription.
	if err := st.Create(ctx, subscription("chan-a"), 2); err != nil {
		t.Fatalf("subscription after delete: %v", err)
	}
}

// Concurrent subscribes never exceed the channel's limit.
func TestSubscriptionLimitUnderContention(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()

	const limit, tries = 5, 20

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
	)

	for range tries {
		wg.Go(func() {
			if err := st.Create(ctx, subscription("busy"), limit); err == nil {
				mu.Lock()
				created++
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	listed, err := st.Touch(ctx, "busy")
	if err != nil || created != limit || len(listed) != limit {
		t.Fatalf("created %d, listed %d (%v), want %d", created, len(listed), err, limit)
	}
}

// Records not written for IdleExpiry are gone; Touch renews them.
func TestIdleExpiry(t *testing.T) {
	t.Parallel()

	s := settings()
	s.IdleExpiry = 2 * time.Second
	st, ctx := open(t, s), t.Context()

	kept, dropped := subscription("kept"), subscription("dropped")
	for _, sub := range []domain.Subscription{kept, dropped} {
		if err := st.Create(ctx, sub, 4); err != nil {
			t.Fatal(err)
		}
	}

	for range 3 {
		time.Sleep(time.Second)

		if _, err := st.Touch(ctx, "kept"); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := st.Get(ctx, kept.ID); err != nil {
		t.Fatalf("touched subscription: %v", err)
	}

	if _, err := st.Get(ctx, dropped.ID); !errors.Is(err, domain.ErrGone) {
		t.Fatalf("idle subscription: %v, want ErrGone", err)
	}
}

// collect opens the channel and gathers its deliveries.
type collect struct {
	mu   sync.Mutex
	got  []domain.Delivery
	seen chan struct{}
}

func (c *collect) deliver(d domain.Delivery) {
	c.mu.Lock()
	c.got = append(c.got, d)
	c.mu.Unlock()

	select {
	case c.seen <- struct{}{}:
	default:
	}
}

func (c *collect) wait(tb testing.TB, n int) []domain.Delivery {
	tb.Helper()

	deadline := time.After(5 * time.Second)

	for {
		c.mu.Lock()
		if len(c.got) >= n {
			got := append([]domain.Delivery(nil), c.got...)
			c.mu.Unlock()

			return got
		}
		c.mu.Unlock()

		select {
		case <-c.seen:
		case <-deadline:
			tb.Fatalf("%d deliveries, want %d", len(c.got), n)
		}
	}
}

// The mailbox keeps messages for a channel until a connection acknowledges
// them; a topic replaces an undelivered message; the channel's oldest is
// dropped at the limit.
func TestMailbox(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()
	sub := domain.NewSubscriptionID()
	put := func(topic, data string, limit int) {
		t.Helper()

		msg := domain.Message{Subscription: sub, Data: []byte(data), TTL: time.Minute, Topic: topic, Urgency: domain.High}
		if _, err := st.Put(ctx, "box", msg, limit); err != nil {
			t.Fatal(err)
		}
	}

	put("call", "first", 10)
	put("call", "replaced", 10)
	put("", "a", 3)
	put("", "b", 3)
	put("", "c", 3) // the limit drops "replaced", the oldest

	if online, err := st.Online(ctx, "box"); err != nil || online {
		t.Fatalf("Online before a connection = %v, %v", online, err)
	}

	c := &collect{seen: make(chan struct{}, 1)}

	in, err := st.Open(ctx, "box", c.deliver)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(in.Close)

	got := c.wait(t, 3)

	var data []string
	for _, d := range got {
		data = append(data, string(d.Data))

		if d.Subscription != sub || d.Urgency != domain.High || d.ID == "" || d.SentAt.IsZero() {
			t.Fatalf("delivery %+v", d)
		}

		if err := d.Ack(); err != nil {
			t.Fatal(err)
		}
	}

	if fmt.Sprint(data) != "[a b c]" {
		t.Fatalf("delivered %v, want [a b c]", data)
	}

	waitFor(t, func() bool {
		online, err := st.Online(ctx, "box")

		return err == nil && online
	})
}

// A message not acknowledged within AckWait is delivered again.
func TestRedelivery(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()

	if _, err := st.Put(ctx, "slow", domain.Message{Subscription: domain.NewSubscriptionID(), Data: []byte("x"), TTL: time.Minute}, 10); err != nil {
		t.Fatal(err)
	}

	c := &collect{seen: make(chan struct{}, 1)}

	in, err := st.Open(ctx, "slow", c.deliver)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(in.Close)

	got := c.wait(t, 2)
	if got[0].ID != got[1].ID {
		t.Fatalf("redelivery ids %q, %q: want the same", got[0].ID, got[1].ID)
	}
}

// A message's TTL drops it undelivered; Purge drops a subscription's.
func TestExpiryAndPurge(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()
	short, purged := domain.NewSubscriptionID(), domain.NewSubscriptionID()

	if _, err := st.Put(ctx, "gone", domain.Message{Subscription: short, Data: []byte("short"), TTL: time.Second}, 10); err != nil {
		t.Fatal(err)
	}

	if _, err := st.Put(ctx, "gone", domain.Message{Subscription: purged, Data: []byte("purged"), TTL: time.Minute}, 10); err != nil {
		t.Fatal(err)
	}

	if err := st.Purge(ctx, "gone", purged); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	c := &collect{seen: make(chan struct{}, 1)}

	in, err := st.Open(ctx, "gone", c.deliver)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(in.Close)

	time.Sleep(500 * time.Millisecond)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.got) != 0 {
		t.Fatalf("delivered %d expired or purged messages", len(c.got))
	}
}

// A newer connection of a channel replaces the older one.
func TestReplaced(t *testing.T) {
	t.Parallel()

	st, ctx := open(t, settings()), t.Context()
	noop := func(domain.Delivery) {}

	older, err := st.Open(ctx, "dup", noop)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(older.Close)

	newer, err := st.Open(ctx, "dup", noop)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(newer.Close)

	select {
	case <-older.Replaced():
	case <-time.After(5 * time.Second):
		t.Fatal("the older connection was not told")
	}

	select {
	case <-newer.Replaced():
		t.Fatal("the newer connection was told it was replaced")
	case <-time.After(200 * time.Millisecond):
	}
}

func waitFor(tb testing.TB, cond func() bool) {
	tb.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatal("condition not reached")
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func BenchmarkPut(b *testing.B) {
	st := open(b, settings())
	ctx := context.Background()
	msg := domain.Message{Subscription: domain.NewSubscriptionID(), Data: make([]byte, 512), TTL: time.Minute}

	for b.Loop() {
		if _, err := st.Put(ctx, "bench", msg, 1_000_000); err != nil {
			b.Fatal(err)
		}
	}
}
