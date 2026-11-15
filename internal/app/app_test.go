package app_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-pushgate/internal/app"
	"github.com/backplane-labs/backplane-pushgate/internal/domain"
)

var errDown = errors.New("store down")

// fakes are the ports in memory; err fails every call when set.
type fakeSubs struct {
	subs    map[domain.SubscriptionID]domain.Subscription
	err     error
	limited int
}

func (f *fakeSubs) Get(_ context.Context, id domain.SubscriptionID) (domain.Subscription, error) {
	if f.err != nil {
		return domain.Subscription{}, f.err
	}

	sub, ok := f.subs[id]
	if !ok {
		return domain.Subscription{}, domain.ErrGone
	}

	return sub, nil
}

func (f *fakeSubs) Create(_ context.Context, sub domain.Subscription, limit int) error {
	f.limited = limit
	if f.err != nil {
		return f.err
	}

	f.subs[sub.ID] = sub

	return nil
}

func (f *fakeSubs) Delete(_ context.Context, channel domain.Channel, id domain.SubscriptionID) error {
	if f.err != nil {
		return f.err
	}

	if sub, ok := f.subs[id]; !ok || sub.Channel != channel {
		return domain.ErrNotFound
	}

	delete(f.subs, id)

	return nil
}

func (f *fakeSubs) Touch(_ context.Context, channel domain.Channel) ([]domain.Subscription, error) {
	if f.err != nil {
		return nil, f.err
	}

	var out []domain.Subscription

	for _, sub := range f.subs {
		if sub.Channel == channel {
			out = append(out, sub)
		}
	}

	return out, nil
}

type fakeMail struct {
	online bool
	put    []domain.Message
	purged []domain.SubscriptionID
	err    error
}

func (f *fakeMail) Put(_ context.Context, _ domain.Channel, msg domain.Message, _ int) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	f.put = append(f.put, msg)

	return "7", nil
}

func (f *fakeMail) Online(context.Context, domain.Channel) (bool, error) { return f.online, f.err }

func (f *fakeMail) Purge(_ context.Context, _ domain.Channel, sub domain.SubscriptionID) error {
	f.purged = append(f.purged, sub)

	return f.err
}

func senderKey(tb testing.TB) string {
	tb.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func TestPush(t *testing.T) {
	t.Parallel()

	key := senderKey(t)
	sub := domain.Subscription{ID: domain.NewSubscriptionID(), Channel: "dev", Key: key}

	tests := []struct {
		name    string
		msg     domain.Message
		key     string
		online  bool
		subsErr error
		mailErr error
		wantID  string
		err     error
		kept    bool
	}{
		{name: "kept", msg: domain.Message{Subscription: sub.ID, TTL: time.Minute}, key: key, wantID: "7", kept: true},
		{name: "ttl 0 online", msg: domain.Message{Subscription: sub.ID}, key: key, online: true, wantID: "7", kept: true},
		{name: "ttl 0 offline dropped", msg: domain.Message{Subscription: sub.ID}, key: key},
		{name: "unknown subscription", msg: domain.Message{Subscription: domain.NewSubscriptionID(), TTL: time.Minute}, key: key, err: domain.ErrGone},
		{name: "another sender", msg: domain.Message{Subscription: sub.ID, TTL: time.Minute}, key: senderKey(t), err: domain.ErrWrongKey},
		{name: "subscriptions down", msg: domain.Message{Subscription: sub.ID, TTL: time.Minute}, key: key, subsErr: errDown, err: errDown},
		{name: "mailbox down", msg: domain.Message{Subscription: sub.ID, TTL: time.Minute}, key: key, mailErr: errDown, err: errDown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			subs := &fakeSubs{subs: map[domain.SubscriptionID]domain.Subscription{sub.ID: sub}, err: tc.subsErr}
			mail := &fakeMail{online: tc.online, err: tc.mailErr}

			id, err := app.New(subs, mail, app.Limits{Mailbox: 10}).Push(t.Context(), tc.msg, tc.key)
			if !errors.Is(err, tc.err) || id != tc.wantID || (len(mail.put) == 1) != tc.kept {
				t.Fatalf("Push = %q, %v (kept %d); want %q, %v, kept %v", id, err, len(mail.put), tc.wantID, tc.err, tc.kept)
			}
		})
	}
}

func TestSubscribeAndUnsubscribe(t *testing.T) {
	t.Parallel()

	key := senderKey(t)
	subs := &fakeSubs{subs: map[domain.SubscriptionID]domain.Subscription{}}
	mail := &fakeMail{}
	svc := app.New(subs, mail, app.Limits{Subscriptions: 3})

	if _, err := svc.Subscribe(t.Context(), "dev", "not a key"); !errors.Is(err, domain.ErrKey) {
		t.Fatalf("bad key: %v", err)
	}

	sub, err := svc.Subscribe(t.Context(), "dev", key+"=")
	if err != nil || sub.Key != key || sub.Channel != "dev" || sub.CreatedAt.IsZero() || subs.limited != 3 {
		t.Fatalf("Subscribe = %+v, %v (limit %d)", sub, err, subs.limited)
	}

	listed, err := svc.Hello(t.Context(), "dev")
	if err != nil || len(listed) != 1 || listed[0].ID != sub.ID {
		t.Fatalf("Hello = %v, %v", listed, err)
	}

	if err := svc.Unsubscribe(t.Context(), "other", sub.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unsubscribe by another channel: %v", err)
	}

	if err := svc.Unsubscribe(t.Context(), "dev", sub.ID); err != nil || len(mail.purged) != 1 || mail.purged[0] != sub.ID {
		t.Fatalf("Unsubscribe = %v, purged %v", err, mail.purged)
	}

	subs.err = errDown
	if _, err := svc.Hello(t.Context(), "dev"); !errors.Is(err, errDown) {
		t.Fatalf("Hello with the store down: %v", err)
	}
}

func BenchmarkPush(b *testing.B) {
	key := senderKey(b)
	sub := domain.Subscription{ID: domain.NewSubscriptionID(), Channel: "dev", Key: key}
	svc := app.New(&fakeSubs{subs: map[domain.SubscriptionID]domain.Subscription{sub.ID: sub}}, &fakeMail{}, app.Limits{Mailbox: 10})
	msg := domain.Message{Subscription: sub.ID, TTL: time.Minute}

	for b.Loop() {
		_, _ = svc.Push(context.Background(), msg, key)
	}
}
