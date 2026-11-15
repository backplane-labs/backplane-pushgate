package session_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	"github.com/backplane-labs/backplane-pushgate/internal/pushtest"
	"github.com/backplane-labs/backplane-pushgate/internal/session"
	clientv1 "github.com/backplane-labs/backplane-pushgate/proto/pushgate/client/v1"
)

var errDown = errors.New("nats down")

// fakeCases runs the scenarios in memory.
type fakeCases struct {
	mu        sync.Mutex
	subs      []domain.Subscription
	helloErr  error
	subscribe error
}

func (f *fakeCases) Hello(context.Context, domain.Channel) ([]domain.Subscription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.subs, f.helloErr
}

func (f *fakeCases) Subscribe(_ context.Context, channel domain.Channel, key string) (domain.Subscription, error) {
	if f.subscribe != nil {
		return domain.Subscription{}, f.subscribe
	}

	if _, err := domain.ParseKey(key); err != nil {
		return domain.Subscription{}, err
	}

	sub := domain.Subscription{ID: domain.NewSubscriptionID(), Channel: channel, Key: key}

	f.mu.Lock()
	f.subs = append(f.subs, sub)
	f.mu.Unlock()

	return sub, nil
}

func (f *fakeCases) Unsubscribe(_ context.Context, _ domain.Channel, id domain.SubscriptionID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, sub := range f.subs {
		if sub.ID == id {
			f.subs = append(f.subs[:i], f.subs[i+1:]...)

			return nil
		}
	}

	return domain.ErrNotFound
}

// fakeInbox hands the test the deliver func and records acks.
type fakeInbox struct {
	mu       sync.Mutex
	deliver  func(domain.Delivery)
	opened   chan struct{}
	replaced chan struct{}
	closed   chan struct{}
	acked    []string
	err      error
}

func newInbox() *fakeInbox {
	return &fakeInbox{opened: make(chan struct{}), replaced: make(chan struct{}), closed: make(chan struct{})}
}

func (f *fakeInbox) Open(_ context.Context, _ domain.Channel, deliver func(domain.Delivery)) (session.Stream, error) {
	if f.err != nil {
		return session.Stream{}, f.err
	}

	f.mu.Lock()
	f.deliver = deliver
	f.mu.Unlock()
	close(f.opened)

	return session.Stream{Replaced: f.replaced, Close: func() { close(f.closed) }}, nil
}

func (f *fakeInbox) send(tb testing.TB, id, data string) {
	tb.Helper()

	select {
	case <-f.opened:
	case <-time.After(5 * time.Second):
		tb.Fatal("the inbox was not opened")
	}

	f.mu.Lock()
	deliver := f.deliver
	f.mu.Unlock()

	deliver(domain.Delivery{
		ID: id, Subscription: "sub", Data: []byte(data), Topic: "t", Urgency: domain.High, SentAt: time.Now(),
		Ack: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()

			f.acked = append(f.acked, id)

			return nil
		},
	})
}

func (f *fakeInbox) acks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.acked...)
}

// serve runs the sessions handler; its WebSocket URL.
func serve(tb testing.TB, cases *fakeCases, inbox *fakeInbox, s session.Settings) string {
	tb.Helper()

	h := backplanetest.New(tb)
	sessions := session.New(h.Root(), cases, inbox, func(id domain.SubscriptionID) string {
		return "https://push.example.com/wpush/" + string(id)
	}, s)

	srv := httptest.NewServer(sessions)
	tb.Cleanup(srv.Close)

	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func settings() session.Settings {
	return session.Settings{HelloTimeout: time.Second, Keepalive: time.Minute}
}

const senderKey = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"

// A proven hello is welcomed with the channel's subscriptions; messages
// reach the client and its acks reach the inbox.
func TestSession(t *testing.T) {
	t.Parallel()

	key := pushtest.DeviceKey(t)
	cases := &fakeCases{subs: []domain.Subscription{{ID: "known", Key: senderKey}}}
	inbox := newInbox()

	c := pushtest.Dial(t, serve(t, cases, inbox, settings()), key)

	w := c.Welcome()
	if w.GetChannel() != string(domain.ChannelOf(ed25519.PublicKey(key[ed25519.SeedSize:]))) || len(w.GetSubscriptions()) != 1 ||
		w.GetSubscriptions()[0].GetEndpoint() != "https://push.example.com/wpush/known" {
		t.Fatalf("welcome %v", w)
	}

	sub, refused := c.Subscribe(t, senderKey)
	if refused != nil || sub.GetApplicationServerKey() != senderKey || !strings.HasSuffix(sub.GetEndpoint(), "/wpush/"+sub.GetId()) {
		t.Fatalf("subscribe %v %v", sub, refused)
	}

	inbox.send(t, "1", "hello")

	n := c.Notification(t)
	if n.GetId() != "1" || string(n.GetData()) != "hello" || n.GetTopic() != "t" || n.GetUrgency() != "high" ||
		n.GetSubscription() != "sub" || n.GetSentAt() == nil {
		t.Fatalf("notification %v", n)
	}

	c.Ack(t, "1", "unknown")

	if r := c.Unsubscribe(t, sub.GetId()); r != nil {
		t.Fatalf("unsubscribe refused %v", r)
	}

	if got := inbox.acks(); len(got) != 1 || got[0] != "1" {
		t.Fatalf("acked %v, want [1]", got)
	}
}

// Requests that fail are refused with their code; the session goes on.
func TestRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		subscribe error
		key       string
		unsub     string
		code      clientv1.RefusalCode
		message   string
	}{
		{name: "bad key", key: "nope", code: clientv1.RefusalCode_REFUSAL_CODE_INVALID},
		{name: "limit", key: senderKey, subscribe: domain.ErrLimit, code: clientv1.RefusalCode_REFUSAL_CODE_LIMIT},
		{name: "store down", key: senderKey, subscribe: errDown, code: clientv1.RefusalCode_REFUSAL_CODE_UNSPECIFIED, message: "try again later"},
		{name: "unknown subscription", unsub: string(domain.NewSubscriptionID()), code: clientv1.RefusalCode_REFUSAL_CODE_NOT_FOUND},
		{name: "malformed subscription", unsub: "nope", code: clientv1.RefusalCode_REFUSAL_CODE_INVALID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := pushtest.Dial(t, serve(t, &fakeCases{subscribe: tc.subscribe}, newInbox(), settings()), pushtest.DeviceKey(t))

			var refused *clientv1.Refused
			if tc.unsub != "" {
				refused = c.Unsubscribe(t, tc.unsub)
			} else {
				_, refused = c.Subscribe(t, tc.key)
			}

			if refused == nil || refused.GetCode() != tc.code || !strings.Contains(refused.GetMessage(), tc.message) {
				t.Fatalf("refused %v, want %v", refused, tc.code)
			}

			if strings.Contains(refused.GetMessage(), "nats") {
				t.Fatalf("a technical failure leaked: %v", refused)
			}

			// The session continues.
			if _, r := c.Subscribe(t, "still-bad"); r == nil {
				t.Fatal("no answer after a refusal")
			}
		})
	}
}

// A connection that does not prove a key, sends a bad frame, is replaced
// or cannot be served is closed with its code.
func TestCloses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cases *fakeCases
		inbox func() *fakeInbox
		run   func(t *testing.T, url string, inbox *fakeInbox) websocket.StatusCode
		want  websocket.StatusCode
	}{
		{
			name: "no hello in time", want: session.CodeHelloTimeout,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c, err := pushtest.Connect(t, url)
				if err != nil {
					t.Fatal(err)
				}

				c.Next(t) // challenge

				return c.Closed(t)
			},
		},
		{
			name: "a signature of something else", want: session.CodeUnauthenticated,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c, err := pushtest.Connect(t, url)
				if err != nil {
					t.Fatal(err)
				}

				c.Next(t)

				key := pushtest.DeviceKey(t)
				c.Send(t, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Hello{Hello: &clientv1.Hello{
					PublicKey: key[ed25519.SeedSize:], Signature: ed25519.Sign(key, []byte("not the challenge")),
				}}})

				return c.Closed(t)
			},
		},
		{
			name: "a subscribe before hello", want: session.CodeUnauthenticated,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c, err := pushtest.Connect(t, url)
				if err != nil {
					t.Fatal(err)
				}

				c.Next(t)
				c.Send(t, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Subscribe{Subscribe: &clientv1.Subscribe{}}})

				return c.Closed(t)
			},
		},
		{
			name: "not protojson", want: session.CodeBadFrame,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c := pushtest.Dial(t, url, pushtest.DeviceKey(t))
				c.SendRaw(t, "{oops")

				return c.Closed(t)
			},
		},
		{
			name: "an empty frame", want: session.CodeBadFrame,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c := pushtest.Dial(t, url, pushtest.DeviceKey(t))
				c.SendRaw(t, "{}")

				return c.Closed(t)
			},
		},
		{
			name: "replaced", want: session.CodeReplaced,
			run: func(t *testing.T, url string, inbox *fakeInbox) websocket.StatusCode {
				t.Helper()

				c := pushtest.Dial(t, url, pushtest.DeviceKey(t))
				<-inbox.opened
				close(inbox.replaced)

				return c.Closed(t)
			},
		},
		{
			name: "hello cannot be served", cases: &fakeCases{helloErr: errDown}, want: websocket.StatusInternalError,
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c, err := pushtest.Connect(t, url)
				if err != nil {
					t.Fatal(err)
				}

				challenge := c.Next(t).GetChallenge()
				key := pushtest.DeviceKey(t)
				c.Send(t, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Hello{Hello: &clientv1.Hello{
					PublicKey: key[ed25519.SeedSize:], Signature: ed25519.Sign(key, domain.HelloMessage(challenge.GetNonce())),
				}}})

				return c.Closed(t)
			},
		},
		{
			name: "inbox cannot open", want: websocket.StatusInternalError,
			inbox: func() *fakeInbox { i := newInbox(); i.err = errDown; return i },
			run: func(t *testing.T, url string, _ *fakeInbox) websocket.StatusCode {
				t.Helper()

				c := pushtest.Dial(t, url, pushtest.DeviceKey(t))

				return c.Closed(t)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cases, inbox := tc.cases, newInbox()
			if cases == nil {
				cases = &fakeCases{}
			}

			if tc.inbox != nil {
				inbox = tc.inbox()
			}

			if got := tc.run(t, serve(t, cases, inbox, settings()), inbox); got != tc.want {
				t.Fatalf("closed with %d, want %d", got, tc.want)
			}
		})
	}
}

// A client that stops answering pings is dropped: its inbox is closed.
func TestKeepalive(t *testing.T) {
	t.Parallel()

	inbox := newInbox()
	s := settings()
	s.Keepalive = 100 * time.Millisecond
	url := serve(t, &fakeCases{}, inbox, s)

	ws, res, err := websocket.Dial(t.Context(), url, nil)
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ws.CloseNow() })

	// Answer the challenge, then stop reading: pongs stop with it.
	_, raw, err := ws.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	nonce := challengeNonce(t, raw)
	key := pushtest.DeviceKey(t)
	hello := `{"hello":{"publicKey":"` + b64(key[ed25519.SeedSize:]) + `","signature":"` +
		b64(ed25519.Sign(key, domain.HelloMessage(nonce))) + `"}}`

	if err := ws.Write(t.Context(), websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-inbox.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a silent client was kept")
	}
}

func BenchmarkSessionDelivery(b *testing.B) {
	inbox := newInbox()
	c := pushtest.Dial(b, serve(b, &fakeCases{}, inbox, settings()), pushtest.DeviceKey(b))

	for b.Loop() {
		inbox.send(b, "1", "payload")
		c.Notification(b)
	}
}

// challengeNonce reads the nonce of a challenge frame.
func challengeNonce(tb testing.TB, raw []byte) []byte {
	tb.Helper()

	frame := &clientv1.ServerFrame{}
	if err := protojson.Unmarshal(raw, frame); err != nil || frame.GetChallenge() == nil {
		tb.Fatalf("challenge %s: %v", raw, err)
	}

	return frame.GetChallenge().GetNonce()
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
