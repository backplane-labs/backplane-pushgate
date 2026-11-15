package sender_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	"github.com/backplane-labs/backplane-pushgate/internal/sender"
	"github.com/backplane-labs/backplane-pushgate/internal/vapid/vapidtest"
)

const public = "https://push.example.com"

// fakeCases answers Push with id and err, recording what it got.
type fakeCases struct {
	id    string
	err   error
	got   domain.Message
	key   string
	calls int
}

func (f *fakeCases) Push(_ context.Context, msg domain.Message, key string) (string, error) {
	f.calls++
	f.got, f.key = msg, key

	return f.id, f.err
}

func (*fakeCases) MaxTTL() time.Duration { return time.Hour }

func TestServeHTTP(t *testing.T) {
	t.Parallel()

	sub := domain.NewSubscriptionID()
	s := vapidtest.New(t)
	auth := s.Header(t, public)

	tests := []struct {
		name     string
		method   string
		path     string
		header   map[string]string
		body     string
		id       string
		err      error
		status   int
		errno    int
		location string
		ttl      string
	}{
		{
			name: "accepted", path: string(sub), body: "secret", id: "42", status: http.StatusCreated,
			header:   map[string]string{"TTL": "60", "Topic": "call-1", "Urgency": "high", "Content-Encoding": "aes128gcm"},
			location: public + "/m/42", ttl: "60",
		},
		{
			name: "ttl capped", path: string(sub), id: "43", status: http.StatusCreated,
			header: map[string]string{"TTL": "999999"}, location: public + "/m/43", ttl: "3600",
		},
		{
			name: "ttl 0 dropped", path: string(sub), status: http.StatusCreated,
			header: map[string]string{"TTL": "0"}, location: public + "/m/0", ttl: "0",
		},
		{name: "get", method: http.MethodGet, path: string(sub), status: http.StatusMethodNotAllowed, errno: 405},
		{name: "malformed id", path: "nope", header: map[string]string{"TTL": "60"}, status: http.StatusNotFound, errno: 102},
		{name: "no authorization", path: string(sub), header: map[string]string{"TTL": "60", "Authorization": ""}, status: http.StatusUnauthorized, errno: 109},
		{name: "no ttl", path: string(sub), status: http.StatusBadRequest, errno: 111},
		{name: "bad topic", path: string(sub), header: map[string]string{"TTL": "60", "Topic": "a.b"}, status: http.StatusBadRequest, errno: 113},
		{name: "bad urgency", path: string(sub), header: map[string]string{"TTL": "60", "Urgency": "now"}, status: http.StatusBadRequest, errno: 114},
		{name: "bad encoding", path: string(sub), body: "x", header: map[string]string{"TTL": "60", "Content-Encoding": "aesgcm"}, status: http.StatusBadRequest, errno: 110},
		{
			name: "too large", path: string(sub), body: strings.Repeat("x", 4097),
			header: map[string]string{"TTL": "60", "Content-Encoding": "aes128gcm"}, status: http.StatusRequestEntityTooLarge, errno: 104,
		},
		{name: "gone", path: string(sub), header: map[string]string{"TTL": "60"}, err: domain.ErrGone, status: http.StatusGone, errno: 103},
		{name: "wrong key", path: string(sub), header: map[string]string{"TTL": "60"}, err: domain.ErrWrongKey, status: http.StatusForbidden, errno: 109},
		{name: "store down", path: string(sub), header: map[string]string{"TTL": "60"}, err: errors.New("nats down"), status: http.StatusInternalServerError, errno: 999},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cases := &fakeCases{id: tc.id, err: tc.err}
			h := backplanetest.New(t)
			u, _ := url.Parse(public)
			srv := sender.New(h.Root(), cases, u)

			method := tc.method
			if method == "" {
				method = http.MethodPost
			}

			req := httptest.NewRequestWithContext(t.Context(), method, sender.Path+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", auth)

			for k, v := range tc.header {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != tc.status {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, tc.status)
			}

			if tc.status == http.StatusCreated {
				if w.Header().Get("Location") != tc.location || w.Header().Get("TTL") != tc.ttl {
					t.Fatalf("Location %q TTL %q, want %q %q", w.Header().Get("Location"), w.Header().Get("TTL"), tc.location, tc.ttl)
				}

				if cases.key != s.Public || cases.got.Subscription != sub {
					t.Fatalf("pushed %+v by %q", cases.got, cases.key)
				}

				return
			}

			var body struct {
				Code    int    `json:"code"`
				Errno   int    `json:"errno"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != tc.status || body.Errno != tc.errno {
				t.Fatalf("body %s (%v), want code %d errno %d", w.Body, err, tc.status, tc.errno)
			}

			if tc.status == http.StatusInternalServerError && strings.Contains(body.Message, "nats") {
				t.Fatalf("a technical failure leaked to the sender: %s", body.Message)
			}
		})
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	u, _ := url.Parse("https://push.example.com/base")
	srv := sender.New(backplanetest.New(t).Root(), &fakeCases{}, u)

	if got := srv.Endpoint("abc"); got != "https://push.example.com/base/wpush/abc" {
		t.Fatalf("endpoint %q", got)
	}
}

func BenchmarkServeHTTP(b *testing.B) {
	sub := domain.NewSubscriptionID()
	s := vapidtest.New(b)
	auth := s.Header(b, public)
	u, _ := url.Parse(public)
	srv := sender.New(backplanetest.New(b).Root(), &fakeCases{id: "1"}, u)

	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, sender.Path+string(sub), strings.NewReader("x"))
		req.Header.Set("Authorization", auth)
		req.Header.Set("TTL", "60")
		req.Header.Set("Content-Encoding", "aes128gcm")
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}
}
