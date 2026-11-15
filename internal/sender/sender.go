// Package sender serves the RFC 8030 push resource: a sender posts an
// encrypted message to a subscription's endpoint.
package sender

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	"github.com/backplane-labs/backplane-pushgate/internal/vapid"
)

// Path is the prefix of the endpoints: <public_url>/wpush/<subscription>.
const Path = "/wpush/"

// Errnos of the error body (autopush's numbering).
const (
	errnoInvalid      = 101
	errnoMalformedURL = 102
	errnoGone         = 103
	errnoTooLarge     = 104
	errnoUnauthorized = 109
	errnoEncoding     = 110
	errnoTTL          = 111
	errnoTopic        = 113
	errnoUrgency      = 114
	errnoMethod       = 405
	errnoFailure      = 999
)

// Outcomes of a send, the pushgate.sends attribute.
const (
	outcomeAccepted     = "accepted"
	outcomeDropped      = "dropped"
	outcomeInvalid      = "invalid"
	outcomeGone         = "gone"
	outcomeUnauthorized = "unauthorized"
	outcomeWrongKey     = "wrong_key"
	outcomeTooLarge     = "too_large"
	outcomeFailed       = "failed"
)

// Cases is the scenario the sender runs.
type Cases interface {
	Push(ctx context.Context, msg domain.Message, senderKey string) (string, error)
	MaxTTL() time.Duration
}

// Sender serves the endpoints.
type Sender struct {
	deps.Component

	cases    Cases
	public   *url.URL
	audience string
	sends    metric.Int64Counter
	now      func() time.Time
}

// New is the endpoints' handler under parent; public is the service's
// public URL (endpoints and the VAPID audience come from it).
func New(parent deps.Scope, cases Cases, public *url.URL) *Sender {
	s := &Sender{
		Component: deps.NewComponent(parent, "sender"), cases: cases, public: public,
		audience: public.Scheme + "://" + public.Host, now: time.Now,
	}

	s.sends, _ = s.Meter().Int64Counter("pushgate.sends",
		metric.WithDescription("Messages posted by senders, by outcome"))

	return s
}

// Endpoint is a subscription's push resource.
func (s *Sender) Endpoint(id domain.SubscriptionID) string {
	return s.public.JoinPath(Path, string(id)).String()
}

// failure is an answer other than 201, in autopush's error shape.
type failure struct {
	status  int
	errno   int
	outcome string
	err     error
}

// refusal is a failure answered with status and errno.
func refusal(status, errno int, outcome string, err error) failure {
	return failure{status: status, errno: errno, outcome: outcome, err: err}
}

// errorBody is the error body.
type errorBody struct {
	Code    int    `json:"code"`
	Errno   int    `json:"errno"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// ServeHTTP accepts one message.
func (s *Sender) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.fail(r.Context(), w, refusal(http.StatusMethodNotAllowed, errnoMethod, outcomeInvalid, errMethod))

		return
	}

	msg, key, f := s.read(r)
	if f.status != 0 {
		s.fail(r.Context(), w, f)

		return
	}

	id, err := s.cases.Push(r.Context(), msg, key)
	if err != nil {
		s.fail(r.Context(), w, pushFailure(err))

		return
	}

	outcome := outcomeAccepted
	if id == "" {
		outcome, id = outcomeDropped, "0"
	}

	s.sends.Add(r.Context(), 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	w.Header().Set("Location", s.public.JoinPath("/m/", id).String())
	w.Header().Set("TTL", strconv.FormatInt(int64(msg.TTL/time.Second), 10))
	w.WriteHeader(http.StatusCreated)
}

var errMethod = errors.New("pushgate: POST the message")

// read parses the request: the message and the sender's key, or why not.
func (s *Sender) read(r *http.Request) (domain.Message, string, failure) {
	id, err := domain.ParseSubscriptionID(strings.TrimPrefix(r.URL.Path, Path))
	if err != nil {
		return domain.Message{}, "", refusal(http.StatusNotFound, errnoMalformedURL, outcomeGone, err)
	}

	key, err := vapid.Verify(r.Header.Get("Authorization"), s.audience, s.now())
	if err != nil {
		return domain.Message{}, "", refusal(http.StatusUnauthorized, errnoUnauthorized, outcomeUnauthorized, err)
	}

	msg := domain.Message{Subscription: id}

	if msg.TTL, err = domain.ParseTTL(r.Header.Get("TTL"), s.cases.MaxTTL()); err != nil {
		return msg, "", refusal(http.StatusBadRequest, errnoTTL, outcomeInvalid, err)
	}

	if msg.Topic, err = domain.ParseTopic(r.Header.Get("Topic")); err != nil {
		return msg, "", refusal(http.StatusBadRequest, errnoTopic, outcomeInvalid, err)
	}

	if msg.Urgency, err = domain.ParseUrgency(r.Header.Get("Urgency")); err != nil {
		return msg, "", refusal(http.StatusBadRequest, errnoUrgency, outcomeInvalid, err)
	}

	if msg.Data, err = io.ReadAll(io.LimitReader(r.Body, domain.MaxPayload+1)); err != nil {
		return msg, "", refusal(http.StatusBadRequest, errnoInvalid, outcomeInvalid, err)
	}

	switch err := domain.CheckBody(r.Header.Get("Content-Encoding"), len(msg.Data)); {
	case errors.Is(err, domain.ErrTooLarge):
		return msg, "", refusal(http.StatusRequestEntityTooLarge, errnoTooLarge, outcomeTooLarge, err)
	case err != nil:
		return msg, "", refusal(http.StatusBadRequest, errnoEncoding, outcomeInvalid, err)
	}

	return msg, key, failure{}
}

// pushFailure is the answer to a failed push.
func pushFailure(err error) failure {
	switch {
	case errors.Is(err, domain.ErrGone):
		return refusal(http.StatusGone, errnoGone, outcomeGone, err)
	case errors.Is(err, domain.ErrWrongKey):
		return refusal(http.StatusForbidden, errnoUnauthorized, outcomeWrongKey, err)
	default:
		return refusal(http.StatusInternalServerError, errnoFailure, outcomeFailed, err)
	}
}

func (s *Sender) fail(ctx context.Context, w http.ResponseWriter, f failure) {
	s.sends.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", f.outcome)))

	message := f.err.Error()
	if f.status == http.StatusInternalServerError {
		// A technical failure: logged with its cause, the sender gets no
		// detail.
		backplane.CaptureError(ctx, s.Log(), fmt.Errorf("push: %w", f.err), xlog.String("outcome", f.outcome))

		message = "push service failure: retry later"
	}

	body, err := json.Marshal(errorBody{
		Code: f.status, Errno: f.errno, Error: http.StatusText(f.status), Message: message,
	})
	if err != nil {
		body = []byte(`{}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = w.Write(body)
}
