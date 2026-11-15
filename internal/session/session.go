// Package session serves a desktop client's WebSocket: the challenge and
// hello, its subscriptions, and its channel's messages until it
// acknowledges them.
package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/coder/websocket"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	clientv1 "github.com/backplane-labs/backplane-pushgate/proto/pushgate/client/v1"
)

// Path is the client's WebSocket: <public_url>/connect.
const Path = "/connect"

// Close codes beyond RFC 6455's.
const (
	// CodeBadFrame: a frame that is not a ClientFrame, or out of order.
	CodeBadFrame websocket.StatusCode = 4400
	// CodeUnauthenticated: the first frame is not a hello, or the hello
	// does not prove the challenge: reconnecting with the same key fails
	// again.
	CodeUnauthenticated websocket.StatusCode = 4401
	// CodeHelloTimeout: no hello within the hello timeout; a slow network
	// may succeed on the next attempt.
	CodeHelloTimeout websocket.StatusCode = 4408
	// CodeReplaced: a newer connection of the channel opened.
	CodeReplaced websocket.StatusCode = 4409
)

// Limits of a connection.
const (
	// maxFrame bounds a client frame.
	maxFrame = 64 << 10
	// writeTimeout bounds sending one frame.
	writeTimeout = 10 * time.Second
)

// Cases are the scenarios a device runs.
type Cases interface {
	Hello(ctx context.Context, channel domain.Channel) ([]domain.Subscription, error)
	Subscribe(ctx context.Context, channel domain.Channel, key string) (domain.Subscription, error)
	Unsubscribe(ctx context.Context, channel domain.Channel, id domain.SubscriptionID) error
}

// Stream is one connection's consumption of its channel.
type Stream struct {
	// Replaced is closed when a newer connection of the channel opened.
	Replaced <-chan struct{}
	// Close stops the consumption.
	Close func()
}

// Inboxes open a channel's messages for a connection.
type Inboxes interface {
	Open(ctx context.Context, channel domain.Channel, deliver func(domain.Delivery)) (Stream, error)
}

// Settings of a connection.
type Settings struct {
	// HelloTimeout is the time to answer the challenge.
	HelloTimeout time.Duration
	// Keepalive is the ping interval; a ping unanswered within it closes
	// the connection.
	Keepalive time.Duration
}

// Sessions serves the clients' connections.
type Sessions struct {
	deps.Component

	cases    Cases
	inboxes  Inboxes
	endpoint func(domain.SubscriptionID) string
	settings Settings

	open       metric.Int64UpDownCounter
	deliveries metric.Int64Counter
}

// New is the clients' handler under parent; endpoint is a subscription's
// push resource.
func New(
	parent deps.Scope, cases Cases, inboxes Inboxes, endpoint func(domain.SubscriptionID) string, s Settings,
) *Sessions {
	sessions := &Sessions{
		Component: deps.NewComponent(parent, "sessions"), cases: cases, inboxes: inboxes, endpoint: endpoint, settings: s,
	}

	sessions.open, _ = sessions.Meter().Int64UpDownCounter("pushgate.sessions",
		metric.WithDescription("Open client sessions"))
	sessions.deliveries, _ = sessions.Meter().Int64Counter("pushgate.deliveries",
		metric.WithDescription("Messages sent to and acknowledged by clients, by outcome"))

	return sessions
}

// conn is one client connection.
type conn struct {
	ws       *websocket.Conn
	sessions *Sessions
	channel  domain.Channel
	cancel   context.CancelFunc

	write sync.Mutex

	mu       sync.Mutex
	inflight map[string]func() error // by message id, until acknowledged
}

// ServeHTTP runs one connection until it ends. Any origin is accepted:
// no cookie or ambient credential is involved, what authenticates is the
// hello's signature, which a page without the device's key cannot make.
func (s *Sessions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}

	defer func() { _ = ws.CloseNow() }()

	ws.SetReadLimit(maxFrame)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	c := &conn{ws: ws, sessions: s, cancel: cancel, inflight: map[string]func() error{}}

	channel, code, err := c.authenticate(ctx)
	if err != nil {
		_ = ws.Close(code, err.Error())

		return
	}

	c.channel = channel

	s.open.Add(ctx, 1)
	defer s.open.Add(context.WithoutCancel(ctx), -1)

	if err := c.run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, errClientGone) {
		s.Log().Ctx().Warn(ctx, "client session ended", xlog.Err(err))
	}
}

// authenticate sends the challenge and checks the hello; the close code
// when it fails.
func (c *conn) authenticate(ctx context.Context) (domain.Channel, websocket.StatusCode, error) {
	nonce := domain.Nonce()

	if err := c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Challenge{
		Challenge: &clientv1.Challenge{Nonce: nonce},
	}}); err != nil {
		return "", websocket.StatusGoingAway, err
	}

	// A Read whose context ends closes the connection without a code: the
	// timeout closes it with ours instead.
	late := time.AfterFunc(c.sessions.settings.HelloTimeout, func() {
		_ = c.ws.Close(CodeHelloTimeout, "no hello in time")
	})
	defer late.Stop()

	frame, err := c.read(ctx)
	if err != nil {
		return "", CodeUnauthenticated, fmt.Errorf("no hello: %w", err)
	}

	hello := frame.GetHello()
	if hello == nil {
		return "", CodeUnauthenticated, errNoHello
	}

	channel, err := domain.VerifyHello(hello.GetPublicKey(), hello.GetSignature(), nonce)
	if err != nil {
		return "", CodeUnauthenticated, err
	}

	return channel, 0, nil
}

var (
	errNoHello  = errors.New("the first frame must be a hello")
	errBadFrame = errors.New("unexpected frame")
	// errClientGone: the client closed, or the session ended: not a
	// failure.
	errClientGone = errors.New("client gone")
)

// run serves an authenticated connection: welcome, then the channel's
// messages and the client's requests, until the client leaves, a newer
// connection replaces it or it stops answering pings.
func (c *conn) run(ctx context.Context) error {
	subs, err := c.sessions.cases.Hello(ctx, c.channel)
	if err != nil {
		_ = c.ws.Close(websocket.StatusInternalError, "try again later")

		return fmt.Errorf("hello: %w", err)
	}

	welcome := &clientv1.Welcome{Channel: string(c.channel)}
	for _, sub := range subs {
		welcome.Subscriptions = append(welcome.Subscriptions, c.subscription(sub))
	}

	if err := c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Welcome{Welcome: welcome}}); err != nil {
		return err
	}

	stream, err := c.sessions.inboxes.Open(ctx, c.channel, func(d domain.Delivery) { c.deliver(ctx, d) })
	if err != nil {
		_ = c.ws.Close(websocket.StatusInternalError, "try again later")

		return fmt.Errorf("open inbox: %w", err)
	}

	defer stream.Close()

	var wg sync.WaitGroup
	defer wg.Wait()
	defer c.cancel()

	wg.Go(func() { c.keepalive(ctx) })
	wg.Go(func() {
		select {
		case <-stream.Replaced:
			_ = c.ws.Close(CodeReplaced, "a newer connection of this channel opened")
			c.cancel()
		case <-ctx.Done():
		}
	})

	return c.serve(ctx)
}

// serve answers the client's frames until the connection ends.
func (c *conn) serve(ctx context.Context) error {
	for {
		frame, err := c.read(ctx)
		if err != nil && (ctx.Err() != nil || websocket.CloseStatus(err) != -1) {
			return fmt.Errorf("%w: %w", errClientGone, err)
		}

		if err != nil {
			return err
		}

		switch f := frame.GetFrame().(type) {
		case *clientv1.ClientFrame_Subscribe:
			c.subscribe(ctx, f.Subscribe)
		case *clientv1.ClientFrame_Unsubscribe:
			c.unsubscribe(ctx, f.Unsubscribe)
		case *clientv1.ClientFrame_Ack:
			c.ack(ctx, f.Ack.GetIds())
		default:
			_ = c.ws.Close(CodeBadFrame, errBadFrame.Error())

			return nil
		}
	}
}

func (c *conn) subscribe(ctx context.Context, req *clientv1.Subscribe) {
	sub, err := c.sessions.cases.Subscribe(ctx, c.channel, req.GetApplicationServerKey())
	if err != nil {
		c.refuse(ctx, req.GetRequestId(), err)

		return
	}

	_ = c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Subscribed{Subscribed: &clientv1.Subscribed{
		RequestId: req.GetRequestId(), Subscription: c.subscription(sub),
	}}})
}

func (c *conn) unsubscribe(ctx context.Context, req *clientv1.Unsubscribe) {
	id, err := domain.ParseSubscriptionID(req.GetSubscription())
	if err == nil {
		err = c.sessions.cases.Unsubscribe(ctx, c.channel, id)
	}

	if err != nil {
		c.refuse(ctx, req.GetRequestId(), err)

		return
	}

	_ = c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Unsubscribed{Unsubscribed: &clientv1.Unsubscribed{
		RequestId: req.GetRequestId(), Subscription: req.GetSubscription(),
	}}})
}

// refuse answers a failed request; a technical failure is logged and
// reported to the client as unspecified.
func (c *conn) refuse(ctx context.Context, requestID string, err error) {
	code := clientv1.RefusalCode_REFUSAL_CODE_UNSPECIFIED

	switch {
	case errors.Is(err, domain.ErrKey), errors.Is(err, domain.ErrSubscriptionID):
		code = clientv1.RefusalCode_REFUSAL_CODE_INVALID
	case errors.Is(err, domain.ErrNotFound):
		code = clientv1.RefusalCode_REFUSAL_CODE_NOT_FOUND
	case errors.Is(err, domain.ErrLimit):
		code = clientv1.RefusalCode_REFUSAL_CODE_LIMIT
	default:
		c.sessions.Log().Ctx().Warn(ctx, "client request failed", xlog.Err(err))
		err = errTryLater
	}

	_ = c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Refused{Refused: &clientv1.Refused{
		RequestId: requestID, Code: code, Message: err.Error(),
	}}})
}

var errTryLater = errors.New("push service failure: try again later")

// deliver sends a message and remembers it until acknowledged.
func (c *conn) deliver(ctx context.Context, d domain.Delivery) {
	c.mu.Lock()
	c.inflight[d.ID] = d.Ack
	c.mu.Unlock()

	notification := &clientv1.Notification{
		Id: d.ID, Subscription: string(d.Subscription), Data: d.Data, Topic: d.Topic, Urgency: string(d.Urgency),
		SentAt: timestamppb.New(d.SentAt),
	}

	err := c.send(ctx, &clientv1.ServerFrame{Frame: &clientv1.ServerFrame_Notification{Notification: notification}})

	outcome := "sent"
	if err != nil {
		// The message is sent again to the next connection.
		outcome = "unsent"

		c.cancel()
	}

	c.sessions.deliveries.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// ack confirms the messages; an unknown id (a repeat, another
// connection's) is ignored.
func (c *conn) ack(ctx context.Context, ids []string) {
	for _, id := range ids {
		c.mu.Lock()
		ack, ok := c.inflight[id]
		delete(c.inflight, id)
		c.mu.Unlock()

		if !ok {
			continue
		}

		if err := ack(); err != nil {
			c.sessions.Log().Ctx().Warn(ctx, "ack not recorded: the message is sent again", xlog.Err(err))

			continue
		}

		c.sessions.deliveries.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", "acked")))
	}
}

// keepalive pings until the connection ends; an unanswered ping ends it.
func (c *conn) keepalive(ctx context.Context) {
	tick := time.NewTicker(c.sessions.settings.Keepalive)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		pingCtx, cancel := context.WithTimeout(ctx, c.sessions.settings.Keepalive)
		err := c.ws.Ping(pingCtx)

		cancel()

		if err != nil {
			c.cancel()

			return
		}
	}
}

func (c *conn) subscription(sub domain.Subscription) *clientv1.Subscription {
	return &clientv1.Subscription{Id: string(sub.ID), Endpoint: c.sessions.endpoint(sub.ID), ApplicationServerKey: sub.Key}
}

func (c *conn) read(ctx context.Context) (*clientv1.ClientFrame, error) {
	typ, raw, err := c.ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	frame, decode := &clientv1.ClientFrame{}, protojson.UnmarshalOptions{DiscardUnknown: true}
	if typ != websocket.MessageText || decode.Unmarshal(raw, frame) != nil {
		_ = c.ws.Close(CodeBadFrame, "frames are protojson text messages")

		return nil, errBadFrame
	}

	return frame, nil
}

func (c *conn) send(ctx context.Context, frame *clientv1.ServerFrame) error {
	raw, err := protojson.Marshal(frame)
	if err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}

	c.write.Lock()
	defer c.write.Unlock()

	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	if err := c.ws.Write(writeCtx, websocket.MessageText, raw); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}
