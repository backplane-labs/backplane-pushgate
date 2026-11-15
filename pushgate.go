// Package pushgate is backplane-pushgate as a library: Main runs it. It is
// a Web Push service (RFC 8030) for desktop clients without an operating
// system push: senders post to a subscription's endpoint, a client keeps
// one WebSocket and receives its messages until it acknowledges them.
package pushgate

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/drivers/standard"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats"

	"github.com/backplane-labs/backplane-pushgate/internal/app"
	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	"github.com/backplane-labs/backplane-pushgate/internal/sender"
	"github.com/backplane-labs/backplane-pushgate/internal/session"
	"github.com/backplane-labs/backplane-pushgate/internal/store"
)

// Config is the whole configuration: file (BACKPLANE_CONFIG_FILE) < env
// PUSHGATE_* (BACKPLANE_* for the SDK block).
type Config struct {
	config.Backplane `json:"backplane"`

	// PublicURL is the service as senders and clients reach it.
	PublicURL string `json:"public_url" schemapb:"description=The service as clients reach it (https)"`
	// NATS holds subscriptions and mailboxes; JetStream is required.
	NATS nats.Config `json:"nats"`
	// MaxTTL is the longest a message is kept.
	MaxTTL time.Duration `json:"max_ttl" schemapb:"default=672h;gt=0;description=Longest TTL kept"`

	Mailbox       Mailbox       `json:"mailbox"`
	Subscriptions Subscriptions `json:"subscriptions"`
	Session       Session       `json:"session"`
}

// Mailbox of a channel.
type Mailbox struct {
	// MaxPerChannel undelivered messages are kept per channel.
	MaxPerChannel int `json:"max_per_channel" schemapb:"default=100;gte=1;description=Undelivered messages per channel"`
	// AckWait: a message not acknowledged in this time is sent again.
	AckWait time.Duration `json:"ack_wait" schemapb:"default=30s;gt=0;description=Time to acknowledge a message"`
	// Replicas of the stream and the bucket (3 in a NATS cluster).
	Replicas int `json:"replicas" schemapb:"default=1;gte=1;lte=5;description=Replicas of the stream and bucket"`
}

// Subscriptions of a channel.
type Subscriptions struct {
	// MaxPerChannel subscriptions a channel may hold.
	MaxPerChannel int `json:"max_per_channel" schemapb:"default=64;gte=1;description=Subscriptions per channel"`
	// IdleExpiry: a channel not connected for this long loses its
	// subscriptions.
	IdleExpiry time.Duration `json:"idle_expiry" schemapb:"default=2160h;gt=0;description=Idle time ending subscriptions"`
}

// Session of a client.
type Session struct {
	HelloTimeout time.Duration `json:"hello_timeout" schemapb:"default=10s;gt=0;description=Time to answer the challenge"`
	Keepalive    time.Duration `json:"keepalive"     schemapb:"default=30s;gt=0;description=Ping interval"`
}

// ErrPublicURL: public_url is not an absolute http(s) URL without a query.
var ErrPublicURL = errors.New("pushgate: public_url must be an absolute http or https URL without query or fragment")

// Validate what the schema cannot.
func (c *Config) Validate() error {
	if _, err := c.public(); err != nil {
		return err
	}

	if err := c.NATS.Validate(); err != nil {
		return fmt.Errorf("pushgate: nats: %w", err)
	}

	return nil
}

func (c *Config) public() (*url.URL, error) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: %q", ErrPublicURL, c.PublicURL)
	}

	return u, nil
}

// State is the service's tree.
type State struct {
	Store    deps.Dependency[*store.Store]
	Sender   *sender.Sender
	Sessions *session.Sessions
}

// Main runs pushgate until a signal stops it, exiting the process on error.
func Main() {
	if err := Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Run runs pushgate until ctx ends or a signal stops it.
func Run(ctx context.Context) error {
	svc, err := backplane.Open(ctx, NewState, standard.Drivers())
	if err != nil {
		return fmt.Errorf("pushgate: %w", err)
	}

	Declare(svc)

	if err := svc.Run(ctx); err != nil {
		return fmt.Errorf("pushgate: %w", err)
	}

	return nil
}

// NewState assembles the service under root.
func NewState(root backplane.Root[Config]) (*State, error) {
	cfg := root.Config()

	return New(root, &cfg)
}

// New assembles the service under parent with cfg.
func New(parent deps.Scope, cfg *Config) (*State, error) {
	public, err := cfg.public()
	if err != nil {
		return nil, err
	}

	dep := deps.NewDependency(parent, store.New(cfg.NATS, store.Settings{
		Replicas: cfg.Mailbox.Replicas, IdleExpiry: cfg.Subscriptions.IdleExpiry,
		MaxTTL: cfg.MaxTTL, AckWait: cfg.Mailbox.AckWait,
	}))
	lazy := resolved{dep: dep}
	cases := app.New(lazy, lazy, app.Limits{
		MaxTTL: cfg.MaxTTL, Mailbox: cfg.Mailbox.MaxPerChannel, Subscriptions: cfg.Subscriptions.MaxPerChannel,
	})

	st := &State{Store: dep, Sender: sender.New(parent, cases, public)}
	st.Sessions = session.New(parent, cases, lazy, st.Sender.Endpoint, session.Settings{
		HelloTimeout: cfg.Session.HelloTimeout, Keepalive: cfg.Session.Keepalive,
	})

	return st, nil
}

// Declare serves the endpoints and the clients' WebSocket on the public
// port.
func Declare(svc *backplane.Service[State]) {
	st := svc.State()
	svc.HTTP(sender.Path, st.Sender)
	svc.HTTP(session.Path, st.Sessions)
}

// resolved is the store once its dependency is ready: handlers run only
// then.
type resolved struct{ dep deps.Dependency[*store.Store] }

func (r resolved) Get(ctx context.Context, id domain.SubscriptionID) (domain.Subscription, error) {
	return r.dep.Get().Get(ctx, id)
}

func (r resolved) Create(ctx context.Context, sub domain.Subscription, limit int) error {
	return r.dep.Get().Create(ctx, sub, limit)
}

func (r resolved) Delete(ctx context.Context, channel domain.Channel, id domain.SubscriptionID) error {
	return r.dep.Get().Delete(ctx, channel, id)
}

func (r resolved) Touch(ctx context.Context, channel domain.Channel) ([]domain.Subscription, error) {
	return r.dep.Get().Touch(ctx, channel)
}

func (r resolved) Put(ctx context.Context, channel domain.Channel, msg domain.Message, limit int) (string, error) {
	return r.dep.Get().Put(ctx, channel, msg, limit)
}

func (r resolved) Online(ctx context.Context, channel domain.Channel) (bool, error) {
	return r.dep.Get().Online(ctx, channel)
}

func (r resolved) Purge(ctx context.Context, channel domain.Channel, sub domain.SubscriptionID) error {
	return r.dep.Get().Purge(ctx, channel, sub)
}

func (r resolved) Open(
	ctx context.Context, channel domain.Channel, deliver func(domain.Delivery),
) (session.Stream, error) {
	in, err := r.dep.Get().Open(ctx, channel, deliver)
	if err != nil {
		return session.Stream{}, err
	}

	return session.Stream{Replaced: in.Replaced(), Close: in.Close}, nil
}
