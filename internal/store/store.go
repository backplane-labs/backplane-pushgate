// Package store keeps pushgate's state in NATS JetStream: subscriptions in
// a key-value bucket, undelivered messages in a work-queue stream, a
// consumer per connected channel, and a subject that tells a channel's
// older connection it was replaced.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/nats"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
)

// Names in JetStream.
const (
	Bucket = "pushgate_subscriptions"
	Stream = "PUSHGATE_MAILBOX"

	mailPrefix    = "pushgate.mail."
	sessionPrefix = "pushgate.session."
	subKey        = "sub."
	chanKey       = "chan."

	headerTopic   = "Pushgate-Topic"
	headerUrgency = "Pushgate-Urgency"

	// minTTL is the shortest message TTL NATS keeps: a TTL 0 message for
	// a connected channel lives this long.
	minTTL = time.Second
	// consumerIdle is how long a channel's consumer outlives its
	// connection.
	consumerIdle = time.Minute
	// maxInFlight bounds the messages sent to a connection and not yet
	// acknowledged.
	maxInFlight = 64
	// casRetries bounds the retries of a channel record's update.
	casRetries = 16
)

// errContended: a channel record kept changing under its update.
var errContended = errors.New("store: channel record contended")

// Settings shape the bucket and the stream.
type Settings struct {
	// Replicas of the bucket and the stream.
	Replicas int
	// IdleExpiry: a record not written for this long expires.
	IdleExpiry time.Duration
	// MaxTTL is the longest a message is kept.
	MaxTTL time.Duration
	// AckWait: a message sent and not acknowledged in this time is sent
	// again.
	AckWait time.Duration
}

// Store is the JetStream state.
type Store struct {
	conn     *natsgo.Conn
	js       jetstream.JetStream
	kv       jetstream.KeyValue
	stream   jetstream.Stream
	settings Settings
}

// New is the store's provider over the NATS of cfg: it connects, then
// creates or updates the bucket and the stream.
func New(cfg nats.Config, s Settings) deps.Provider[*Store] {
	return provider{conn: nats.New(cfg, nats.WithJetStream()), cfg: cfg, settings: s}
}

type provider struct {
	conn     deps.Provider[*natsgo.Conn]
	cfg      nats.Config
	settings Settings
}

func (provider) Name() string { return "nats" }

func (p provider) Provide(ctx context.Context, scope deps.Scope) (*Store, error) {
	conn, err := p.conn.Provide(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	st, err := Open(ctx, conn, p.cfg, p.settings)
	if err != nil {
		conn.Close()

		return nil, err
	}

	return st, nil
}

func (p provider) Probe(ctx context.Context, st *Store) error {
	if err := p.conn.Probe(ctx, st.conn); err != nil {
		return fmt.Errorf("store: %w", err)
	}

	return nil
}

func (p provider) Close(ctx context.Context, st *Store) error {
	if err := p.conn.Close(ctx, st.conn); err != nil {
		return fmt.Errorf("store: %w", err)
	}

	return nil
}

// Open creates or updates the bucket and the stream on conn.
func Open(ctx context.Context, conn *natsgo.Conn, cfg nats.Config, s Settings) (*Store, error) {
	jetStream, err := cfg.JetStream(conn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	kv, err := jetStream.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "pushgate subscriptions: sub.<id>, chan.<channel>",
		TTL: s.IdleExpiry, History: 1, Replicas: s.Replicas, Storage: jetstream.FileStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("store: bucket: %w", err)
	}

	stream, err := jetStream.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: Stream, Description: "pushgate undelivered messages: pushgate.mail.<channel>.<subscription>.<slot>",
		Subjects: []string{mailPrefix + ">"}, Retention: jetstream.WorkQueuePolicy, MaxMsgsPerSubject: 1,
		Discard: jetstream.DiscardOld, MaxAge: s.MaxTTL, AllowMsgTTL: true, Replicas: s.Replicas,
		Storage: jetstream.FileStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("store: stream: %w", err)
	}

	return &Store{conn: conn, js: jetStream, kv: kv, stream: stream, settings: s}, nil
}

// channelRecord lists a channel's subscriptions.
type channelRecord struct {
	Subscriptions []domain.SubscriptionID `json:"subscriptions"`
}

// Get is a subscription by id; domain.ErrGone when there is none.
func (s *Store) Get(ctx context.Context, id domain.SubscriptionID) (domain.Subscription, error) {
	entry, err := s.kv.Get(ctx, subKey+string(id))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return domain.Subscription{}, domain.ErrGone
	}

	if err != nil {
		return domain.Subscription{}, fmt.Errorf("store: get subscription: %w", err)
	}

	var sub domain.Subscription
	if err := json.Unmarshal(entry.Value(), &sub); err != nil {
		return domain.Subscription{}, fmt.Errorf("store: decode subscription: %w", err)
	}

	return sub, nil
}

// Create stores sub and lists it on its channel unless the channel has
// limit subscriptions (domain.ErrLimit).
func (s *Store) Create(ctx context.Context, sub domain.Subscription, limit int) error {
	raw, err := json.Marshal(sub)
	if err != nil {
		return fmt.Errorf("store: encode subscription: %w", err)
	}

	if _, err := s.kv.Put(ctx, subKey+string(sub.ID), raw); err != nil {
		return fmt.Errorf("store: put subscription: %w", err)
	}

	err = s.updateChannel(ctx, sub.Channel, func(r *channelRecord) error {
		if len(r.Subscriptions) >= limit {
			return domain.ErrLimit
		}

		r.Subscriptions = append(r.Subscriptions, sub.ID)

		return nil
	})
	if err != nil {
		_ = s.kv.Delete(context.WithoutCancel(ctx), subKey+string(sub.ID))

		return err
	}

	return nil
}

// Delete removes the channel's subscription id; domain.ErrNotFound when
// the channel has none such.
func (s *Store) Delete(ctx context.Context, channel domain.Channel, id domain.SubscriptionID) error {
	sub, err := s.Get(ctx, id)
	if errors.Is(err, domain.ErrGone) || (err == nil && sub.Channel != channel) {
		return domain.ErrNotFound
	}

	if err != nil {
		return err
	}

	if err := s.kv.Delete(ctx, subKey+string(id)); err != nil {
		return fmt.Errorf("store: delete subscription: %w", err)
	}

	return s.updateChannel(ctx, channel, func(r *channelRecord) error {
		r.Subscriptions = slices.DeleteFunc(r.Subscriptions, func(have domain.SubscriptionID) bool { return have == id })

		return nil
	})
}

// Touch rewrites the channel's records, renewing their expiry, and lists
// its subscriptions.
func (s *Store) Touch(ctx context.Context, channel domain.Channel) ([]domain.Subscription, error) {
	var subs []domain.Subscription

	err := s.updateChannel(ctx, channel, func(r *channelRecord) error {
		subs = subs[:0]
		kept := r.Subscriptions[:0]

		for _, id := range r.Subscriptions {
			sub, err := s.Get(ctx, id)
			if errors.Is(err, domain.ErrGone) {
				continue
			}

			if err != nil {
				return err
			}

			raw, err := json.Marshal(sub)
			if err != nil {
				return fmt.Errorf("store: encode subscription: %w", err)
			}

			if _, err := s.kv.Put(ctx, subKey+string(id), raw); err != nil {
				return fmt.Errorf("store: renew subscription: %w", err)
			}

			subs, kept = append(subs, sub), append(kept, id)
		}

		r.Subscriptions = kept

		return nil
	})

	return subs, err
}

// updateChannel applies change to the channel's record, retrying while
// another writer changes it first; the record is written even unchanged,
// which renews its expiry.
func (s *Store) updateChannel(ctx context.Context, channel domain.Channel, change func(*channelRecord) error) error {
	key := chanKey + string(channel)

	for range casRetries {
		var (
			record   channelRecord
			revision uint64
		)

		entry, err := s.kv.Get(ctx, key)

		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound):
		case err != nil:
			return fmt.Errorf("store: get channel: %w", err)
		default:
			revision = entry.Revision()
			if err := json.Unmarshal(entry.Value(), &record); err != nil {
				return fmt.Errorf("store: decode channel: %w", err)
			}
		}

		if err := change(&record); err != nil {
			return err
		}

		raw, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("store: encode channel: %w", err)
		}

		if revision == 0 {
			_, err = s.kv.Create(ctx, key, raw)
		} else {
			_, err = s.kv.Update(ctx, key, raw, revision)
		}

		if errors.Is(err, jetstream.ErrKeyExists) || isWrongSequence(err) {
			continue
		}

		if err != nil {
			return fmt.Errorf("store: write channel: %w", err)
		}

		return nil
	}

	return errContended
}

// isWrongSequence: an Update lost the race to another writer.
func isWrongSequence(err error) bool {
	var apiErr *jetstream.APIError

	return errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence
}

// mailSubject is a message's subject; channelMail all of a channel's.
func mailSubject(channel domain.Channel, sub domain.SubscriptionID, slot string) string {
	return mailPrefix + string(channel) + "." + string(sub) + "." + slot
}

func channelMail(channel domain.Channel) string { return mailPrefix + string(channel) + ".>" }

func subscriptionMail(channel domain.Channel, sub domain.SubscriptionID) string {
	return mailPrefix + string(channel) + "." + string(sub) + ".>"
}

// consumerName is the durable consumer of a channel.
func consumerName(channel domain.Channel) string { return "ch-" + string(channel) }

// Put keeps msg for channel, dropping the channel's oldest message when it
// holds limit; the message's id (its stream sequence).
func (s *Store) Put(ctx context.Context, channel domain.Channel, msg domain.Message, limit int) (string, error) {
	if err := s.makeRoom(ctx, channel, limit); err != nil {
		return "", err
	}

	ttl := max(msg.TTL, minTTL)
	out := &natsgo.Msg{
		Subject: mailSubject(channel, msg.Subscription, msg.Slot()), Data: msg.Data,
		Header: natsgo.Header{headerUrgency: {string(msg.Urgency)}},
	}

	if msg.Topic != "" {
		out.Header.Set(headerTopic, msg.Topic)
	}

	ack, err := s.js.PublishMsg(ctx, out, jetstream.WithMsgTTL(ttl), jetstream.WithExpectStream(Stream))
	if err != nil {
		return "", fmt.Errorf("store: publish: %w", err)
	}

	return strconv.FormatUint(ack.Sequence, 10), nil
}

// makeRoom deletes the channel's oldest messages until it holds fewer
// than limit.
func (s *Store) makeRoom(ctx context.Context, channel domain.Channel, limit int) error {
	info, err := s.stream.Info(ctx, jetstream.WithSubjectFilter(channelMail(channel)))
	if err != nil {
		return fmt.Errorf("store: count mailbox: %w", err)
	}

	// One message per subject: the subjects are the messages.
	for held := len(info.State.Subjects); held >= limit; held-- {
		oldest, err := s.stream.GetMsg(ctx, 1, jetstream.WithGetMsgSubject(channelMail(channel)))
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("store: oldest message: %w", err)
		}

		if err := s.stream.DeleteMsg(ctx, oldest.Sequence); err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("store: drop oldest message: %w", err)
		}
	}

	return nil
}

// Online reports whether a connection consumes the channel's messages.
func (s *Store) Online(ctx context.Context, channel domain.Channel) (bool, error) {
	consumer, err := s.stream.Consumer(ctx, consumerName(channel))
	if errors.Is(err, jetstream.ErrConsumerNotFound) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("store: consumer: %w", err)
	}

	info := consumer.CachedInfo()

	return info != nil && info.NumWaiting > 0, nil
}

// Purge drops the subscription's undelivered messages.
func (s *Store) Purge(ctx context.Context, channel domain.Channel, sub domain.SubscriptionID) error {
	if err := s.stream.Purge(ctx, jetstream.WithPurgeSubject(subscriptionMail(channel, sub))); err != nil {
		return fmt.Errorf("store: purge: %w", err)
	}

	return nil
}

// Inbox is a connection's consumption of its channel's messages.
type Inbox struct {
	consume  jetstream.ConsumeContext
	sub      *natsgo.Subscription
	replaced chan struct{}
	once     sync.Once
}

// Open consumes the channel's messages for one connection, calling deliver
// with each (and again with one not acknowledged in time). The channel's
// older connection, on any replica, is told it was replaced.
func (s *Store) Open(ctx context.Context, channel domain.Channel, deliver func(domain.Delivery)) (*Inbox, error) {
	in := &Inbox{replaced: make(chan struct{})}
	token := domain.Nonce()

	sub, err := s.conn.Subscribe(sessionPrefix+string(channel), func(m *natsgo.Msg) {
		if !bytes.Equal(m.Data, token) {
			in.once.Do(func() { close(in.replaced) })
		}
	})
	if err != nil {
		return nil, fmt.Errorf("store: session subject: %w", err)
	}

	in.sub = sub

	if err := s.conn.Publish(sessionPrefix+string(channel), token); err != nil {
		in.Close()

		return nil, fmt.Errorf("store: announce session: %w", err)
	}

	consumer, err := s.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Name: consumerName(channel), Durable: consumerName(channel), FilterSubject: channelMail(channel),
		AckPolicy: jetstream.AckExplicitPolicy, AckWait: s.settings.AckWait, MaxAckPending: maxInFlight,
		InactiveThreshold: consumerIdle, DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		in.Close()

		return nil, fmt.Errorf("store: consumer: %w", err)
	}

	in.consume, err = consumer.Consume(func(m jetstream.Msg) { deliver(delivery(m)) })
	if err != nil {
		in.Close()

		return nil, fmt.Errorf("store: consume: %w", err)
	}

	return in, nil
}

// Replaced is closed when a newer connection of the channel opened.
func (in *Inbox) Replaced() <-chan struct{} { return in.replaced }

// Close stops the consumption.
func (in *Inbox) Close() {
	if in.consume != nil {
		in.consume.Stop()
	}

	if in.sub != nil {
		_ = in.sub.Unsubscribe()
	}
}

// delivery reads a message of pushgate.mail.<channel>.<subscription>.<slot>;
// its id is its stream sequence, its Ack removes it.
func delivery(m jetstream.Msg) domain.Delivery {
	d := domain.Delivery{
		Data: m.Data(), Topic: m.Headers().Get(headerTopic), Urgency: domain.Urgency(m.Headers().Get(headerUrgency)),
		Ack: func() error {
			if err := m.Ack(); err != nil {
				return fmt.Errorf("store: ack: %w", err)
			}

			return nil
		},
	}

	if tokens := strings.Split(m.Subject(), "."); len(tokens) == subjectTokens {
		d.Subscription = domain.SubscriptionID(tokens[3])
	}

	if meta, err := m.Metadata(); err == nil {
		d.ID, d.SentAt = strconv.FormatUint(meta.Sequence.Stream, 10), meta.Timestamp
	}

	return d
}

// subjectTokens is the number of tokens of a mail subject.
const subjectTokens = 5
