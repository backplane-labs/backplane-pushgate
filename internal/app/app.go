// Package app holds pushgate's scenarios: a sender's push, and a device's
// hello, subscribe and unsubscribe.
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
)

// Subscriptions keeps subscriptions.
type Subscriptions interface {
	// Get is a subscription; domain.ErrGone when there is none.
	Get(ctx context.Context, id domain.SubscriptionID) (domain.Subscription, error)
	// Create stores one unless its channel has limit (domain.ErrLimit).
	Create(ctx context.Context, sub domain.Subscription, limit int) error
	// Delete removes the channel's subscription (domain.ErrNotFound).
	Delete(ctx context.Context, channel domain.Channel, id domain.SubscriptionID) error
	// Touch renews a channel's records and lists its subscriptions.
	Touch(ctx context.Context, channel domain.Channel) ([]domain.Subscription, error)
}

// Mailbox keeps messages until a connection acknowledges them.
type Mailbox interface {
	// Put keeps a message for channel within limit; its id.
	Put(ctx context.Context, channel domain.Channel, msg domain.Message, limit int) (string, error)
	// Online reports whether a connection consumes the channel.
	Online(ctx context.Context, channel domain.Channel) (bool, error)
	// Purge drops a subscription's messages.
	Purge(ctx context.Context, channel domain.Channel, sub domain.SubscriptionID) error
}

// Limits of a channel.
type Limits struct {
	// MaxTTL is the longest a message is kept.
	MaxTTL time.Duration
	// Mailbox is the number of undelivered messages kept per channel.
	Mailbox int
	// Subscriptions is the number of subscriptions per channel.
	Subscriptions int
}

// Service runs the scenarios.
type Service struct {
	subs   Subscriptions
	mail   Mailbox
	limits Limits
	now    func() time.Time
}

// New is the service over its stores.
func New(subs Subscriptions, mail Mailbox, limits Limits) Service {
	return Service{subs: subs, mail: mail, limits: limits, now: time.Now}
}

// MaxTTL is the longest a message is kept.
func (s Service) MaxTTL() time.Duration { return s.limits.MaxTTL }

// Push keeps a sender's message for its subscription, the sender
// identified by senderKey; the message's id, empty when a TTL 0 message
// found no connection and was dropped.
func (s Service) Push(ctx context.Context, msg domain.Message, senderKey string) (string, error) {
	sub, err := s.subs.Get(ctx, msg.Subscription)
	if err != nil {
		return "", fmt.Errorf("push: %w", err)
	}

	if sub.Key != senderKey {
		return "", domain.ErrWrongKey
	}

	if msg.TTL == 0 {
		online, err := s.mail.Online(ctx, sub.Channel)
		if err != nil {
			return "", fmt.Errorf("push: %w", err)
		}

		if !online {
			return "", nil
		}
	}

	id, err := s.mail.Put(ctx, sub.Channel, msg, s.limits.Mailbox)
	if err != nil {
		return "", fmt.Errorf("push: %w", err)
	}

	return id, nil
}

// Hello opens a channel's session: its subscriptions, renewed.
func (s Service) Hello(ctx context.Context, channel domain.Channel) ([]domain.Subscription, error) {
	subs, err := s.subs.Touch(ctx, channel)
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}

	return subs, nil
}

// Subscribe makes a channel's subscription for a sender key.
func (s Service) Subscribe(ctx context.Context, channel domain.Channel, key string) (domain.Subscription, error) {
	canonical, err := domain.ParseKey(key)
	if err != nil {
		return domain.Subscription{}, err
	}

	sub := domain.Subscription{ID: domain.NewSubscriptionID(), Channel: channel, Key: canonical, CreatedAt: s.now().UTC()}
	if err := s.subs.Create(ctx, sub, s.limits.Subscriptions); err != nil {
		return domain.Subscription{}, fmt.Errorf("subscribe: %w", err)
	}

	return sub, nil
}

// Unsubscribe ends a channel's subscription and drops its messages.
func (s Service) Unsubscribe(ctx context.Context, channel domain.Channel, id domain.SubscriptionID) error {
	if err := s.subs.Delete(ctx, channel, id); err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}

	if err := s.mail.Purge(ctx, channel, id); err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}

	return nil
}
