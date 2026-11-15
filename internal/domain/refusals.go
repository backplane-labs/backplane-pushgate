package domain

import "errors"

// Refusals of the scenarios: expected outcomes a sender or a device gets.
var (
	// ErrGone: no such subscription: never made, unsubscribed or expired.
	ErrGone = errors.New("pushgate: subscription is gone")
	// ErrWrongKey: the sender's key is not the subscription's.
	ErrWrongKey = errors.New("pushgate: sender key is not the subscription's")
	// ErrLimit: the channel has subscriptions.max_per_channel subscriptions.
	ErrLimit = errors.New("pushgate: subscription limit of the channel reached")
	// ErrNotFound: no such subscription of the channel.
	ErrNotFound = errors.New("pushgate: no such subscription of the channel")
)
