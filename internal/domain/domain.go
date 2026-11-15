// Package domain holds pushgate's rules without infrastructure: a device's
// channel and its proof, subscriptions, and what a sender may post.
package domain

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Refusals of a device or a sender: expected outcomes of the contract.
var (
	// ErrHello: the hello's key or signature does not prove the challenge.
	ErrHello = errors.New("pushgate: hello does not prove the challenge")
	// ErrKey: an application server key is not a P-256 public key.
	ErrKey = errors.New("pushgate: application server key is not a base64url uncompressed P-256 point")
	// ErrSubscriptionID: not a subscription id pushgate makes.
	ErrSubscriptionID = errors.New("pushgate: malformed subscription id")
	// ErrTTL: the TTL header is missing or not a non-negative integer.
	ErrTTL = errors.New("pushgate: TTL is required: a non-negative number of seconds")
	// ErrTopic: the Topic header is not up to 32 base64url characters.
	ErrTopic = errors.New("pushgate: topic is up to 32 characters of A-Z a-z 0-9 - _")
	// ErrUrgency: the Urgency header is none of the four.
	ErrUrgency = errors.New("pushgate: urgency is very-low, low, normal or high")
	// ErrEncoding: the body is not aes128gcm (RFC 8291).
	ErrEncoding = errors.New("pushgate: Content-Encoding must be aes128gcm")
	// ErrTooLarge: the body exceeds MaxPayload.
	ErrTooLarge = errors.New("pushgate: payload exceeds 4096 bytes")
)

// MaxPayload is the largest encrypted body a sender may post (RFC 8030
// push services accept at least 4096 bytes).
const MaxPayload = 4096

// HelloContext is the domain separation of the signed challenge.
const HelloContext = "backplane-pushgate/v1 hello\x00"

// NonceSize is the size of a challenge.
const NonceSize = 32

// Channel is a device: the base64url SHA-256 of its Ed25519 public key.
type Channel string

// ChannelOf is the channel of an Ed25519 public key.
func ChannelOf(key ed25519.PublicKey) Channel {
	sum := sha256.Sum256(key)

	return Channel(base64.RawURLEncoding.EncodeToString(sum[:]))
}

// HelloMessage is what a device signs to answer nonce.
func HelloMessage(nonce []byte) []byte { return append([]byte(HelloContext), nonce...) }

// VerifyHello is the channel proven by a signature of nonce with key.
func VerifyHello(key, signature, nonce []byte) (Channel, error) {
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || len(nonce) != NonceSize ||
		!ed25519.Verify(key, HelloMessage(nonce), signature) {
		return "", ErrHello
	}

	return ChannelOf(key), nil
}

// Nonce is a new challenge.
func Nonce() []byte { return random(NonceSize) }

// random is n bytes from crypto/rand, which never fails (Go 1.24).
func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return b
}

// SubscriptionID names a subscription in its endpoint: 128 random bits,
// base64url, so nothing in it relates two subscriptions of one device.
type SubscriptionID string

// subscriptionIDSize is the size of a subscription id's randomness.
const subscriptionIDSize = 16

// NewSubscriptionID is a fresh id.
func NewSubscriptionID() SubscriptionID {
	return SubscriptionID(base64.RawURLEncoding.EncodeToString(random(subscriptionIDSize)))
}

// ParseSubscriptionID checks s is an id pushgate makes.
func ParseSubscriptionID(s string) (SubscriptionID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != subscriptionIDSize {
		return "", ErrSubscriptionID
	}

	return SubscriptionID(s), nil
}

// Subscription is one sender key's address of a channel.
type Subscription struct {
	ID      SubscriptionID `json:"id"`
	Channel Channel        `json:"channel"`
	// Key is the sender's VAPID public key, base64url of the uncompressed
	// P-256 point.
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

// ParseKey checks an application server key: base64url (padding
// tolerated) of an uncompressed P-256 point; the canonical form is
// unpadded.
func ParseKey(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(trimPadding(s))
	if err != nil {
		return "", ErrKey
	}

	if _, err := ecdh.P256().NewPublicKey(raw); err != nil || len(raw) != uncompressedPoint {
		return "", ErrKey
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// uncompressedPoint is the size of an uncompressed P-256 point.
const uncompressedPoint = 65

func trimPadding(s string) string { return strings.TrimRight(s, "=") }

// Urgency of a message (RFC 8030 5.3).
type Urgency string

// The urgencies.
const (
	VeryLow Urgency = "very-low"
	Low     Urgency = "low"
	Normal  Urgency = "normal"
	High    Urgency = "high"
)

// ParseUrgency reads the Urgency header; empty is normal.
func ParseUrgency(s string) (Urgency, error) {
	switch u := Urgency(s); u {
	case "":
		return Normal, nil
	case VeryLow, Low, Normal, High:
		return u, nil
	default:
		return "", ErrUrgency
	}
}

var topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ParseTopic reads the Topic header; empty is none.
func ParseTopic(s string) (string, error) {
	if s != "" && !topicPattern.MatchString(s) {
		return "", ErrTopic
	}

	return s, nil
}

// ParseTTL reads the TTL header and caps it at limit.
func ParseTTL(s string, limit time.Duration) (time.Duration, error) {
	seconds, err := strconv.ParseInt(s, 10, 64)
	if err != nil || seconds < 0 {
		return 0, ErrTTL
	}

	if seconds > int64(limit/time.Second) {
		return limit, nil
	}

	return time.Duration(seconds) * time.Second, nil
}

// CheckBody checks the body's encoding and size.
func CheckBody(encoding string, size int) error {
	switch {
	case size > MaxPayload:
		return ErrTooLarge
	case size > 0 && encoding != "aes128gcm":
		return ErrEncoding
	}

	return nil
}

// Message is a sender's message as pushgate keeps it.
type Message struct {
	Subscription SubscriptionID
	Data         []byte
	TTL          time.Duration
	Topic        string
	Urgency      Urgency
}

// Slot is the message's place in its subscription's mailbox: its topic,
// so a newer one replaces it, or a fresh one.
func (m Message) Slot() string {
	if m.Topic != "" {
		return "t" + m.Topic
	}

	return "m" + base64.RawURLEncoding.EncodeToString(random(subscriptionIDSize))
}

// Delivery is a message sent to a connection.
type Delivery struct {
	// ID names the message; the same on a repeated delivery.
	ID           string
	Subscription SubscriptionID
	Data         []byte
	Topic        string
	Urgency      Urgency
	SentAt       time.Time
	// Ack confirms it: it is not sent again.
	Ack func() error
}
