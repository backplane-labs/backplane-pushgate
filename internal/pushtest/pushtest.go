// Package pushtest is a desktop client for tests: it connects, proves its
// key, subscribes, receives and acknowledges, and decrypts RFC 8291
// messages.
package pushtest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
	clientv1 "github.com/backplane-labs/backplane-pushgate/proto/pushgate/client/v1"
)

// wait bounds every expectation of the client.
const wait = 10 * time.Second

// frameBuffer is how many unread frames the client holds.
const frameBuffer = 64

// Client is one connection of a device key.
type Client struct {
	tb      testing.TB
	ws      *websocket.Conn
	welcome *clientv1.Welcome
	frames  chan *clientv1.ServerFrame
	closed  chan websocket.StatusCode
}

// Dial connects to the WebSocket at url as key and completes the hello.
func Dial(tb testing.TB, url string, key ed25519.PrivateKey) *Client {
	tb.Helper()

	c, err := Connect(tb, url)
	if err != nil {
		tb.Fatal(err)
	}

	challenge := c.Next(tb).GetChallenge()
	if challenge == nil {
		tb.Fatal("the first frame is not a challenge")
	}

	c.Send(tb, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Hello{Hello: &clientv1.Hello{
		PublicKey: key[ed25519.SeedSize:], Signature: ed25519.Sign(key, domain.HelloMessage(challenge.GetNonce())),
	}}})

	c.welcome = c.Next(tb).GetWelcome()
	if c.welcome == nil {
		tb.Fatal("the hello was not welcomed")
	}

	return c
}

// Connect opens the WebSocket without a hello.
func Connect(tb testing.TB, url string) (*Client, error) {
	tb.Helper()

	ws, res, err := websocket.Dial(context.Background(), url, nil)
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}

	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	c := &Client{
		tb: tb, ws: ws, frames: make(chan *clientv1.ServerFrame, frameBuffer), closed: make(chan websocket.StatusCode, 1),
	}
	tb.Cleanup(func() { _ = ws.CloseNow() })

	go c.receive()

	return c, nil
}

func (c *Client) receive() {
	for {
		_, raw, err := c.ws.Read(context.Background())
		if err != nil {
			c.closed <- websocket.CloseStatus(err)

			close(c.frames)

			return
		}

		frame := &clientv1.ServerFrame{}
		if err := protojson.Unmarshal(raw, frame); err != nil {
			c.closed <- -1

			close(c.frames)

			return
		}

		c.frames <- frame
	}
}

// Welcome is the server's welcome.
func (c *Client) Welcome() *clientv1.Welcome { return c.welcome }

// Send sends a frame.
func (c *Client) Send(tb testing.TB, frame *clientv1.ClientFrame) {
	tb.Helper()

	raw, err := protojson.Marshal(frame)
	if err != nil {
		tb.Fatal(err)
	}

	if err := c.ws.Write(context.Background(), websocket.MessageText, raw); err != nil {
		tb.Fatal(err)
	}
}

// SendRaw sends a text message as it is.
func (c *Client) SendRaw(tb testing.TB, raw string) {
	tb.Helper()

	if err := c.ws.Write(context.Background(), websocket.MessageText, []byte(raw)); err != nil {
		tb.Fatal(err)
	}
}

// Next is the next frame.
func (c *Client) Next(tb testing.TB) *clientv1.ServerFrame {
	tb.Helper()

	select {
	case f, ok := <-c.frames:
		if !ok {
			tb.Fatal("the connection closed")
		}

		return f
	case <-time.After(wait):
		tb.Fatal("no frame")
	}

	return nil
}

// Notification is the next notification, skipping no other frame.
func (c *Client) Notification(tb testing.TB) *clientv1.Notification {
	tb.Helper()

	n := c.Next(tb).GetNotification()
	if n == nil {
		tb.Fatal("the next frame is not a notification")
	}

	return n
}

// Quiet fails when a frame arrives within d.
func (c *Client) Quiet(tb testing.TB, d time.Duration) {
	tb.Helper()

	select {
	case f, ok := <-c.frames:
		if ok {
			tb.Fatalf("unexpected frame %v", f)
		}
	case <-time.After(d):
	}
}

// Subscribe subscribes key and waits for the answer: the subscription, or
// the refusal.
func (c *Client) Subscribe(tb testing.TB, key string) (*clientv1.Subscription, *clientv1.Refused) {
	tb.Helper()

	c.Send(tb, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Subscribe{Subscribe: &clientv1.Subscribe{
		RequestId: "sub-" + key, ApplicationServerKey: key,
	}}})

	f := c.Next(tb)
	if r := f.GetRefused(); r != nil {
		return nil, r
	}

	if f.GetSubscribed().GetRequestId() != "sub-"+key {
		tb.Fatalf("subscribe answered %v", f)
	}

	return f.GetSubscribed().GetSubscription(), nil
}

// Unsubscribe ends a subscription: nil when confirmed, else the refusal.
func (c *Client) Unsubscribe(tb testing.TB, id string) *clientv1.Refused {
	tb.Helper()

	c.Send(tb, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Unsubscribe{Unsubscribe: &clientv1.Unsubscribe{
		RequestId: "unsub-" + id, Subscription: id,
	}}})

	f := c.Next(tb)
	if r := f.GetRefused(); r != nil {
		return r
	}

	if f.GetUnsubscribed().GetSubscription() != id {
		tb.Fatalf("unsubscribe answered %v", f)
	}

	return nil
}

// Ack acknowledges notifications.
func (c *Client) Ack(tb testing.TB, ids ...string) {
	tb.Helper()

	c.Send(tb, &clientv1.ClientFrame{Frame: &clientv1.ClientFrame_Ack{Ack: &clientv1.Ack{Ids: ids}}})
}

// Closed waits for the server to close the connection: its close code.
func (c *Client) Closed(tb testing.TB) websocket.StatusCode {
	tb.Helper()

	for {
		select {
		case code := <-c.closed:
			return code
		case _, ok := <-c.frames:
			if !ok {
				return <-c.closed
			}
		case <-time.After(wait):
			tb.Fatal("the connection stayed open")
		}
	}
}

// Close closes the connection from the client.
func (c *Client) Close() { _ = c.ws.Close(websocket.StatusNormalClosure, "") }

// DeviceKey is a fresh Ed25519 device key.
func DeviceKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	return key
}

// Keys are a subscription's content keys (RFC 8291): the P-256 key pair
// and the auth secret.
type Keys struct {
	private *ecdh.PrivateKey
	auth    []byte
}

// NewKeys are fresh content keys.
func NewKeys(tb testing.TB) Keys {
	tb.Helper()

	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	auth := make([]byte, authSize)
	_, _ = rand.Read(auth)

	return Keys{private: private, auth: auth}
}

// P256dh is the public key, base64url, as a subscription carries it.
func (k Keys) P256dh() string {
	return base64.RawURLEncoding.EncodeToString(k.private.PublicKey().Bytes())
}

// Auth is the auth secret, base64url.
func (k Keys) Auth() string { return base64.RawURLEncoding.EncodeToString(k.auth) }

// Errors of Decrypt.
var errCiphertext = errors.New("pushtest: not an aes128gcm message for these keys")

// Sizes of RFC 8188 / RFC 8291.
const (
	authSize   = 16
	saltSize   = 16
	header     = saltSize + 4 + 1 // salt, record size, key id length
	ikmSize    = 32
	cekSize    = 16
	nonceSize  = 12
	lastRecord = 2 // the last record's padding delimiter
)

// Decrypt opens an aes128gcm message (RFC 8188, keys per RFC 8291) of a
// single record.
func (k Keys) Decrypt(data []byte) ([]byte, error) {
	if len(data) < header {
		return nil, errCiphertext
	}

	salt, idLen := data[:saltSize], int(data[header-1])
	if len(data) < header+idLen {
		return nil, errCiphertext
	}

	senderPublic, err := ecdh.P256().NewPublicKey(data[header : header+idLen])
	if err != nil {
		return nil, errCiphertext
	}

	shared, err := k.private.ECDH(senderPublic)
	if err != nil {
		return nil, errCiphertext
	}

	info := append([]byte("WebPush: info\x00"), k.private.PublicKey().Bytes()...)
	info = append(info, senderPublic.Bytes()...)

	ikm, err := hkdf.Key(sha256.New, shared, k.auth, string(info), ikmSize)
	if err != nil {
		return nil, fmt.Errorf("pushtest: ikm: %w", err)
	}

	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", cekSize)
	if err != nil {
		return nil, fmt.Errorf("pushtest: cek: %w", err)
	}

	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", nonceSize)
	if err != nil {
		return nil, fmt.Errorf("pushtest: nonce: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("pushtest: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pushtest: gcm: %w", err)
	}

	plain, err := gcm.Open(nil, nonce, data[header+idLen:], nil)
	if err != nil {
		return nil, errCiphertext
	}

	// The last record ends with the delimiter 2 and zero padding.
	for len(plain) > 0 && plain[len(plain)-1] == 0 {
		plain = plain[:len(plain)-1]
	}

	if len(plain) == 0 || plain[len(plain)-1] != lastRecord {
		return nil, errCiphertext
	}

	return plain[:len(plain)-1], nil
}
