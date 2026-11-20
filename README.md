# backplane-pushgate

A Web Push service ([RFC 8030](https://www.rfc-editor.org/rfc/rfc8030)) for
**desktop clients that have no usable operating-system push**: Electron apps on
Windows, macOS and Linux. A desktop client keeps one WebSocket connection to
pushgate; senders post to it exactly as to any Web Push service.

pushgate is a backplane service (SDK, configuration, telemetry, lifecycle); it
stores nothing in PostgreSQL: subscriptions and undelivered messages live in
NATS JetStream.

## Scope and responsibility

pushgate is for desktop clients only. Mobile apps use their platform's push
(FCM, APNs, RuStore) and browsers use their vendor's Web Push service; they do
not connect to pushgate.

| Component | Is responsible for | Is not responsible for |
| --- | --- | --- |
| **pushgate** | Device connections and their authentication; subscriptions (one per sender key); accepting messages on the RFC 8030 endpoint and checking the sender's VAPID key; keeping each message until the device acknowledges it or its TTL ends; replacing an undelivered message with the same `Topic`; routing a message to the replica that holds the device's connection. | Reading or encrypting payloads (it cannot: they are encrypted to the device); deciding who may notify whom; storing who a device belongs to; showing anything to a user; waking an app that is not running. |
| **Sender** (backplane-courier's `webpush` channel, unchanged) | Encrypting the payload to the subscription ([RFC 8291](https://www.rfc-editor.org/rfc/rfc8291)), signing with its VAPID key ([RFC 8292](https://www.rfc-editor.org/rfc/rfc8292)), TTL/Topic/Urgency, retrying by the answer. Courier lists pushgate's host in `webpush.hosts`. | Connections, storage until delivery. |
| **Product** (e.g. a push relay) | Storing a device's subscription (`endpoint`, `p256dh`, `auth`) as a Web Push address and choosing when to send to it; dropping it on `404`/`410`. | Talking to devices. |
| **Desktop client** | Generating and keeping its Ed25519 identity key and, per subscription, its P-256 content key and auth secret; connecting and reconnecting; decrypting; acknowledging; showing the notification. | Anything about senders. |

A message reaches a desktop client only while the client runs (a window or a
tray icon). Waking a closed app is the operating system's push (APNs for a
signed macOS app, WNS for a packaged Windows app), outside pushgate.

## Sender side: RFC 8030

`POST <public_url>/wpush/<subscription>`, the subscription's `endpoint`.

| Request | |
| --- | --- |
| Body | The payload encrypted per RFC 8291 (`Content-Encoding: aes128gcm`), at most 4096 bytes. |
| `TTL` | Required: seconds to keep the message for an offline client, 0 to `max_ttl`; a larger value is reduced to `max_ttl`, and the answer's `TTL` header says the value kept. `0`: deliver only to a connected client, otherwise drop. |
| `Topic` | Optional, up to 32 characters of `A-Z a-z 0-9 - _`: an undelivered message of the same subscription and topic is replaced. |
| `Urgency` | Optional: `very-low`, `low`, `normal` (default), `high`; passed to the client. |
| `Authorization` | Required: `vapid t=<JWT>, k=<public key>` (RFC 8292). The JWT is ES256, `aud` is the origin of `public_url`, `exp` is at most 24 hours ahead, `sub` is present; `k` is the key the subscription was made with. |

| Answer | Meaning |
| --- | --- |
| `201 Created`, `Location`, `TTL` | Accepted: handed to the connected client or kept until it connects, acknowledges or the TTL ends. Not a delivery receipt. |
| `400` | Missing or invalid `TTL`, `Topic`, `Urgency` or `Content-Encoding`. |
| `401` | `Authorization` missing or invalid (bad JWT, wrong `aud`, expired). |
| `403` | A valid VAPID key that is not the subscription's. |
| `404` | The endpoint is not a pushgate subscription (a malformed id). |
| `410` | No such subscription: the client unsubscribed, it has not connected for `subscriptions.idle_expiry`, or it never existed. Drop the address. |
| `413` | Body over 4096 bytes. |

Error bodies are `{"code", "errno", "error", "message"}` (autopush's shape).
Push message receipts and message cancellation (RFC 8030 sections 5.1, 7) are
not supported.

## Client side: WebSocket

`GET <public_url>/connect`, a WebSocket. Every frame is one JSON text message:
a `ClientFrame` or a `ServerFrame` of
[`proto/pushgate/client/v1/client.proto`](proto/pushgate/client/v1/client.proto)
in protojson (field names in lowerCamelCase, bytes in base64). The proto is the
single definition; any WebSocket and JSON library speaks it.

1. The server sends `challenge {nonce}` (32 random bytes).
2. The client answers `hello {publicKey, signature}`: its Ed25519 public key
   and the signature of `"backplane-pushgate/v1 hello\x00" || nonce`, within
   `session.hello_timeout`. The client's channel is the base64url SHA-256 of
   the public key; there is no account.
3. The server answers `welcome {channel, subscriptions}` and starts sending the
   channel's messages. A newer connection of the same key replaces an older
   one, which is closed with code 4409.
4. `subscribe {requestId, applicationServerKey}` makes a subscription bound to
   that sender key (the sender's VAPID public key); the answer is
   `subscribed {requestId, subscription {id, endpoint, applicationServerKey}}`.
   The client gives the product `endpoint` with its own `p256dh` and `auth`.
   `unsubscribe {requestId, subscription}` ends one: its endpoint answers 410,
   its undelivered messages are dropped.
5. `notification {id, subscription, data, topic, urgency, sentAt}` carries a
   message: `data` is the encrypted body as the sender posted it. The client
   answers `ack {ids}`; a message not acknowledged within `mailbox.ack_wait` is
   sent again, so delivery is at least once and the client drops a repeated
   `id`.
6. `refused {requestId, code, message}` answers a request that failed:
   `REFUSAL_CODE_INVALID` (a malformed key or field),
   `REFUSAL_CODE_NOT_FOUND` (no such subscription of the channel),
   `REFUSAL_CODE_LIMIT` (`subscriptions.max_per_channel` reached).

Close codes: 4401 the hello does not prove the key, or the first frame is not
a hello (reconnecting with the same key fails again); 4408 no hello within
`session.hello_timeout` (a retry may succeed); 4409 replaced by a newer
connection of the same key; 4400 a malformed frame. 1011 means the service
cannot serve now (retry). The server pings every `session.keepalive`; a
connection that does not answer is closed.

## Client package: `@backplane-labs/pushgate-client`

The TypeScript client of the protocol above, for Electron's main process and
Node ≥ 22 (ESM, no DOM types). It is published to GitHub Packages:
`@backplane-labs:registry=https://npm.pkg.github.com` in `.npmrc`.

```ts
import { PushgateClient, decrypt, generateContentKeys, importContentKeys } from '@backplane-labs/pushgate-client';

const client = new PushgateClient({
  url: 'wss://push.example.com/connect',
  device: { publicKey, sign },              // Ed25519; sign may stay in the OS keystore
  subscriptions: persistedIds,              // ids the host kept: vanished ones reach onSubscriptionGone
  onNotification: async (n) => {            // one at a time; resolving acknowledges, throwing leaves it to come again
    const keys = await importContentKeys(storedKeys[n.subscription]);
    const plaintext = await decrypt(keys, n.data); // DecryptError {reason}: drop it, still resolve
  },
  onStatus: (s) => {},                      // connecting | online | offline {code, retryInMs, final}
  onSubscriptionGone: (id) => {},           // expired: subscribe again, register the new address
});
client.start();

const keys = await generateContentKeys();   // per subscription; keys.export() is plain JSON to persist
const sub = await client.subscribe(applicationServerKey); // give sub.endpoint, keys.p256dh, keys.auth to the sender
```

- Reconnection is automatic with exponential backoff and jitter
  (`backoff: {initialMs, maxMs, jitter}`), except after 4400, 4401 and 4409:
  then the status is `final` and the client stops. `reconnect()` drops the
  connection and connects at once. Call it on resume from sleep or a network
  change, since a half-open connection is not seen otherwise.
- `subscribe` and `unsubscribe` take `{signal, timeoutMs}`. They wait for the
  connection and reject with `PushgateRefusedError {code: INVALID | NOT_FOUND
  | LIMIT | UNAVAILABLE}` or `PushgateTimeoutError`.
- `webSocket` replaces the transport (a proxy-aware socket). It is a factory
  of `WebSocketLike` (`send`, `close`, `listen({open, message, close,
  error})`); `nativeWebSocket` is the default. `clock`, `random` and `log`
  are injectable too.
- `@backplane-labs/pushgate-client/testing` has `FakeGateway`, an in-process
  gateway with the service's semantics (`webSocket`, `push`, `close(code)`,
  `expire`, `refuse`, `acked`), plus `createDeviceKey` and RFC 8291 `encrypt`,
  so hosts test without the service.

## Storage

All in the NATS of the `nats` section, with JetStream:

- KV bucket `pushgate_subscriptions`: `sub.<id>` holds a subscription,
  `chan.<channel>` lists a channel's subscriptions (updated by compare and
  swap, so the per-channel limit holds under concurrent subscribes). The
  bucket's TTL is `subscriptions.idle_expiry`; every hello rewrites the
  channel's records, so only a channel that does not connect for that long
  loses them.
- Stream `PUSHGATE_MAILBOX`, subjects
  `pushgate.mail.<channel>.<subscription>.<slot>`, one message per subject (a
  `Topic` is a slot, so a newer message replaces an undelivered one), a TTL per
  message, work-queue retention: an acknowledged message is gone. A channel
  keeps up to `mailbox.max_per_channel` undelivered messages; beyond it the
  oldest is dropped (under concurrent sends it may briefly hold a few more).
- The replica holding a channel's connection consumes
  `pushgate.mail.<channel>.>` through a consumer named after the channel, so
  NATS routes every message there; no registry of connections is kept. A
  new connection announces itself on `pushgate.session.<channel>`, and the
  older one, on any replica, closes with 4409.
- A `TTL: 0` message is kept (for one second) only while a connection
  consumes the channel; otherwise it is dropped and the sender still gets
  201, as RFC 8030 allows.

## Configuration

| Key | Default | |
| --- | --- | --- |
| `public_url` | required | `https://push.example.com`: endpoints are `<public_url>/wpush/<id>`, VAPID `aud` is its origin. |
| `nats` | required | The NATS with JetStream holding subscriptions and mailboxes (`url`, `creds`, `tls`, ...). |
| `max_ttl` | `672h` | Longest TTL kept (28 days). |
| `mailbox.max_per_channel` | `100` | Undelivered messages kept per channel. |
| `mailbox.ack_wait` | `30s` | A sent message not acknowledged in this time is sent again. |
| `mailbox.replicas` | `1` | Replicas of the stream and the bucket (3 in a NATS cluster). |
| `subscriptions.max_per_channel` | `64` | Subscriptions per channel. |
| `subscriptions.idle_expiry` | `2160h` | A channel not connected for this long (90 days): its subscriptions answer 410. |
| `session.hello_timeout` | `10s` | Time to answer the challenge. |
| `session.keepalive` | `30s` | Ping interval. |

Limits per sender or per address belong to the edge proxy.

## Develop

```sh
make configure configure-client  # golangci-lint, easyp, protoc-gen-go into ./bin; the client's deps (Yarn 4 via `corepack enable`)
make gen         # proto/pushgate/client/v1 -> Go and client/src/gen
make lint test   # builds the client, then Go tests on NATS with JetStream in-process: no docker needed
make run         # against the local backplane stack (deployments/dev.yaml)
```

| Package | |
| --- | --- |
| `internal/domain` | Rules: channels and hello proofs, subscription ids, sender headers. |
| `internal/vapid` | RFC 8292 verification; `vapidtest` signs headers for tests. |
| `internal/app` | Scenarios: push, hello, subscribe, unsubscribe. |
| `internal/store` | JetStream: the bucket, the mailbox stream, a channel's consumer. |
| `internal/sender` | The RFC 8030 endpoint. |
| `internal/session` | The client WebSocket. |
| `internal/pushtest` | A test client: hello, subscribe, receive, ack, RFC 8291 decryption. |
| `tests` | The service whole on a real NATS: senders through webpush-go (what backplane-courier sends with), two replicas, a NATS node down, NATS gone, and the TypeScript client (`client/e2e/device.mjs`) against it. |
| `client` | The TypeScript client package with its own tests (`make client`). Biome lints and formats it (`yarn lint`, `yarn fmt`): its recommended rules, the project's bans (any, non-null, default and `export *`, enums, namespaces, `==`, floating promises, console), and two GritQL plugins in `client/biome/` that reject `as` casts (except `as const`) and `unknown`. |

## Metrics

| Name | Type | Labels |
|---|---|---|
| `pushgate.sends` | counter | `outcome`: `accepted`, `dropped` (no client and TTL 0), `invalid`, `gone`, `unauthorized`, `wrong_key`, `too_large`, `failed` |
| `pushgate.sessions` | up-down counter | — (open client sessions) |
| `pushgate.deliveries` | counter | `outcome`: `sent`, `unsent` (resent on the next connection), `acked` |

The SDK's metrics come on top (backplane `reference/metrics`): NATS lag,
HTTP and gRPC servers, the Go runtime.
