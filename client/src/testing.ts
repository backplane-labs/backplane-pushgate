import { create, fromJsonString, type MessageInitShape, toJsonString } from '@bufbuild/protobuf';
import { timestampNow } from '@bufbuild/protobuf/wkt';

import { type DeviceKey, HELLO_CONTEXT } from './client.js';
import { base64url, encrypt, fromBase64url } from './crypto.js';
import { ClientFrameSchema, RefusalCode, ServerFrameSchema } from './gen/pushgate/client/v1/client_pb.js';
import type { SocketEvents, WebSocketFactory, WebSocketLike } from './socket.js';

export { encrypt };

const subtle = globalThis.crypto.subtle;

/** A server frame's content, as create() takes it. */
type FrameInit = NonNullable<MessageInitShape<typeof ServerFrameSchema>['frame']>;

/** A fresh Ed25519 device key held in WebCrypto (not extractable). */
export async function createDeviceKey(): Promise<DeviceKey> {
  const pair = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  if (!('privateKey' in pair)) throw new Error('Ed25519 made no key pair');

  const publicKey = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));

  return {
    publicKey,
    sign: async (message) => new Uint8Array(await subtle.sign('Ed25519', pair.privateKey, message)),
  };
}

/** A message the fake gateway keeps until the client acknowledges it. */
export interface FakeMessage {
  readonly id: string;
  readonly subscription: string;
  readonly data: Uint8Array;
  readonly topic?: string;
  readonly urgency?: string;
}

interface FakeSubscription {
  readonly id: string;
  readonly channel: string;
  readonly key: string;
}

/** The fake gateway's side of one connection. */
interface FakeConnection {
  readonly events: SocketEvents;
  nonce: Uint8Array;
  channel?: string;
  closed: boolean;
}

/**
 * An in-process backplane-pushgate for tests: it speaks the client protocol over the WebSocketLike
 * its webSocket factory makes, with the gateway's semantics (a mailbox until ack, a newer
 * connection of a key replacing the older with 4409).
 */
export class FakeGateway {
  /** Pass as PushgateClientOptions.webSocket. */
  readonly webSocket: WebSocketFactory = () => this.open();
  /** Every message id acknowledged, in order. */
  readonly acked: string[] = [];

  private readonly subscriptions = new Map<string, FakeSubscription>();
  private readonly mailbox = new Map<string, FakeMessage[]>(); // by channel
  private readonly live = new Map<string, FakeConnection>(); // by channel
  private connection: FakeConnection | undefined;
  private sequence = 0;
  private refuseNext: RefusalCode | undefined;

  /** How many connections were opened. */
  connections = 0;

  /** Sends data (already encrypted) to a subscription: at once to a connected client, else on its next connection. */
  push(subscription: string, data: Uint8Array, options: { topic?: string; urgency?: string } = {}): string {
    const sub = this.subscriptions.get(subscription);
    if (sub === undefined) throw new Error(`fake gateway: no subscription ${subscription}`);

    const message: FakeMessage = { id: String(++this.sequence), subscription, data, ...options };
    const box = (this.mailbox.get(sub.channel) ?? []).filter(
      (m) => options.topic === undefined || m.topic !== options.topic,
    );
    this.mailbox.set(sub.channel, [...box, message]);

    const connection = this.live.get(sub.channel);
    if (connection !== undefined) this.deliver(connection, message);

    return message.id;
  }

  /** Closes the current connection with code, as the gateway does. */
  close(code: number, reason = ''): void {
    const connection = this.connection;
    if (connection === undefined) return;

    this.drop(connection);
    queueMicrotask(() => connection.events.close(code, reason));
  }

  /** Forgets a subscription, as idle expiry does: the next welcome lacks it. */
  expire(subscription: string): void {
    this.subscriptions.delete(subscription);
  }

  /** The subscriptions of a channel. */
  subscriptionsOf(channel: string): readonly string[] {
    return [...this.subscriptions.values()].filter((s) => s.channel === channel).map((s) => s.id);
  }

  /** Makes the next subscribe or unsubscribe fail with code. */
  refuse(code: 'INVALID' | 'NOT_FOUND' | 'LIMIT' | 'UNAVAILABLE'): void {
    this.refuseNext = {
      INVALID: RefusalCode.INVALID,
      NOT_FOUND: RefusalCode.NOT_FOUND,
      LIMIT: RefusalCode.LIMIT,
      UNAVAILABLE: RefusalCode.UNSPECIFIED,
    }[code];
  }

  private open(): WebSocketLike {
    this.connections++;

    let connection: FakeConnection | undefined;

    return {
      send: (data) => {
        if (connection !== undefined && !connection.closed) void this.receive(connection, data);
      },
      close: () => {
        if (connection !== undefined) this.drop(connection);
      },
      listen: (events) => {
        const opened: FakeConnection = {
          events,
          nonce: globalThis.crypto.getRandomValues(new Uint8Array(32)),
          closed: false,
        };
        connection = opened;
        this.connection = opened;
        queueMicrotask(() => {
          events.open();
          this.emit(opened, { case: 'challenge', value: { nonce: opened.nonce } });
        });
      },
    };
  }

  private async receive(connection: FakeConnection, data: string): Promise<void> {
    const frame = fromJsonString(ClientFrameSchema, data).frame;

    switch (frame.case) {
      case 'hello': {
        const message = new Uint8Array([...new TextEncoder().encode(HELLO_CONTEXT), ...connection.nonce]);
        const key = await subtle.importKey('raw', frame.value.publicKey, { name: 'Ed25519' }, false, ['verify']);
        if (!(await subtle.verify('Ed25519', key, frame.value.signature, message))) {
          this.drop(connection);
          connection.events.close(4401, 'the hello does not prove the key');

          return;
        }

        const channel = base64url(new Uint8Array(await subtle.digest('SHA-256', frame.value.publicKey)));
        const older = this.live.get(channel);
        if (older !== undefined) {
          this.drop(older);
          queueMicrotask(() => older.events.close(4409, 'replaced'));
        }

        connection.channel = channel;
        this.live.set(channel, connection);
        this.emit(connection, {
          case: 'welcome',
          value: {
            channel,
            subscriptions: [...this.subscriptions.values()]
              .filter((s) => s.channel === channel)
              .map((s) => ({ id: s.id, endpoint: endpoint(s.id), applicationServerKey: s.key })),
          },
        });

        for (const message of this.mailbox.get(channel) ?? []) this.deliver(connection, message);

        return;
      }
      case 'subscribe': {
        const { requestId, applicationServerKey } = frame.value;
        if (this.refused(connection, requestId)) return;

        if (fromBase64url(applicationServerKey).length !== 65 || connection.channel === undefined) {
          this.emit(connection, {
            case: 'refused',
            value: { requestId, code: RefusalCode.INVALID, message: 'not a P-256 key' },
          });

          return;
        }

        const id = `sub-${++this.sequence}`;
        this.subscriptions.set(id, { id, channel: connection.channel, key: applicationServerKey });
        this.emit(connection, {
          case: 'subscribed',
          value: { requestId, subscription: { id, endpoint: endpoint(id), applicationServerKey } },
        });

        return;
      }
      case 'unsubscribe': {
        const { requestId, subscription } = frame.value;
        if (this.refused(connection, requestId)) return;

        if (this.subscriptions.get(subscription)?.channel !== connection.channel) {
          this.emit(connection, {
            case: 'refused',
            value: { requestId, code: RefusalCode.NOT_FOUND, message: 'no such subscription' },
          });

          return;
        }

        this.subscriptions.delete(subscription);
        this.emit(connection, { case: 'unsubscribed', value: { requestId, subscription } });

        return;
      }
      case 'ack': {
        const channel = connection.channel;
        for (const id of frame.value.ids) {
          this.acked.push(id);
          if (channel !== undefined)
            this.mailbox.set(
              channel,
              (this.mailbox.get(channel) ?? []).filter((m) => m.id !== id),
            );
        }

        return;
      }
      case undefined:
        return;
    }
  }

  private refused(connection: FakeConnection, requestId: string): boolean {
    const code = this.refuseNext;
    if (code === undefined) return false;

    this.refuseNext = undefined;
    this.emit(connection, { case: 'refused', value: { requestId, code, message: 'refused by the fake gateway' } });

    return true;
  }

  private deliver(connection: FakeConnection, m: FakeMessage): void {
    this.emit(connection, {
      case: 'notification',
      value: {
        id: m.id,
        subscription: m.subscription,
        data: m.data,
        topic: m.topic ?? '',
        urgency: m.urgency ?? 'normal',
        sentAt: timestampNow(),
      },
    });
  }

  private emit(connection: FakeConnection, frame: FrameInit): void {
    if (connection.closed) return;

    const text = toJsonString(ServerFrameSchema, create(ServerFrameSchema, { frame }));
    queueMicrotask(() => {
      if (!connection.closed) connection.events.message(text);
    });
  }

  private drop(connection: FakeConnection): void {
    connection.closed = true;
    if (connection.channel !== undefined && this.live.get(connection.channel) === connection)
      this.live.delete(connection.channel);
    if (this.connection === connection) this.connection = undefined;
  }
}

function endpoint(id: string): string {
  return `https://pushgate.test/wpush/${id}`;
}
