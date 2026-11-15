import { create, fromJsonString, type MessageInitShape, toJsonString } from '@bufbuild/protobuf';
import { timestampDate } from '@bufbuild/protobuf/wkt';
import { PushgateRefusedError, PushgateTimeoutError, type RefusalCode } from './errors.js';
import {
  ClientFrameSchema,
  type ServerFrame,
  ServerFrameSchema,
  type Notification as WireNotification,
  RefusalCode as WireRefusal,
  type Subscription as WireSubscription,
} from './gen/pushgate/client/v1/client_pb.js';
import { nativeWebSocket, type WebSocketFactory, type WebSocketLike } from './socket.js';

/** What a device signs to answer the gateway's challenge, before the nonce. */
export const HELLO_CONTEXT = 'backplane-pushgate/v1 hello\0';

/** Close codes after which reconnecting cannot succeed: the client stops. */
export const FINAL_CLOSE_CODES: readonly number[] = [
  4400, // a malformed frame: a bug
  4401, // the hello does not prove the key
  4409, // a newer connection of the same key replaced this one
];

/** The device's Ed25519 identity: the gateway knows it by its public key. */
export interface DeviceKey {
  /** The 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** The Ed25519 signature (64 bytes) of message. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** A subscription id, as the gateway names it. */
export type SubscriptionId = string & { readonly brand: 'pushgate.SubscriptionId' };

/** A message id: the same on a repeated delivery. */
export type NotificationId = string & { readonly brand: 'pushgate.NotificationId' };

/** One sender key's address of the device: give the endpoint (with the content keys) to the sender. */
export interface Subscription {
  readonly id: SubscriptionId;
  /** The RFC 8030 push resource the sender posts to. */
  readonly endpoint: string;
  /** The sender's VAPID public key the endpoint accepts. */
  readonly applicationServerKey: string;
}

/** Urgency of a message (RFC 8030 5.3). */
export type Urgency = 'very-low' | 'low' | 'normal' | 'high';

/** A message: data is the encrypted body (decrypt with the subscription's content keys). */
export interface Notification {
  readonly id: NotificationId;
  readonly subscription: SubscriptionId;
  readonly data: Uint8Array;
  readonly topic?: string;
  readonly urgency: Urgency;
  readonly sentAt: Date;
}

/** The connection: offline with a code when it closed; final when the client stopped for good. */
export interface Status {
  readonly state: 'connecting' | 'online' | 'offline';
  readonly code?: number;
  readonly retryInMs?: number;
  readonly final?: boolean;
}

/** Fields of a log record. */
export type LogFields = Readonly<Record<string, string | number | boolean>>;

/** Where the client logs. */
export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

/** Time for the client: injected for deterministic tests. */
export interface Clock {
  now(): number;
  /** Runs fn after ms; the result cancels it. */
  setTimeout(fn: () => void, ms: number): () => void;
}

/** Reconnection: the delay doubles from initialMs to maxMs, less up to jitter of it at random. */
export interface Backoff {
  readonly initialMs?: number;
  readonly maxMs?: number;
  readonly jitter?: number;
}

/** A request's cancellation and deadline. */
export interface RequestOptions {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export interface PushgateClientOptions {
  /** The gateway's WebSocket: wss://<host>/connect. */
  readonly url: string;
  readonly device: DeviceKey;
  /** Subscription ids the host persisted: any the gateway no longer has is reported to onSubscriptionGone. */
  readonly subscriptions?: readonly string[];
  readonly webSocket?: WebSocketFactory;
  readonly backoff?: Backoff;
  readonly clock?: Clock;
  readonly random?: () => number;
  readonly log?: Logger;
  /** A request's deadline when RequestOptions sets none (10 s). */
  readonly requestTimeoutMs?: number;
  /** Handles a message: resolving acknowledges it, throwing leaves it to be sent again. One at a time. */
  onNotification(notification: Notification): Promise<void>;
  onStatus?(status: Status): void;
  /** A known subscription the gateway no longer has (it expired): subscribe again and register the new address. */
  onSubscriptionGone?(id: SubscriptionId, reason: 'expired'): void;
}

const DEFAULT_BACKOFF: Required<Backoff> = { initialMs: 1000, maxMs: 60_000, jitter: 0.5 };

/** A client frame's content, as create() takes it. */
type FrameInit = NonNullable<MessageInitShape<typeof ClientFrameSchema>['frame']>;
const DEFAULT_REQUEST_TIMEOUT = 10_000;
/** How many handled message ids are remembered to drop repeats. */
const REMEMBERED = 1024;

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const realClock: Clock = {
  now: () => Date.now(),
  setTimeout(fn, ms) {
    const handle = setTimeout(fn, ms);

    return () => clearTimeout(handle);
  },
};

/** Narrows a gateway-given id. */
function isSubscriptionId(s: string): s is SubscriptionId {
  return s !== '';
}

function isNotificationId(s: string): s is NotificationId {
  return s !== '';
}

function urgency(s: string): Urgency {
  switch (s) {
    case 'very-low':
    case 'low':
    case 'high':
      return s;
    default:
      return 'normal';
  }
}

function refusalCode(code: WireRefusal): RefusalCode {
  switch (code) {
    case WireRefusal.INVALID:
      return 'INVALID';
    case WireRefusal.NOT_FOUND:
      return 'NOT_FOUND';
    case WireRefusal.LIMIT:
      return 'LIMIT';
    case WireRefusal.UNSPECIFIED:
      return 'UNAVAILABLE';
  }
}

/** One open connection; events of an older one are ignored. */
interface Connection {
  readonly socket: WebSocketLike;
  online: boolean;
}

interface Pending {
  resolve(frame: ServerFrame): void;
  reject(error: Error): void;
}

/**
 * A desktop device's connection to backplane-pushgate: it proves the device key, keeps the
 * connection (reconnecting with backoff), hands over messages one at a time and acknowledges each
 * one its handler accepted.
 */
export class PushgateClient {
  private readonly options: PushgateClientOptions;
  private readonly clock: Clock;
  private readonly random: () => number;
  private readonly log: Logger;
  private readonly factory: WebSocketFactory;
  private readonly backoff: Required<Backoff>;

  private running = false;
  private connection: Connection | undefined;
  private cancelRetry: (() => void) | undefined;
  private attempt = 0;
  private known: ReadonlySet<string>;
  private current: readonly Subscription[] = [];
  private readonly pending = new Map<string, Pending>();
  /** Requests waiting for the connection: send once online, fail when the client stops. */
  private readonly waiting = new Map<() => void, (error: Error) => void>();
  private readonly handled = new Set<string>();
  private queue: Promise<void> = Promise.resolve();
  private sequence = 0;

  constructor(options: PushgateClientOptions) {
    this.options = options;
    this.clock = options.clock ?? realClock;
    this.random = options.random ?? Math.random;
    this.log = options.log ?? silent;
    this.factory = options.webSocket ?? nativeWebSocket;
    this.backoff = { ...DEFAULT_BACKOFF, ...options.backoff };
    this.known = new Set(options.subscriptions ?? []);
  }

  /** The subscriptions of the last welcome and those made since. */
  get subscriptions(): readonly Subscription[] {
    return this.current;
  }

  /** Connects and keeps the connection until stop. */
  start(): void {
    if (this.running) return;

    this.running = true;
    this.connect();
  }

  /** Closes the connection; pending requests fail with UNAVAILABLE. */
  stop(): void {
    if (!this.running) return;

    this.running = false;
    this.cancelRetry?.();
    this.cancelRetry = undefined;

    const connection = this.connection;
    this.connection = undefined;
    connection?.socket.close(1000, 'stopped');
    this.failPending('the client stopped');
    for (const fail of [...this.waiting.values()]) fail(new PushgateRefusedError('UNAVAILABLE', 'the client stopped'));
    this.status({ state: 'offline', code: 1000, final: true });
  }

  /**
   * Drops the connection and connects again at once: call it when the network changed or the
   * machine woke up, since a half-open connection is not seen otherwise.
   */
  reconnect(): void {
    if (!this.running) return;

    this.cancelRetry?.();
    this.cancelRetry = undefined;

    const connection = this.connection;
    this.connection = undefined;
    connection?.socket.close(1000, 'reconnect');
    this.failPending('the connection was replaced');
    this.attempt = 0;
    this.connect();
  }

  /** Makes a subscription for a sender key (its VAPID public key, base64url). */
  async subscribe(applicationServerKey: string, options: RequestOptions = {}): Promise<Subscription> {
    const frame = await this.request(options, (requestId) => ({
      case: 'subscribe',
      value: { requestId, applicationServerKey },
    }));

    if (frame.frame.case !== 'subscribed' || frame.frame.value.subscription === undefined) {
      throw new PushgateRefusedError('UNAVAILABLE', 'unexpected answer to subscribe');
    }

    const subscription = this.subscription(frame.frame.value.subscription);
    this.current = [...this.current, subscription];
    this.known = new Set([...this.known, subscription.id]);

    return subscription;
  }

  /** Ends a subscription: its endpoint answers 410. */
  async unsubscribe(id: SubscriptionId, options: RequestOptions = {}): Promise<void> {
    await this.request(options, (requestId) => ({ case: 'unsubscribe', value: { requestId, subscription: id } }));

    this.current = this.current.filter((s) => s.id !== id);
    this.known = new Set([...this.known].filter((k) => k !== id));
  }

  private connect(): void {
    if (!this.running) return;

    const socket = this.factory(this.options.url);
    const connection: Connection = { socket, online: false };
    this.connection = connection;
    this.status({ state: 'connecting' });

    socket.listen({
      open: () => this.log.debug('pushgate: connected'),
      message: (data) => {
        if (this.connection === connection) void this.onFrame(connection, data);
      },
      close: (code, reason) => {
        if (this.connection === connection) this.onClose(code, reason);
      },
      error: () => this.log.debug('pushgate: socket error'),
    });
  }

  private async onFrame(connection: Connection, data: string): Promise<void> {
    let frame: ServerFrame;
    try {
      frame = fromJsonString(ServerFrameSchema, data, { ignoreUnknownFields: true });
    } catch (error) {
      this.log.error('pushgate: a frame is not protojson', { error: String(error) });
      connection.socket.close(1002, 'malformed frame');

      return;
    }

    switch (frame.frame.case) {
      case 'challenge': {
        const message = new Uint8Array([...new TextEncoder().encode(HELLO_CONTEXT), ...frame.frame.value.nonce]);
        const signature = await this.options.device.sign(message);
        this.send(connection, { case: 'hello', value: { publicKey: this.options.device.publicKey, signature } });

        return;
      }
      case 'welcome':
        this.onWelcome(connection, frame.frame.value.subscriptions);

        return;
      case 'subscribed':
      case 'unsubscribed':
        this.settle(frame.frame.value.requestId, frame);

        return;
      case 'refused': {
        const { requestId, code, message } = frame.frame.value;
        this.settle(requestId, undefined, new PushgateRefusedError(refusalCode(code), message));

        return;
      }
      case 'notification':
        this.enqueue(connection, frame.frame.value);

        return;
      case undefined:
        return;
    }
  }

  private onWelcome(connection: Connection, subscriptions: readonly WireSubscription[]): void {
    this.current = subscriptions.map((s) => this.subscription(s));

    const present = new Set<string>(this.current.map((s) => s.id));
    for (const id of this.known) {
      if (!present.has(id) && isSubscriptionId(id)) this.options.onSubscriptionGone?.(id, 'expired');
    }

    this.known = present;
    this.attempt = 0;
    connection.online = true;
    this.status({ state: 'online' });

    for (const wake of [...this.waiting.keys()]) wake();
    this.waiting.clear();
  }

  private onClose(code: number, reason: string): void {
    this.connection = undefined;
    this.failPending('the connection closed');

    if (!this.running) return;

    if (FINAL_CLOSE_CODES.includes(code)) {
      this.running = false;
      this.log.error('pushgate: closed for good', { code, reason });
      this.status({ state: 'offline', code, final: true });

      return;
    }

    const delay = Math.min(this.backoff.maxMs, this.backoff.initialMs * 2 ** this.attempt);
    const retryInMs = Math.round(delay * (1 - this.backoff.jitter * this.random()));
    this.attempt++;
    this.log.warn('pushgate: disconnected', { code, retryInMs });
    this.status({ state: 'offline', code, retryInMs });
    this.cancelRetry = this.clock.setTimeout(() => {
      this.cancelRetry = undefined;
      this.connect();
    }, retryInMs);
  }

  /** Runs the handler for each message in turn; acknowledges what it accepted and repeats of it. */
  private enqueue(connection: Connection, wire: WireNotification): void {
    this.queue = this.queue.then(() => this.handle(connection, wire));
  }

  private async handle(connection: Connection, wire: WireNotification): Promise<void> {
    if (!isNotificationId(wire.id) || !isSubscriptionId(wire.subscription)) return;

    if (this.handled.has(wire.id)) {
      this.ack(connection, wire.id);

      return;
    }

    const notification: Notification = {
      id: wire.id,
      subscription: wire.subscription,
      data: wire.data,
      urgency: urgency(wire.urgency),
      sentAt: wire.sentAt === undefined ? new Date(this.clock.now()) : timestampDate(wire.sentAt),
      ...(wire.topic === '' ? {} : { topic: wire.topic }),
    };

    try {
      await this.options.onNotification(notification);
    } catch (error) {
      this.log.warn('pushgate: a message was not handled; it comes again', { id: wire.id, error: String(error) });

      return;
    }

    this.remember(wire.id);
    this.ack(connection, wire.id);
  }

  private remember(id: string): void {
    this.handled.add(id);
    if (this.handled.size <= REMEMBERED) return;

    for (const oldest of this.handled) {
      this.handled.delete(oldest);
      break;
    }
  }

  private ack(connection: Connection, id: string): void {
    // A closed connection loses the ack: the message comes again and is acknowledged then.
    if (this.connection !== connection) return;

    this.send(connection, { case: 'ack', value: { ids: [id] } });
  }

  private request(options: RequestOptions, frame: (requestId: string) => FrameInit): Promise<ServerFrame> {
    const timeoutMs = options.timeoutMs ?? this.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT;
    const requestId = `r${++this.sequence}`;

    return new Promise<ServerFrame>((resolve, reject) => {
      let done = false;
      const cleanups: (() => void)[] = [];
      const finish = (settle: () => void): void => {
        if (done) return;

        done = true;
        for (const cleanup of cleanups) cleanup();
        this.pending.delete(requestId);
        settle();
      };

      cleanups.push(
        this.clock.setTimeout(
          () => finish(() => reject(new PushgateTimeoutError(`no answer within ${timeoutMs} ms`))),
          timeoutMs,
        ),
      );

      if (options.signal !== undefined) {
        const signal = options.signal;
        if (signal.aborted) {
          finish(() => reject(signal.reason instanceof Error ? signal.reason : new Error('aborted')));

          return;
        }

        const onAbort = (): void =>
          finish(() => reject(signal.reason instanceof Error ? signal.reason : new Error('aborted')));
        signal.addEventListener('abort', onAbort, { once: true });
        cleanups.push(() => signal.removeEventListener('abort', onAbort));
      }

      const send = (): void => {
        const connection = this.connection;
        if (done || connection === undefined || !connection.online) return;

        this.pending.set(requestId, {
          resolve: (f) => finish(() => resolve(f)),
          reject: (e) => finish(() => reject(e)),
        });
        this.send(connection, frame(requestId));
      };

      if (this.connection?.online === true) {
        send();
      } else {
        this.waiting.set(send, (error) => finish(() => reject(error)));
        cleanups.push(() => this.waiting.delete(send));
      }
    });
  }

  private settle(requestId: string, frame: ServerFrame | undefined, error?: Error): void {
    const pending = this.pending.get(requestId);
    if (pending === undefined) return;

    if (error !== undefined) pending.reject(error);
    else if (frame !== undefined) pending.resolve(frame);
  }

  private failPending(message: string): void {
    for (const pending of [...this.pending.values()]) pending.reject(new PushgateRefusedError('UNAVAILABLE', message));
  }

  private send(connection: Connection, frame: FrameInit): void {
    try {
      connection.socket.send(toJsonString(ClientFrameSchema, create(ClientFrameSchema, { frame })));
    } catch (error) {
      this.log.warn('pushgate: a frame was not sent', { error: String(error) });
    }
  }

  private subscription(s: WireSubscription): Subscription {
    if (!isSubscriptionId(s.id)) throw new PushgateRefusedError('UNAVAILABLE', 'a subscription without an id');

    return { id: s.id, endpoint: s.endpoint, applicationServerKey: s.applicationServerKey };
  }

  private status(status: Status): void {
    this.options.onStatus?.(status);
  }
}
