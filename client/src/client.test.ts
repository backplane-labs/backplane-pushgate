import { describe, expect, test, vi } from 'vitest';

import { PushgateClient, type Clock, type Notification, type PushgateClientOptions, type Status } from './client.js';
import { decrypt, encrypt, generateContentKeys } from './crypto.js';
import { PushgateRefusedError, PushgateTimeoutError } from './errors.js';
import type { WebSocketLike } from './socket.js';
import { FakeGateway, createDeviceKey } from './testing.js';

const senderKey = 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8';
const text = new TextEncoder();

/** A clock the test advances. */
function manualClock(): { clock: Clock; advance(ms: number): void } {
  let now = 0;
  const timers: { at: number; fn: () => void; cancelled: boolean }[] = [];

  return {
    clock: {
      now: () => now,
      setTimeout(fn, ms) {
        const timer = { at: now + ms, fn, cancelled: false };
        timers.push(timer);
        return () => {
          timer.cancelled = true;
        };
      },
    },
    advance(ms) {
      now += ms;
      for (const timer of timers.filter((t) => !t.cancelled && t.at <= now)) {
        timer.cancelled = true;
        timer.fn();
      }
    },
  };
}

interface Harness {
  readonly client: PushgateClient;
  readonly gateway: FakeGateway;
  readonly statuses: Status[];
  readonly received: Notification[];
  readonly gone: string[];
  readonly advance: (ms: number) => void;
}

async function harness(
  overrides: Partial<PushgateClientOptions> = {}, gateway = new FakeGateway(),
): Promise<Harness> {
  const { clock, advance } = manualClock();
  const statuses: Status[] = [];
  const received: Notification[] = [];
  const gone: string[] = [];
  const client = new PushgateClient({
    url: 'wss://pushgate.test/connect', device: await createDeviceKey(), webSocket: gateway.webSocket, clock,
    random: () => 0,
    onNotification: async (n) => {
      received.push(n);
    },
    onStatus: (s) => statuses.push(s),
    onSubscriptionGone: (id) => gone.push(id),
    ...overrides,
  });

  return { client, gateway, statuses, received, gone, advance };
}

async function online(h: Harness): Promise<void> {
  await vi.waitFor(() => expect(h.statuses.at(-1)?.state).toBe('online'));
}

describe('PushgateClient', () => {
  test('subscribes, receives, decrypts and acknowledges', async () => {
    const h = await harness();
    h.client.start();
    await online(h);

    const sub = await h.client.subscribe(senderKey);
    expect(sub.endpoint).toBe(`https://pushgate.test/wpush/${sub.id}`);
    expect(h.client.subscriptions).toEqual([sub]);

    const keys = await generateContentKeys();
    const id = h.gateway.push(sub.id, await encrypt(keys.p256dh, keys.auth, text.encode('ring')), { topic: 'call', urgency: 'high' });

    await vi.waitFor(() => expect(h.gateway.acked).toEqual([id]));

    const n = h.received[0];
    expect(n?.subscription).toBe(sub.id);
    expect(n?.topic).toBe('call');
    expect(n?.urgency).toBe('high');
    expect(n === undefined ? '' : new TextDecoder().decode(await decrypt(keys, n.data))).toBe('ring');
    h.client.stop();
  });

  test('a handler that throws leaves the message to come again; a repeat of a handled one is acknowledged unseen', async () => {
    let calls = 0;
    const gateway = new FakeGateway();
    const h = await harness({
      onNotification: async () => {
        calls++;
        if (calls === 1) throw new Error('not now');
        if (calls === 2) gateway.close(1006); // handled, but the ack is lost with the connection
      },
    }, gateway);

    h.client.start();
    await online(h);
    const sub = await h.client.subscribe(senderKey);
    const id = gateway.push(sub.id, new Uint8Array([1]));

    await vi.waitFor(() => expect(calls).toBe(1));
    h.client.reconnect(); // redelivered: handled this time, the ack lost
    await vi.waitFor(() => expect(calls).toBe(2));
    await vi.waitFor(() => expect(h.statuses.at(-1)?.state).toBe('offline'));

    h.advance(1000); // back again: a repeat, acknowledged without the handler
    await vi.waitFor(() => expect(gateway.acked).toEqual([id]));
    expect(calls).toBe(2);
    h.client.stop();
  });

  test('handles messages one at a time, acknowledging in order', async () => {
    const order: string[] = [];
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = await harness({
      onNotification: async (n) => {
        order.push(`start ${n.id}`);
        if (order.length === 1) await gate;
        order.push(`end ${n.id}`);
      },
    });

    h.client.start();
    await online(h);
    const sub = await h.client.subscribe(senderKey);
    const first = h.gateway.push(sub.id, new Uint8Array([1]));
    const second = h.gateway.push(sub.id, new Uint8Array([2]));

    await vi.waitFor(() => expect(order).toEqual([`start ${first}`]));
    release();
    await vi.waitFor(() => expect(h.gateway.acked).toEqual([first, second]));
    expect(order).toEqual([`start ${first}`, `end ${first}`, `start ${second}`, `end ${second}`]);
    h.client.stop();
  });

  test.each([4400, 4401, 4409])('stops for good on close code %i', async (code) => {
    const h = await harness();
    h.client.start();
    await online(h);

    h.gateway.close(code);
    await vi.waitFor(() => expect(h.statuses.at(-1)).toEqual({ state: 'offline', code, final: true }));

    h.advance(120_000);
    expect(h.gateway.connections).toBe(1);
  });

  test.each([4408, 1011, 1006])('reconnects after close code %i', async (code) => {
    const h = await harness();
    h.client.start();
    await online(h);

    h.gateway.close(code);
    await vi.waitFor(() => expect(h.statuses.at(-1)).toEqual({ state: 'offline', code, retryInMs: 1000 }));

    h.advance(1000);
    await vi.waitFor(() => expect(h.gateway.connections).toBe(2));
    await online(h);
    h.client.stop();
  });

  test('backs off exponentially up to the cap, with jitter', async () => {
    const delays: number[] = [];
    const failing = (): WebSocketLike => ({
      send() {},
      close() {},
      listen(events) {
        queueMicrotask(() => events.close(1006, ''));
      },
    });
    const h = await harness({
      webSocket: failing, random: () => 0.5, backoff: { initialMs: 100, maxMs: 500, jitter: 0.5 },
      onStatus: (s) => {
        if (s.retryInMs !== undefined) delays.push(s.retryInMs);
      },
    });

    h.client.start();
    for (const wait of [75, 150, 300, 375, 375]) {
      await vi.waitFor(() => expect(delays.at(-1)).toBe(wait));
      h.advance(wait);
    }

    expect(delays).toEqual([75, 150, 300, 375, 375]);
    h.client.stop();
  });

  test('a bad device key is refused for good', async () => {
    const real = await createDeviceKey();
    const other = await createDeviceKey();
    const h = await harness({ device: { publicKey: other.publicKey, sign: real.sign } });

    h.client.start();
    await vi.waitFor(() => expect(h.statuses.at(-1)).toEqual({ state: 'offline', code: 4401, final: true }));
  });

  test('reports a known subscription the gateway no longer has', async () => {
    const gateway = new FakeGateway();
    const device = await createDeviceKey();
    const first = await harness({ device }, gateway);
    first.client.start();
    await online(first);
    const kept = await first.client.subscribe(senderKey);
    const expired = await first.client.subscribe(senderKey);
    first.client.stop();

    gateway.expire(expired.id);

    const second = await harness({ device, subscriptions: [kept.id, expired.id] }, gateway);
    second.client.start();
    await online(second);

    expect(second.gone).toEqual([expired.id]);
    expect(second.client.subscriptions.map((s) => s.id)).toEqual([kept.id]);
    second.client.stop();
  });

  test.each(['INVALID', 'NOT_FOUND', 'LIMIT', 'UNAVAILABLE'] as const)('a refusal %s rejects with its code', async (code) => {
    const h = await harness();
    h.client.start();
    await online(h);

    h.gateway.refuse(code);
    const error = await h.client.subscribe(senderKey).catch((e: Error) => e);

    expect(error).toBeInstanceOf(PushgateRefusedError);
    expect(error instanceof PushgateRefusedError && error.code).toBe(code);
    h.client.stop();
  });

  test('a request waits for the connection, within its deadline', async () => {
    const silent = (): WebSocketLike => ({ send() {}, close() {}, listen() {} });
    const h = await harness({ webSocket: silent });
    h.client.start();

    const pending = h.client.subscribe(senderKey, { timeoutMs: 500 }).catch((e: Error) => e);
    h.advance(500);

    expect(await pending).toBeInstanceOf(PushgateTimeoutError);
    h.client.stop();
  });

  test('a request is cancelled by its signal', async () => {
    const silent = (): WebSocketLike => ({ send() {}, close() {}, listen() {} });
    const h = await harness({ webSocket: silent });
    h.client.start();

    const abort = new AbortController();
    const pending = h.client.subscribe(senderKey, { signal: abort.signal }).then(() => 'subscribed', (e: Error) => e.message);
    abort.abort(new Error('user left'));

    expect(await pending).toBe('user left');
    h.client.stop();
  });

  test('stop fails waiting requests at once and reports offline for good', async () => {
    const silent = (): WebSocketLike => ({ send() {}, close() {}, listen() {} });
    const h = await harness({ webSocket: silent });
    h.client.start();

    const pending = h.client.subscribe(senderKey).then(() => 'subscribed', (e: Error) => e);
    h.client.stop();

    const error = await pending;
    expect(error).toBeInstanceOf(PushgateRefusedError);
    expect(error instanceof PushgateRefusedError && error.code).toBe('UNAVAILABLE');
    expect(h.statuses.at(-1)).toEqual({ state: 'offline', code: 1000, final: true });
  });

  test('unsubscribe ends a subscription', async () => {
    const h = await harness();
    h.client.start();
    await online(h);

    const sub = await h.client.subscribe(senderKey);
    await h.client.unsubscribe(sub.id);

    expect(h.client.subscriptions).toEqual([]);
    await expect(h.client.unsubscribe(sub.id)).rejects.toThrow(PushgateRefusedError);
    h.client.stop();
  });
});
