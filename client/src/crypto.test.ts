import { describe, expect, test } from 'vitest';

import { decrypt, encrypt, generateContentKeys, importContentKeys, type ContentKeys } from './crypto.js';
import { DecryptError } from './errors.js';

const text = new TextEncoder();

describe('content keys', () => {
  test('export and import round-trip through plain JSON', async () => {
    const keys = await generateContentKeys();
    const json = JSON.parse(JSON.stringify(keys.export()));
    const again = await importContentKeys(json);

    expect(again.p256dh).toBe(keys.p256dh);
    expect(again.auth).toBe(keys.auth);

    const data = await encrypt(keys.p256dh, keys.auth, text.encode('kept across restarts'));
    expect(new TextDecoder().decode(await decrypt(again, data))).toBe('kept across restarts');
  });

  test('import refuses what is not exported keys', async () => {
    const keys = (await generateContentKeys()).export();

    await expect(importContentKeys({ ...keys, auth: 'AAAA' })).rejects.toThrow(TypeError);
    await expect(importContentKeys({ ...keys, privateKey: 'AAAA' })).rejects.toThrow();
  });
});

describe('decrypt', () => {
  test.each([
    ['empty', ''],
    ['short', 'hello'],
    ['a payload at the limit', 'x'.repeat(3993)],
  ])('opens what a sender encrypted: %s', async (_, plaintext) => {
    const keys = await generateContentKeys();
    const data = await encrypt(keys.p256dh, keys.auth, text.encode(plaintext));

    expect(new TextDecoder().decode(await decrypt(keys, data))).toBe(plaintext);
  });

  test.each<[string, string, (data: Uint8Array) => Promise<{ data: Uint8Array; keys?: ContentKeys }>]>([
    ['other keys', 'auth', async (data: Uint8Array) => ({ data, keys: await generateContentKeys() })],
    ['a flipped byte', 'auth', async (data: Uint8Array) => {
      const tampered = data.slice();
      tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
      return { data: tampered };
    }],
    ['a truncated header', 'malformed', async (data: Uint8Array) => ({ data: data.slice(0, 10) })],
    ['no sender key', 'malformed', async (data: Uint8Array) => {
      const broken = data.slice();
      broken[20] = 10;
      return { data: broken };
    }],
    ['a sender key off the curve', 'malformed', async (data: Uint8Array) => {
      const broken = data.slice();
      broken.fill(7, 21, 86);
      return { data: broken };
    }],
  ])('refuses %s with a typed error', async (_, reason, mutate) => {
    const keys = await generateContentKeys();
    const data = await encrypt(keys.p256dh, keys.auth, text.encode('secret'));
    const bad = await mutate(data);

    const error = await decrypt(bad.keys ?? keys, bad.data).catch((e: Error) => e);
    expect(error).toBeInstanceOf(DecryptError);
    expect(error instanceof DecryptError && error.reason).toBe(reason);
  });
});
