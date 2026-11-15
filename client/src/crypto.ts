import type { webcrypto } from 'node:crypto';

import { DecryptError } from './errors.js';

type CryptoKey = webcrypto.CryptoKey;

// RFC 8291 (message encryption for Web Push) over RFC 8188 (aes128gcm), on WebCrypto.

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

const SALT = 16;
const HEADER = SALT + 4 + 1; // salt, record size, key id length
const AUTH = 16;
const POINT = 65; // an uncompressed P-256 point
const LAST_RECORD = 2; // the last record's padding delimiter
const RECORD_SIZE = 4096;

/** A subscription's content keys exported as plain JSON (base64url strings), to persist and import again. */
export interface ExportedContentKeys {
  /** The P-256 public key, base64url of the uncompressed point. */
  readonly p256dh: string;
  /** The 16-byte auth secret, base64url. */
  readonly auth: string;
  /** The P-256 private key, base64url of its PKCS #8 encoding. */
  readonly privateKey: string;
}

/** A subscription's content keys (RFC 8291): give `p256dh` and `auth` with the endpoint to the sender. */
export interface ContentKeys {
  readonly p256dh: string;
  readonly auth: string;
  /** The keys as plain JSON to persist. */
  export(): ExportedContentKeys;
}

/** ContentKeys with what decrypt needs. */
class Keys implements ContentKeys {
  readonly p256dh: string;
  readonly auth: string;

  constructor(
    readonly privateKey: CryptoKey,
    readonly publicRaw: Uint8Array,
    readonly authRaw: Uint8Array,
    private readonly pkcs8: Uint8Array,
  ) {
    this.p256dh = base64url(publicRaw);
    this.auth = base64url(authRaw);
  }

  export(): ExportedContentKeys {
    return { p256dh: this.p256dh, auth: this.auth, privateKey: base64url(this.pkcs8) };
  }
}

/** Fresh content keys for one subscription. */
export async function generateContentKeys(): Promise<ContentKeys> {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));

  return new Keys(pair.privateKey, publicRaw, globalThis.crypto.getRandomValues(new Uint8Array(AUTH)), pkcs8);
}

/** Content keys from their export. */
export async function importContentKeys(e: ExportedContentKeys): Promise<ContentKeys> {
  const pkcs8 = fromBase64url(e.privateKey);
  const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const publicRaw = fromBase64url(e.p256dh);
  const authRaw = fromBase64url(e.auth);
  if (publicRaw.length !== POINT || authRaw.length !== AUTH) throw new TypeError('pushgate: not exported content keys');

  return new Keys(privateKey, publicRaw, authRaw, pkcs8);
}

/** Opens an aes128gcm message (RFC 8291: one record) with the subscription's keys. */
export async function decrypt(keys: ContentKeys, data: Uint8Array): Promise<Uint8Array> {
  if (!(keys instanceof Keys))
    throw new TypeError('pushgate: keys must come from generateContentKeys or importContentKeys');
  if (data.length < HEADER) throw new DecryptError('malformed', 'shorter than the aes128gcm header');

  const salt = data.subarray(0, SALT);
  const idLength = data[HEADER - 1] ?? 0;
  if (idLength !== POINT || data.length < HEADER + idLength)
    throw new DecryptError('malformed', 'no sender key in the header');

  const senderRaw = data.subarray(HEADER, HEADER + idLength);

  let senderKey: CryptoKey;
  try {
    senderKey = await subtle.importKey('raw', senderRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } catch {
    throw new DecryptError('malformed', 'the sender key is not a P-256 point');
  }

  const { key, nonce } = await contentKey(
    new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: senderKey }, keys.privateKey, 256)),
    keys.authRaw,
    keys.publicRaw,
    senderRaw,
    salt,
  );

  let plain: Uint8Array;
  try {
    plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, data.subarray(HEADER + idLength)));
  } catch {
    throw new DecryptError('auth', 'the message does not open with these keys');
  }

  let end = plain.length;
  while (end > 0 && plain[end - 1] === 0) end--;
  if (end === 0 || plain[end - 1] !== LAST_RECORD) throw new DecryptError('auth', 'no last-record delimiter');

  return plain.slice(0, end - 1);
}

/** Encrypts plaintext to a subscription's p256dh and auth (RFC 8291), as a sender does. */
export async function encrypt(p256dh: string, auth: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const receiverRaw = fromBase64url(p256dh);
  const receiver = await subtle.importKey('raw', receiverRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const senderRaw = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey));
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT));

  const { key, nonce } = await contentKey(
    new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: receiver }, ephemeral.privateKey, 256)),
    fromBase64url(auth),
    receiverRaw,
    senderRaw,
    salt,
  );

  const padded = new Uint8Array(plaintext.length + 1);
  padded.set(plaintext);
  padded[plaintext.length] = LAST_RECORD;

  const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, padded));
  const out = new Uint8Array(HEADER + POINT + sealed.length);
  out.set(salt);
  new DataView(out.buffer).setUint32(SALT, RECORD_SIZE);
  out[HEADER - 1] = POINT;
  out.set(senderRaw, HEADER);
  out.set(sealed, HEADER + POINT);

  return out;
}

/** The record's AES-128-GCM key and nonce (RFC 8291 3.4, RFC 8188 2.2). */
async function contentKey(
  shared: Uint8Array,
  auth: Uint8Array,
  receiver: Uint8Array,
  sender: Uint8Array,
  salt: Uint8Array,
): Promise<{ key: CryptoKey; nonce: Uint8Array }> {
  const ikm = await hkdf(shared, auth, concat(encoder.encode('WebPush: info\0'), receiver, sender), 32);
  const cek = await hkdf(ikm, salt, encoder.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(ikm, salt, encoder.encode('Content-Encoding: nonce\0'), 12);

  return { key: await subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt', 'decrypt']), nonce };
}

async function hkdf(secret: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const key = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);

  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }

  return out;
}

/** base64url without padding. */
export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Bytes of base64url (padding tolerated). */
export function fromBase64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
