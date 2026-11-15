/** Why the gateway refused a request (the protocol's RefusalCode), or UNAVAILABLE when it could not answer. */
export type RefusalCode = 'INVALID' | 'NOT_FOUND' | 'LIMIT' | 'UNAVAILABLE';

/** A subscribe or unsubscribe the gateway refused or could not serve. */
export class PushgateRefusedError extends Error {
  override readonly name = 'PushgateRefusedError';
  constructor(
    readonly code: RefusalCode,
    message: string,
  ) {
    super(message);
  }
}

/** A subscribe or unsubscribe without an answer within its deadline. */
export class PushgateTimeoutError extends Error {
  override readonly name = 'PushgateTimeoutError';
}

/** Why a message did not decrypt: malformed bytes, or keys or data that do not match. */
export type DecryptFailure = 'malformed' | 'auth';

/** A message that does not decrypt with the subscription's keys: drop it (and still acknowledge it). */
export class DecryptError extends Error {
  override readonly name = 'DecryptError';
  constructor(
    readonly reason: DecryptFailure,
    message: string,
  ) {
    super(message);
  }
}
