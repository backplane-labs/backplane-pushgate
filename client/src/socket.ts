/** What the client needs of a WebSocket: text frames, a close, and its events. */
export interface WebSocketLike {
  /** Sends a text frame. */
  send(data: string): void;
  /** Closes the connection. */
  close(code?: number, reason?: string): void;
  /** Wires the socket's events; the client calls it once, right after the factory. */
  listen(events: SocketEvents): void;
}

/** The events a WebSocketLike reports. */
export interface SocketEvents {
  open(): void;
  /** A text frame; binary frames are not part of the protocol. */
  message(data: string): void;
  /** The connection closed, with the close code (1006 when none came). */
  close(code: number, reason: string): void;
  error(): void;
}

/** A factory of connections to url. */
export type WebSocketFactory = (url: string) => WebSocketLike;

/** The runtime's WebSocket (Node ≥ 22, Electron, browsers) as a WebSocketLike. */
export function nativeWebSocket(url: string): WebSocketLike {
  const socket = new WebSocket(url);

  return {
    send: (data) => socket.send(data),
    close: (code, reason) => socket.close(code, reason),
    listen(events) {
      socket.addEventListener('open', () => events.open());
      socket.addEventListener('message', (event) => {
        if (typeof event.data === 'string') events.message(event.data);
      });
      socket.addEventListener('close', (event) => events.close(event.code, event.reason));
      socket.addEventListener('error', () => events.error());
    },
  };
}
