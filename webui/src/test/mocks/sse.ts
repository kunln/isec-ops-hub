/**
 * SSE (EventSource) mock utilities for tests.
 *
 * Provides a controllable fake EventSource so hooks that use SSE
 * can be tested without a real HTTP server.
 *
 * @example
 * import { setupSSEMock } from '@/test/mocks/sse';
 *
 * describe('useSSE', () => {
 *   const sse = setupSSEMock();
 *
 *   it('calls onEvent when a message arrives', () => {
 *     // render hook ...
 *     sse.open();
 *     sse.send({ type: 'ping', properties: {} });
 *     // assert ...
 *   });
 * });
 */

import { vi, beforeEach, afterEach } from 'vitest';

export interface SSEMockControls {
  /** Simulate the connection opening successfully. */
  open: () => void;
  /** Dispatch a parsed-data message. */
  send: (data: unknown) => void;
  /** Simulate a connection error. */
  error: () => void;
  /** Return the URL the most recent EventSource was created with. */
  url: () => string;
  /** Return current readyState of the most recent instance. */
  readyState: () => number;
}

/**
 * Install a global EventSource mock before each test and restore afterwards.
 *
 * Call this at the top of a describe block; it returns controls to drive the
 * fake SSE stream from within individual tests.
 */
export function setupSSEMock(): SSEMockControls {
  let lastInstance: any = null;

  class FakeEventSource {
    url: string;
    readyState = 0; // CONNECTING
    onopen: ((e: Event) => void) | null = null;
    onmessage: ((e: MessageEvent) => void) | null = null;
    onerror: ((e: Event) => void) | null = null;

    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;

    constructor(url: string) {
      this.url = url;
      lastInstance = this;
    }

    close() {
      this.readyState = FakeEventSource.CLOSED;
    }

    addEventListener() {}
    removeEventListener() {}
    dispatchEvent() { return true; }
  }

  beforeEach(() => {
    lastInstance = null;
    vi.stubGlobal('EventSource', FakeEventSource);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  return {
    open() {
      if (!lastInstance) return;
      lastInstance.readyState = FakeEventSource.OPEN;
      lastInstance.onopen?.(new Event('open'));
    },

    send(data: unknown) {
      if (!lastInstance) return;
      lastInstance.onmessage?.(
        new MessageEvent('message', { data: JSON.stringify(data) }),
      );
    },

    error() {
      if (!lastInstance) return;
      lastInstance.onerror?.(new Event('error'));
    },

    url() {
      return lastInstance?.url ?? '';
    },

    readyState() {
      return lastInstance?.readyState ?? -1;
    },
  };
}
