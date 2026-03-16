import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  startCodexLoopbackCallbackServer,
  stopCodexLoopbackCallbackServer,
} from './localCallbackServer.js';

describe('codex loopback callback server', () => {
  afterEach(async () => {
    await stopCodexLoopbackCallbackServer();
  });

  it('accepts oauth callback requests and closes the popup on success', async () => {
    const callbackHandler = vi.fn(async () => ({ accountId: 12, siteId: 34 }));
    const started = await startCodexLoopbackCallbackServer({
      host: '127.0.0.1',
      port: 0,
      callbackHandler,
    });

    const response = await fetch(`${started.origin}/auth/callback?state=test-state&code=test-code`);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(callbackHandler).toHaveBeenCalledWith({
      provider: 'codex',
      state: 'test-state',
      code: 'test-code',
      error: undefined,
    });
    expect(body).toContain('window.close()');
  });

  it('renders an error page when oauth completion fails', async () => {
    const callbackHandler = vi.fn(async () => {
      throw new Error('oauth failed');
    });
    const started = await startCodexLoopbackCallbackServer({
      host: '127.0.0.1',
      port: 0,
      callbackHandler,
    });

    const response = await fetch(`${started.origin}/auth/callback?state=test-state&code=test-code`);
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(body).toContain('oauth failed');
  });
});
