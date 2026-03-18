import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  startOAuthLoopbackCallbackServer,
  stopOAuthLoopbackCallbackServers,
} from './localCallbackServer.js';

describe('oauth loopback callback server', () => {
  afterEach(async () => {
    await stopOAuthLoopbackCallbackServers();
  });

  it('accepts codex oauth callback requests and closes the popup on success', async () => {
    const callbackHandler = vi.fn(async () => ({ accountId: 12, siteId: 34 }));
    const started = await startOAuthLoopbackCallbackServer('codex', {
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

  it('renders a stable error page when oauth completion fails', async () => {
    const callbackHandler = vi.fn(async () => {
      throw new Error('oauth failed');
    });
    const started = await startOAuthLoopbackCallbackServer('claude', {
      callbackHandler,
    });

    const response = await fetch(`${started.origin}/callback?state=test-state&code=test-code`);
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(body).toContain('OAuth authorization failed');
    expect(body).not.toContain('oauth failed');
  });
});
