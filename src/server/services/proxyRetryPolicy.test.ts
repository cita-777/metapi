import { describe, expect, it } from 'vitest';
import { shouldRetryProxyRequest } from './proxyRetryPolicy.js';

describe('proxyRetryPolicy', () => {
  it('retries on rate limit and server errors', () => {
    expect(shouldRetryProxyRequest(429, 'rate limit')).toBe(true);
    expect(shouldRetryProxyRequest(500, 'internal error')).toBe(true);
    expect(shouldRetryProxyRequest(503, 'service unavailable')).toBe(true);
  });

  it('retries on model unsupported messages from upstream', () => {
    expect(
      shouldRetryProxyRequest(400, '{"error":"当前 API 不支持所选模型 claude-sonnet-4-5-20250929","type":"error"}'),
    ).toBe(true);
    expect(
      shouldRetryProxyRequest(400, '{"error":{"message":"unsupported model: claude-3"}}'),
    ).toBe(true);
    expect(
      shouldRetryProxyRequest(404, '{"error":{"message":"The model `gpt-4.1` does not exist"}}'),
    ).toBe(true);
  });

  it('does not retry obvious request-shape errors that will fail on every channel', () => {
    expect(
      shouldRetryProxyRequest(400, '{"error":{"message":"invalid request body"}}'),
    ).toBe(false);
    expect(
      shouldRetryProxyRequest(422, '{"error":{"message":"unprocessable"}}'),
    ).toBe(false);
    expect(
      shouldRetryProxyRequest(404, '{"error":{"message":"not found"}}'),
    ).toBe(false);
  });

  it('keeps retrying channel-local compatibility and auth failures', () => {
    expect(
      shouldRetryProxyRequest(401, '{"error":{"message":"invalid access token"}}'),
    ).toBe(true);
    expect(
      shouldRetryProxyRequest(403, '{"error":{"message":"forbidden"}}'),
    ).toBe(true);
    expect(
      shouldRetryProxyRequest(400, 'Unsupported legacy protocol: /v1/chat/completions is not supported. Please use /v1/responses.'),
    ).toBe(true);
  });

  it('does not retry client-side timeout validation errors', () => {
    expect(
      shouldRetryProxyRequest(400, '{"error":{"message":"timeout must be <= 60"}}'),
    ).toBe(false);
    expect(
      shouldRetryProxyRequest(400, '{"error":{"message":"invalid timeout parameter"}}'),
    ).toBe(false);
  });
});
