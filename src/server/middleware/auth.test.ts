import { describe, expect, it } from 'vitest';
import { extractClientIp, isIpAllowed } from './auth.js';

describe('auth middleware IP helpers', () => {
  it('uses the socket peer and ignores forwarded headers when no proxy is trusted', () => {
    expect(extractClientIp('::ffff:10.0.0.1', '198.51.100.7, 203.0.113.2', [])).toBe('10.0.0.1');
    expect(extractClientIp('203.0.113.50', ['198.51.100.7'], [])).toBe('203.0.113.50');
  });

  it('ignores forwarded headers when the peer is not a trusted proxy', () => {
    expect(extractClientIp('203.0.113.50', '127.0.0.1', ['10.0.0.0/8'])).toBe('203.0.113.50');
    expect(isIpAllowed(extractClientIp('203.0.113.50', '127.0.0.1', ['10.0.0.0/8']), ['127.0.0.1'])).toBe(false);
  });

  it('resolves the nearest untrusted hop when the peer is a trusted proxy', () => {
    expect(extractClientIp('::ffff:10.0.0.1', '198.51.100.7', ['10.0.0.0/8'])).toBe('198.51.100.7');
    // Client-supplied entries left of the hop added by the trusted proxy are not believed.
    expect(extractClientIp('10.0.0.1', '127.0.0.1, 198.51.100.7', ['10.0.0.0/8'])).toBe('198.51.100.7');
    expect(extractClientIp('10.0.0.1', '198.51.100.7, 10.0.0.2', ['10.0.0.0/8'])).toBe('198.51.100.7');
    expect(extractClientIp('10.0.0.1', undefined, ['10.0.0.0/8'])).toBe('10.0.0.1');
    expect(extractClientIp('10.0.0.1', 'not-an-ip', ['10.0.0.0/8'])).toBe('10.0.0.1');
  });

  it('allows request when allowlist is empty', () => {
    expect(isIpAllowed('203.0.113.8', [])).toBe(true);
  });

  it('rejects non-allowlisted IP when allowlist is configured', () => {
    expect(isIpAllowed('203.0.113.8', ['203.0.113.9'])).toBe(false);
    expect(isIpAllowed('203.0.113.9', ['203.0.113.9'])).toBe(true);
  });

  it('matches ipv4 CIDR ranges in the allowlist', () => {
    expect(isIpAllowed('8.8.8.8', ['8.8.8.0/24'])).toBe(true);
    expect(isIpAllowed('8.8.9.8', ['8.8.8.0/24'])).toBe(false);
    expect(isIpAllowed('8.8.8.8', ['8.8.0.0/16'])).toBe(true);
  });

  it('ignores malformed CIDR entries instead of matching unexpectedly', () => {
    expect(isIpAllowed('8.8.8.8', ['8.8.8.0/99'])).toBe(false);
    expect(isIpAllowed('8.8.8.8', ['not-an-ip/24'])).toBe(false);
  });
});
