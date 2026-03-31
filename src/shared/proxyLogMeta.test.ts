import { describe, expect, it } from 'vitest';

import { parseProxyLogMetadata } from './proxyLogMeta.js';

describe('proxyLogMeta', () => {
  it('parses all supported proxy log prefixes', () => {
    expect(parseProxyLogMetadata(
      '[client:codex] [session:turn-1] [downstream:/v1/responses] [upstream:/responses] [usage:self-log] boom',
    )).toEqual({
      clientKind: 'codex',
      sessionId: 'turn-1',
      downstreamPath: '/v1/responses',
      upstreamPath: '/responses',
      usageSource: 'self-log',
      messageText: 'boom',
    });
  });

  it('keeps plain message text when no metadata prefixes exist', () => {
    expect(parseProxyLogMetadata('network timeout')).toEqual({
      clientKind: null,
      sessionId: null,
      downstreamPath: null,
      upstreamPath: null,
      usageSource: null,
      messageText: 'network timeout',
    });
  });

  it('handles mixed-case, partial, reordered, and empty metadata safely', () => {
    expect(parseProxyLogMetadata('[CLIENT:codex] [SESSION:turn-1] boom')).toEqual({
      clientKind: 'codex',
      sessionId: 'turn-1',
      downstreamPath: null,
      upstreamPath: null,
      usageSource: null,
      messageText: 'boom',
    });

    expect(parseProxyLogMetadata('[client:codex] boom')).toEqual({
      clientKind: 'codex',
      sessionId: null,
      downstreamPath: null,
      upstreamPath: null,
      usageSource: null,
      messageText: 'boom',
    });

    expect(parseProxyLogMetadata('[upstream:/x] [client:codex] [session:1] msg')).toEqual({
      clientKind: 'codex',
      sessionId: '1',
      downstreamPath: null,
      upstreamPath: '/x',
      usageSource: null,
      messageText: 'msg',
    });

    expect(parseProxyLogMetadata('')).toEqual({
      clientKind: null,
      sessionId: null,
      downstreamPath: null,
      upstreamPath: null,
      usageSource: null,
      messageText: '',
    });
  });
});
