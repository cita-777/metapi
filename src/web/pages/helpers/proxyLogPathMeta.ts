import { parseProxyLogMetadata, type ParsedProxyLogMetadata } from '../../../shared/proxyLogMeta.js';

type ProxyLogPathMeta = {
  clientFamily: string | null;
  sessionId: string | null;
  downstreamPath: string | null;
  upstreamPath: string | null;
  usageSource: ParsedProxyLogMetadata['usageSource'];
  errorMessage: string;
};

export function parseProxyLogPathMeta(message?: string): ProxyLogPathMeta {
  const raw = typeof message === 'string' ? message.trim() : '';
  const parsed = parseProxyLogMetadata(raw);

  return {
    clientFamily: parsed.clientKind,
    sessionId: parsed.sessionId,
    downstreamPath: parsed.downstreamPath,
    upstreamPath: parsed.upstreamPath,
    usageSource: parsed.usageSource,
    errorMessage: parsed.messageText,
  };
}
