import { parseProxyLogMetadata } from '../../../shared/proxyLogMeta.js';

type ProxyLogPathMeta = {
  clientFamily: string | null;
  sessionId: string | null;
  downstreamPath: string | null;
  upstreamPath: string | null;
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
    errorMessage: parsed.messageText,
  };
}
