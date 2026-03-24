import { parseProxyLogMetadata, type ParsedProxyLogMetadata } from '../../../shared/proxyLogMeta.js';

type ComposeProxyLogMessageArgs = {
  clientKind?: string | null;
  sessionId?: string | null;
  traceHint?: string | null;
  downstreamPath?: string | null;
  upstreamPath?: string | null;
  errorMessage?: string | null;
};

export type ParsedProxyLogMessageMeta = ParsedProxyLogMetadata;

export function parseProxyLogMessageMeta(rawMessage: string): ParsedProxyLogMessageMeta {
  return parseProxyLogMetadata(rawMessage);
}

export function composeProxyLogMessage({
  clientKind,
  sessionId,
  traceHint,
  downstreamPath,
  upstreamPath,
  errorMessage,
}: ComposeProxyLogMessageArgs): string | null {
  const rawMessage = typeof errorMessage === 'string' ? errorMessage.trim() : '';
  const parsed = parseProxyLogMessageMeta(rawMessage);
  const finalClientKind = (clientKind || parsed.clientKind || '').trim();
  const finalSessionId = (sessionId || traceHint || parsed.sessionId || '').trim();
  const finalDownstreamPath = (downstreamPath || parsed.downstreamPath || '').trim();
  const finalUpstreamPath = (upstreamPath || parsed.upstreamPath || '').trim();
  const finalMessageText = parsed.messageText.trim();

  const prefixParts: string[] = [];
  if (finalClientKind) prefixParts.push(`[client:${finalClientKind}]`);
  if (finalSessionId) prefixParts.push(`[session:${finalSessionId}]`);
  if (finalDownstreamPath) prefixParts.push(`[downstream:${finalDownstreamPath}]`);
  if (finalUpstreamPath) prefixParts.push(`[upstream:${finalUpstreamPath}]`);

  if (prefixParts.length === 0 && !finalMessageText) return null;
  if (finalMessageText) return `${prefixParts.join(' ')} ${finalMessageText}`.trim();
  return prefixParts.join(' ');
}
