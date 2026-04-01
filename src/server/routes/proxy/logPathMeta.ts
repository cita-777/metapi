import {
  parseProxyLogMetadata,
  type ParsedProxyLogMetadata,
  type ProxyLogUsageSource,
} from '../../../shared/proxyLogMeta.js';

type ComposeProxyLogMessageArgs = {
  clientKind?: string | null;
  sessionId?: string | null;
  traceHint?: string | null;
  downstreamPath?: string | null;
  upstreamPath?: string | null;
  usageSource?: ProxyLogUsageSource;
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
  usageSource,
  errorMessage,
}: ComposeProxyLogMessageArgs): string | null {
  const rawMessage = typeof errorMessage === 'string' ? errorMessage.trim() : '';
  const parsed = parseProxyLogMessageMeta(rawMessage);
  const finalClientKind = (clientKind || parsed.clientKind || '').trim();
  const finalSessionId = (sessionId || traceHint || parsed.sessionId || '').trim();
  const finalDownstreamPath = (downstreamPath || parsed.downstreamPath || '').trim();
  const finalUpstreamPath = (upstreamPath || parsed.upstreamPath || '').trim();
  const finalUsageSource = (usageSource || parsed.usageSource || '').trim();
  const finalMessageText = parsed.messageText.trim();

  const prefixParts: string[] = [];
  if (finalClientKind) prefixParts.push(`[client:${finalClientKind}]`);
  if (finalSessionId) prefixParts.push(`[session:${finalSessionId}]`);
  if (finalDownstreamPath) prefixParts.push(`[downstream:${finalDownstreamPath}]`);
  if (finalUpstreamPath) prefixParts.push(`[upstream:${finalUpstreamPath}]`);
  if (finalUsageSource) prefixParts.push(`[usage:${finalUsageSource}]`);

  if (prefixParts.length === 0 && !finalMessageText) return null;
  if (finalMessageText) return `${prefixParts.join(' ')} ${finalMessageText}`.trim();
  return prefixParts.join(' ');
}
