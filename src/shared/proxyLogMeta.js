export function parseProxyLogMetadata(rawMessage) {
  const clientMatch = rawMessage.match(/\[client:([^\]]+)\]/i);
  const sessionMatch = rawMessage.match(/\[session:([^\]]+)\]/i);
  const downstreamMatch = rawMessage.match(/\[downstream:([^\]]+)\]/i);
  const upstreamMatch = rawMessage.match(/\[upstream:([^\]]+)\]/i);
  const messageText = rawMessage.replace(
    /^\s*(?:\[(?:client|session|downstream|upstream):[^\]]+\]\s*)+/i,
    '',
  ).trim();

  return {
    clientKind: clientMatch?.[1]?.trim() || null,
    sessionId: sessionMatch?.[1]?.trim() || null,
    downstreamPath: downstreamMatch?.[1]?.trim() || null,
    upstreamPath: upstreamMatch?.[1]?.trim() || null,
    messageText,
  };
}
