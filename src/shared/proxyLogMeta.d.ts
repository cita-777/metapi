export type ProxyLogUsageSource = 'upstream' | 'self-log' | 'unknown' | null;

export type ParsedProxyLogMetadata = {
  clientKind: string | null;
  sessionId: string | null;
  downstreamPath: string | null;
  upstreamPath: string | null;
  usageSource: ProxyLogUsageSource;
  messageText: string;
};

export declare function parseProxyLogMetadata(rawMessage: string): ParsedProxyLogMetadata;
