export type ParsedProxyLogMetadata = {
  clientKind: string | null;
  sessionId: string | null;
  downstreamPath: string | null;
  upstreamPath: string | null;
  messageText: string;
};

export declare function parseProxyLogMetadata(rawMessage: string): ParsedProxyLogMetadata;
