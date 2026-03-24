export type CliProfileId =
  | 'generic'
  | 'codex'
  | 'claude_code'
  | 'gemini_cli';

export type CliProfileCapabilities = {
  supportsResponsesCompact: boolean;
  supportsResponsesWebsocketIncremental: boolean;
  preservesContinuation: boolean;
  supportsCountTokens: boolean;
  echoesTurnState: boolean;
};

export type CliProfileClientConfidence = 'exact' | 'heuristic';

export type DetectCliProfileInput = {
  downstreamPath: string;
  headers?: Record<string, unknown>;
  body?: unknown;
};

export type DetectedCliProfile = {
  id: CliProfileId;
  sessionId?: string;
  traceHint?: string;
  clientAppId?: string;
  clientAppName?: string;
  clientConfidence?: CliProfileClientConfidence;
  capabilities: CliProfileCapabilities;
};

export type CliProfileDefinition = {
  id: CliProfileId;
  capabilities: CliProfileCapabilities;
  detect(input: DetectCliProfileInput): Omit<DetectedCliProfile, 'capabilities'> | null;
};
