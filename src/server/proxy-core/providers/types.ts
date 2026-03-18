export type ProviderProfileId =
  | 'codex'
  | 'claude'
  | 'gemini-cli'
  | 'antigravity';

export type ProviderEndpoint =
  | 'chat'
  | 'messages'
  | 'responses';

export type ProviderAction =
  | 'generateContent'
  | 'streamGenerateContent'
  | 'countTokens';

export type ProviderRuntimeDescriptor = {
  executor: 'default' | 'codex' | 'gemini-cli' | 'antigravity' | 'claude';
  modelName?: string;
  stream?: boolean;
  oauthProjectId?: string | null;
  action?: ProviderAction;
};

export type PreparedProviderRequest = {
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  runtime: ProviderRuntimeDescriptor;
};

export type PrepareProviderRequestInput = {
  endpoint: ProviderEndpoint;
  modelName: string;
  stream: boolean;
  tokenValue: string;
  oauthProvider?: string;
  oauthProjectId?: string;
  sitePlatform?: string;
  baseHeaders: Record<string, string>;
  providerHeaders?: Record<string, string>;
  claudeHeaders?: Record<string, string>;
  codexSessionCacheKey?: string | null;
  codexExplicitSessionId?: string | null;
  body: Record<string, unknown>;
  action?: ProviderAction;
};

export type ProviderProfile = {
  id: ProviderProfileId;
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest;
};
