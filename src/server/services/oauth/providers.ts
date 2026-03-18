import { codexOauthProvider } from './codexProvider.js';
import { claudeOauthProvider } from './claudeProvider.js';
import { geminiCliOauthProvider } from './geminiCliProvider.js';
import { antigravityOauthProvider } from './antigravityProvider.js';

export type OAuthProviderId = 'codex' | 'claude' | 'gemini-cli' | 'antigravity';

export type OAuthProviderMetadata = {
  provider: OAuthProviderId;
  label: string;
  platform: string;
  enabled: boolean;
  loginType: 'oauth';
  requiresProjectId: boolean;
  supportsDirectAccountRouting: boolean;
  supportsCloudValidation: boolean;
  supportsNativeProxy: boolean;
};

export type OAuthProviderExchangeResult = {
  accessToken: string;
  refreshToken?: string;
  tokenExpiresAt?: number;
  email?: string;
  accountKey?: string;
  accountId?: string;
  planType?: string;
  projectId?: string;
  idToken?: string;
  providerData?: Record<string, unknown>;
};

export type OAuthProviderRefreshResult = OAuthProviderExchangeResult;

export type OAuthProviderProxyHeaderInput = {
  oauth: {
    provider: string;
    accountKey?: string;
    accountId?: string;
    projectId?: string;
    providerData?: Record<string, unknown>;
  };
  downstreamHeaders?: Record<string, unknown>;
};

export interface OAuthProviderDefinition {
  metadata: OAuthProviderMetadata;
  site: {
    name: string;
    url: string;
    platform: string;
  };
  loopback: {
    host: string;
    port: number;
    path: string;
    redirectUri: string;
  };
  buildAuthorizationUrl(input: {
    state: string;
    redirectUri: string;
    codeVerifier: string;
    projectId?: string;
  }): Promise<string>;
  resolveRedirectUri?(input: {
    requestOrigin?: string;
  }): string;
  exchangeAuthorizationCode(input: {
    code: string;
    state: string;
    redirectUri: string;
    codeVerifier: string;
    projectId?: string;
  }): Promise<OAuthProviderExchangeResult>;
  refreshAccessToken(input: {
    refreshToken: string;
    oauth?: {
      projectId?: string;
      providerData?: Record<string, unknown>;
    };
  }): Promise<OAuthProviderRefreshResult>;
  buildProxyHeaders?(input: OAuthProviderProxyHeaderInput): Record<string, string>;
}

const PROVIDERS: OAuthProviderDefinition[] = [
  codexOauthProvider,
  claudeOauthProvider,
  geminiCliOauthProvider,
  antigravityOauthProvider,
];

const PROVIDER_BY_ID = new Map(PROVIDERS.map((provider) => [provider.metadata.provider, provider] as const));

export function listOAuthProviderDefinitions(): OAuthProviderDefinition[] {
  return PROVIDERS.slice();
}

export function getOAuthProviderDefinition(provider: string): OAuthProviderDefinition | undefined {
  return PROVIDER_BY_ID.get(provider as OAuthProviderId);
}
