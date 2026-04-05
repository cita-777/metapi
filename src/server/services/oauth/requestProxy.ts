import { eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { getOAuthProviderDefinition } from './providers.js';
import { resolveProxyUrlFromExtraConfig } from '../accountExtraConfig.js';
import { resolveSiteProxyUrlByRequestUrl } from '../siteProxy.js';

export async function resolveOauthProviderProxyUrl(provider: string): Promise<string | null> {
  const definition = getOAuthProviderDefinition(provider);
  if (!definition) return null;
  return resolveSiteProxyUrlByRequestUrl(definition.site.url);
}

export async function resolveOauthAccountProxyUrl(input: {
  siteId?: number | null;
  extraConfig?: string | null;
}): Promise<string | null> {
  const accountProxyUrl = resolveProxyUrlFromExtraConfig(input.extraConfig);
  if (accountProxyUrl) return accountProxyUrl;
  if (!input.siteId || input.siteId <= 0) return null;
  const site = await db.select({
    url: schema.sites.url,
  }).from(schema.sites).where(eq(schema.sites.id, input.siteId)).get();
  if (!site?.url) return null;
  return resolveSiteProxyUrlByRequestUrl(site.url);
}
