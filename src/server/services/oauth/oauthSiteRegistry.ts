import { and, eq, sql } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { listOAuthProviderDefinitions, type OAuthProviderDefinition } from './providers.js';

function isUniqueConstraintError(error: unknown): boolean {
  if (!error) return false;
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.toLowerCase();
  return normalized.includes('unique')
    || normalized.includes('duplicate')
    || normalized.includes('constraint failed');
}

async function getNextSiteSortOrder(): Promise<number> {
  const row = await db.select({
    maxSortOrder: sql<number>`COALESCE(MAX(${schema.sites.sortOrder}), -1)`,
  }).from(schema.sites).get();
  return (row?.maxSortOrder ?? -1) + 1;
}

export async function ensureOauthProviderSite(definition: OAuthProviderDefinition) {
  const existing = await db.select().from(schema.sites).where(and(
    eq(schema.sites.platform, definition.site.platform),
    eq(schema.sites.url, definition.site.url),
  )).get();
  if (existing) return existing;

  try {
    return await db.insert(schema.sites).values({
      name: definition.site.name,
      url: definition.site.url,
      platform: definition.site.platform,
      status: 'active',
      useSystemProxy: false,
      isPinned: false,
      globalWeight: 1,
      sortOrder: await getNextSiteSortOrder(),
    }).returning().get();
  } catch (error) {
    if (!isUniqueConstraintError(error)) throw error;
    const recovered = await db.select().from(schema.sites).where(and(
      eq(schema.sites.platform, definition.site.platform),
      eq(schema.sites.url, definition.site.url),
    )).get();
    if (recovered) return recovered;
    throw error;
  }
}

export async function ensureOauthProviderSitesExist(): Promise<void> {
  const definitions = listOAuthProviderDefinitions();
  for (const definition of definitions) {
    await ensureOauthProviderSite(definition);
  }
}
