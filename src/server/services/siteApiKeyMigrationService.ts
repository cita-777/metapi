import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { insertAndGetById } from '../db/insertHelpers.js';
import { getCredentialModeFromExtraConfig, mergeAccountExtraConfig } from './accountExtraConfig.js';

export type SiteApiKeyMigrationSummary = {
  migrated: number;
  deduped: number;
  clearedSites: number;
  removedMirrorTokens: number;
  warned: number;
};

function normalizeTokenValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isApiKeyConnection(account: typeof schema.accounts.$inferSelect): boolean {
  const explicit = getCredentialModeFromExtraConfig(account.extraConfig);
  if (explicit && explicit !== 'auto') return explicit === 'apikey';
  return normalizeTokenValue(account.accessToken).length === 0;
}

async function clearSiteApiKey(siteId: number) {
  await db.update(schema.sites)
    .set({
      apiKey: null,
      updatedAt: new Date().toISOString(),
    })
    .where(eq(schema.sites.id, siteId))
    .run();
}

export async function migrateSiteApiKeysToAccounts(): Promise<SiteApiKeyMigrationSummary> {
  const summary: SiteApiKeyMigrationSummary = {
    migrated: 0,
    deduped: 0,
    clearedSites: 0,
    removedMirrorTokens: 0,
    warned: 0,
  };

  const sites = await db.select().from(schema.sites).all();
  if (sites.length === 0) return summary;

  const accounts = await db.select().from(schema.accounts).all();
  let nextSortOrder = accounts.reduce((max, account) => Math.max(max, account.sortOrder || 0), -1) + 1;

  for (const site of sites) {
    const siteApiKey = normalizeTokenValue(site.apiKey);
    if (!siteApiKey) continue;

    let targetAccount = accounts.find((account) => (
      account.siteId === site.id
      && isApiKeyConnection(account)
      && normalizeTokenValue(account.apiToken) === siteApiKey
    )) || null;

    if (targetAccount) {
      summary.deduped += 1;
    } else {
      targetAccount = await insertAndGetById<typeof schema.accounts.$inferSelect>({
        table: schema.accounts,
        idColumn: schema.accounts.id,
        values: {
          siteId: site.id,
          username: null,
          accessToken: '',
          apiToken: siteApiKey,
          checkinEnabled: false,
          status: 'active',
          extraConfig: mergeAccountExtraConfig(undefined, { credentialMode: 'apikey' }),
          isPinned: false,
          sortOrder: nextSortOrder,
        },
        insertErrorMessage: 'failed to create migrated site account',
        loadErrorMessage: 'failed to create migrated site account',
      });
      accounts.push(targetAccount);
      nextSortOrder += 1;
      summary.migrated += 1;
    }

    if (targetAccount) {
      const childTokens = await db.select()
        .from(schema.accountTokens)
        .where(eq(schema.accountTokens.accountId, targetAccount.id))
        .all();

      if (childTokens.length === 1 && normalizeTokenValue(childTokens[0]?.token) === siteApiKey) {
        await db.delete(schema.accountTokens).where(eq(schema.accountTokens.id, childTokens[0]!.id)).run();
        summary.removedMirrorTokens += 1;
      } else if (childTokens.length > 1) {
        summary.warned += 1;
        console.warn(`Skipped destructive token cleanup for API key connection #${targetAccount.id}: found ${childTokens.length} child tokens`);
      }
    }

    await clearSiteApiKey(site.id);
    summary.clearedSites += 1;
  }

  return summary;
}
