import { eq, isNotNull, isNull, or } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { buildOauthIdentityBackfillPatch } from './oauthAccount.js';

let inFlightOauthIdentityBackfill: Promise<number> | null = null;

async function runOauthIdentityBackfill(): Promise<number> {
  const rows = await db.select().from(schema.accounts)
    .where(or(
      isNotNull(schema.accounts.extraConfig),
      isNull(schema.accounts.oauthProvider),
    ))
    .all();

  let updated = 0;
  for (const row of rows) {
    const patch = buildOauthIdentityBackfillPatch(row);
    if (!patch) continue;
    await db.update(schema.accounts).set({
      ...patch,
      updatedAt: new Date().toISOString(),
    }).where(eq(schema.accounts.id, row.id)).run();
    updated += 1;
  }

  return updated;
}

export async function ensureOauthIdentityBackfill(): Promise<number> {
  if (inFlightOauthIdentityBackfill) {
    return inFlightOauthIdentityBackfill;
  }

  inFlightOauthIdentityBackfill = (async () => {
    try {
      return await runOauthIdentityBackfill();
    } finally {
      inFlightOauthIdentityBackfill = null;
    }
  })();

  return inFlightOauthIdentityBackfill;
}
