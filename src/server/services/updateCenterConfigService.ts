import { eq } from 'drizzle-orm';

import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';

/**
 * The update center deliberately has a very small persisted configuration.
 * Release discovery is always performed against the Metapi GitHub repository;
 * callers cannot configure an arbitrary URL or deployment backend.
 */
export type UpdateCenterChannel = 'stable';

export type UpdateCenterConfig = {
  enabled: boolean;
  channel: UpdateCenterChannel;
  autoCheck: boolean;
};

/** Current configuration key. The legacy deployment key is read-only compatibility data. */
export const UPDATE_CENTER_CONFIG_SETTING_KEY = 'update_center_config_v2';
export const UPDATE_CENTER_CONFIG_V2_SETTING_KEY = UPDATE_CENTER_CONFIG_SETTING_KEY;
export const LEGACY_UPDATE_CENTER_CONFIG_SETTING_KEY = 'update_center_k3s_config_v1';

export function getDefaultUpdateCenterConfig(): UpdateCenterConfig {
  return {
    enabled: false,
    channel: 'stable',
    autoCheck: false,
  };
}

function asRecord(input: unknown): Record<string, unknown> {
  return input && typeof input === 'object' && !Array.isArray(input)
    ? input as Record<string, unknown>
    : {};
}

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * Normalize only the public v2 shape.  Unknown legacy deployment fields are
 * intentionally ignored so they cannot accidentally re-enable removed deployment behavior.
 */
export function normalizeUpdateCenterConfig(input: unknown): UpdateCenterConfig {
  const defaults = getDefaultUpdateCenterConfig();
  const record = asRecord(input);
  return {
    enabled: normalizeBoolean(record.enabled, defaults.enabled),
    channel: record.channel === 'stable' ? 'stable' : defaults.channel,
    autoCheck: normalizeBoolean(record.autoCheck, defaults.autoCheck),
  };
}

function migrateLegacyConfig(input: unknown): UpdateCenterConfig {
  const defaults = getDefaultUpdateCenterConfig();
  const record = asRecord(input);
  // Keep the user's release-check preference, but never inherit enabled=true
  // from the removed external deployment path.
  return {
    enabled: false,
    channel: 'stable',
    autoCheck: normalizeBoolean(record.githubReleasesEnabled, defaults.autoCheck),
  };
}

async function readSetting(key: string): Promise<unknown | null> {
  const row = await db.select().from(schema.settings).where(eq(schema.settings.key, key)).get();
  if (!row?.value) return null;
  try {
    return JSON.parse(row.value);
  } catch {
    return null;
  }
}

export async function loadUpdateCenterConfig(): Promise<UpdateCenterConfig> {
  const current = await readSetting(UPDATE_CENTER_CONFIG_SETTING_KEY);
  if (current !== null) return normalizeUpdateCenterConfig(current);

  const legacy = await readSetting(LEGACY_UPDATE_CENTER_CONFIG_SETTING_KEY);
  if (legacy !== null) return migrateLegacyConfig(legacy);

  return getDefaultUpdateCenterConfig();
}

export async function saveUpdateCenterConfig(input: unknown): Promise<UpdateCenterConfig> {
  const next = normalizeUpdateCenterConfig(input);
  await upsertSetting(UPDATE_CENTER_CONFIG_SETTING_KEY, next);
  return next;
}
