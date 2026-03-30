import { eq } from 'drizzle-orm';

import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';
import type { UpdateCenterVersionSource } from './updateCenterVersionService.js';

export type UpdateCenterConfig = {
  enabled: boolean;
  helperBaseUrl: string;
  namespace: string;
  releaseName: string;
  chartRef: string;
  imageRepository: string;
  githubReleasesEnabled: boolean;
  dockerHubTagsEnabled: boolean;
  defaultDeploySource: UpdateCenterVersionSource;
};

export const UPDATE_CENTER_CONFIG_SETTING_KEY = 'update_center_k3s_config_v1';

export function getDefaultUpdateCenterConfig(): UpdateCenterConfig {
  return {
    enabled: false,
    helperBaseUrl: '',
    namespace: 'default',
    releaseName: '',
    chartRef: '',
    imageRepository: '1467078763/metapi',
    githubReleasesEnabled: true,
    dockerHubTagsEnabled: true,
    defaultDeploySource: 'github-release',
  };
}

function normalizeString(value: unknown, fallback = ''): string {
  if (typeof value !== 'string') return fallback;
  return value.trim();
}

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function normalizeUpdateCenterConfig(input: unknown): UpdateCenterConfig {
  const defaults = getDefaultUpdateCenterConfig();
  const record = input && typeof input === 'object' ? input as Record<string, unknown> : {};
  const defaultDeploySource = record.defaultDeploySource === 'docker-hub-tag'
    ? 'docker-hub-tag'
    : 'github-release';

  return {
    enabled: normalizeBoolean(record.enabled, defaults.enabled),
    helperBaseUrl: normalizeString(record.helperBaseUrl, defaults.helperBaseUrl),
    namespace: normalizeString(record.namespace, defaults.namespace) || defaults.namespace,
    releaseName: normalizeString(record.releaseName, defaults.releaseName),
    chartRef: normalizeString(record.chartRef, defaults.chartRef),
    imageRepository: normalizeString(record.imageRepository, defaults.imageRepository) || defaults.imageRepository,
    githubReleasesEnabled: normalizeBoolean(record.githubReleasesEnabled, defaults.githubReleasesEnabled),
    dockerHubTagsEnabled: normalizeBoolean(record.dockerHubTagsEnabled, defaults.dockerHubTagsEnabled),
    defaultDeploySource,
  };
}

export async function loadUpdateCenterConfig(): Promise<UpdateCenterConfig> {
  const row = await db.select().from(schema.settings).where(eq(schema.settings.key, UPDATE_CENTER_CONFIG_SETTING_KEY)).get();
  if (!row?.value) {
    return getDefaultUpdateCenterConfig();
  }

  try {
    return normalizeUpdateCenterConfig(JSON.parse(row.value));
  } catch {
    return getDefaultUpdateCenterConfig();
  }
}

export async function saveUpdateCenterConfig(input: unknown): Promise<UpdateCenterConfig> {
  const next = normalizeUpdateCenterConfig(input);
  await upsertSetting(UPDATE_CENTER_CONFIG_SETTING_KEY, next);
  return next;
}
