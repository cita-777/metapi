import { eq } from 'drizzle-orm';

import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';
import type { UpdateCenterVersionSource } from './updateCenterVersionService.js';

export type UpdateCenterRuntimeState = {
  lastCheckedAt: string | null;
  lastCheckError: string | null;
  lastResolvedSource: UpdateCenterVersionSource | null;
  lastResolvedDisplayVersion: string | null;
  lastResolvedCandidateKey: string | null;
  lastNotifiedCandidateKey: string | null;
  lastNotifiedAt: string | null;
};

export const UPDATE_CENTER_RUNTIME_STATE_SETTING_KEY = 'update_center_runtime_state_v1';

export function getDefaultUpdateCenterRuntimeState(): UpdateCenterRuntimeState {
  return {
    lastCheckedAt: null,
    lastCheckError: null,
    lastResolvedSource: null,
    lastResolvedDisplayVersion: null,
    lastResolvedCandidateKey: null,
    lastNotifiedCandidateKey: null,
    lastNotifiedAt: null,
  };
}

function normalizeNullableString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function normalizeNullableSource(value: unknown): UpdateCenterVersionSource | null {
  return value === 'docker-hub-tag' || value === 'github-release' ? value : null;
}

export function normalizeUpdateCenterRuntimeState(input: unknown): UpdateCenterRuntimeState {
  const defaults = getDefaultUpdateCenterRuntimeState();
  const record = input && typeof input === 'object' ? input as Record<string, unknown> : {};
  return {
    lastCheckedAt: normalizeNullableString(record.lastCheckedAt) ?? defaults.lastCheckedAt,
    lastCheckError: normalizeNullableString(record.lastCheckError) ?? defaults.lastCheckError,
    lastResolvedSource: normalizeNullableSource(record.lastResolvedSource) ?? defaults.lastResolvedSource,
    lastResolvedDisplayVersion: normalizeNullableString(record.lastResolvedDisplayVersion) ?? defaults.lastResolvedDisplayVersion,
    lastResolvedCandidateKey: normalizeNullableString(record.lastResolvedCandidateKey) ?? defaults.lastResolvedCandidateKey,
    lastNotifiedCandidateKey: normalizeNullableString(record.lastNotifiedCandidateKey) ?? defaults.lastNotifiedCandidateKey,
    lastNotifiedAt: normalizeNullableString(record.lastNotifiedAt) ?? defaults.lastNotifiedAt,
  };
}

export async function loadUpdateCenterRuntimeState(): Promise<UpdateCenterRuntimeState> {
  const row = await db.select().from(schema.settings).where(eq(schema.settings.key, UPDATE_CENTER_RUNTIME_STATE_SETTING_KEY)).get();
  if (!row?.value) {
    return getDefaultUpdateCenterRuntimeState();
  }

  try {
    return normalizeUpdateCenterRuntimeState(JSON.parse(row.value));
  } catch {
    return getDefaultUpdateCenterRuntimeState();
  }
}

export async function saveUpdateCenterRuntimeState(input: unknown): Promise<UpdateCenterRuntimeState> {
  const next = normalizeUpdateCenterRuntimeState(input);
  await upsertSetting(UPDATE_CENTER_RUNTIME_STATE_SETTING_KEY, next);
  return next;
}
