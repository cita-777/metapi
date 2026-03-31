import { eq } from 'drizzle-orm';

import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';
import type { UpdateCenterHelperStatus } from './updateCenterHelperClient.js';
import type { UpdateCenterVersionCandidate, UpdateCenterVersionSource } from './updateCenterVersionService.js';

export type UpdateCenterStatusSnapshot = {
  githubRelease: UpdateCenterVersionCandidate | null;
  dockerHubTag: UpdateCenterVersionCandidate | null;
  helper: UpdateCenterHelperStatus | null;
};

export type UpdateCenterRuntimeState = {
  lastCheckedAt: string | null;
  lastCheckError: string | null;
  lastResolvedSource: UpdateCenterVersionSource | null;
  lastResolvedDisplayVersion: string | null;
  lastResolvedCandidateKey: string | null;
  lastNotifiedCandidateKey: string | null;
  lastNotifiedAt: string | null;
  statusSnapshot: UpdateCenterStatusSnapshot | null;
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
    statusSnapshot: null,
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

function normalizeVersionCandidate(input: unknown): UpdateCenterVersionCandidate | null {
  if (!input || typeof input !== 'object') return null;
  const record = input as Record<string, unknown>;
  const source = normalizeNullableSource(record.source);
  const rawVersion = normalizeNullableString(record.rawVersion);
  const normalizedVersion = normalizeNullableString(record.normalizedVersion);
  if (!source || !rawVersion || !normalizedVersion) return null;
  return {
    source,
    rawVersion,
    normalizedVersion,
    url: normalizeNullableString(record.url),
    tagName: normalizeNullableString(record.tagName),
    digest: normalizeNullableString(record.digest),
    displayVersion: normalizeNullableString(record.displayVersion),
    publishedAt: normalizeNullableString(record.publishedAt),
  };
}

function normalizeHelperHistoryEntry(input: unknown): NonNullable<UpdateCenterHelperStatus['history']>[number] | null {
  if (!input || typeof input !== 'object') return null;
  const record = input as Record<string, unknown>;
  const revision = normalizeNullableString(record.revision);
  if (!revision) return null;
  return {
    revision,
    updatedAt: normalizeNullableString(record.updatedAt),
    status: normalizeNullableString(record.status),
    description: normalizeNullableString(record.description),
    imageRepository: normalizeNullableString(record.imageRepository),
    imageTag: normalizeNullableString(record.imageTag),
    imageDigest: normalizeNullableString(record.imageDigest),
  };
}

function normalizeHelperSnapshot(input: unknown): UpdateCenterHelperStatus | null {
  if (!input || typeof input !== 'object') return null;
  const record = input as Record<string, unknown>;
  return {
    ok: typeof record.ok === 'boolean' ? record.ok : false,
    releaseName: normalizeNullableString(record.releaseName),
    namespace: normalizeNullableString(record.namespace),
    revision: normalizeNullableString(record.revision),
    imageRepository: normalizeNullableString(record.imageRepository),
    imageTag: normalizeNullableString(record.imageTag),
    imageDigest: normalizeNullableString(record.imageDigest),
    healthy: typeof record.healthy === 'boolean' ? record.healthy : false,
    error: normalizeNullableString(record.error) || undefined,
    history: Array.isArray(record.history)
      ? record.history
        .map((entry) => normalizeHelperHistoryEntry(entry))
        .filter((entry): entry is NonNullable<UpdateCenterHelperStatus['history']>[number] => !!entry)
      : [],
  };
}

function normalizeStatusSnapshot(input: unknown): UpdateCenterStatusSnapshot | null {
  if (!input || typeof input !== 'object') return null;
  const record = input as Record<string, unknown>;
  return {
    githubRelease: normalizeVersionCandidate(record.githubRelease),
    dockerHubTag: normalizeVersionCandidate(record.dockerHubTag),
    helper: normalizeHelperSnapshot(record.helper),
  };
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
    statusSnapshot: Object.prototype.hasOwnProperty.call(record, 'statusSnapshot')
      ? normalizeStatusSnapshot(record.statusSnapshot)
      : defaults.statusSnapshot,
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
