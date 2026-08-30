import { and, eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  ACCOUNT_TOKEN_VALUE_STATUS_READY,
  isUsableAccountToken,
} from './accountTokenService.js';
import { clearRouteDecisionSnapshot, clearRouteDecisionSnapshots } from './routeDecisionSnapshotStore.js';
import { invalidateTokenRouterCache, matchesModelPattern, normalizeModelAlias } from './tokenRouter.js';
import { normalizeTokenRouteMode } from '../../shared/tokenRouteContract.js';
import { isExactTokenRouteModelPattern } from '../../shared/tokenRoutePatterns.js';
import { upsertSetting } from '../db/upsertSetting.js';

type DbExecutor = Pick<typeof db, 'select' | 'insert' | 'delete'>;

const MODEL_EXCLUSIONS_SETTING_KEY = 'token_route_deleted_model_exclusions_v1';

type PatternRouteChannelCandidate = {
  tokenId: number | null;
  accountId: number;
  oauthRouteUnitId: number | null;
  sourceModel: string;
  priority: number;
  weight: number;
  enabled: boolean;
};

export type PatternRouteChannelSyncResult = {
  rebuiltRoutes: number;
  routeIds: number[];
  removedChannels: number;
  createdChannels: number;
};

export type RebuildPatternRouteOptions = {
  excludeExactModelPatterns?: string[];
  includeModelPatterns?: string[];
  /**
   * Restrict availability-backed candidates to the models that survived the
   * normal model rebuild filters (whitelist, site disables, and brand rules).
   * `undefined` means no restriction; an empty array intentionally allows no
   * availability-backed candidates.
  */
  allowedModelNames?: string[];
  /**
   * Restrict token-availability candidates to the exact account/token/model
   * tuples that survived the model rebuild filters. This preserves
   * per-site filtering when another site still exposes the same model.
   */
  allowedAvailabilityCandidateKeys?: string[];
};

type PatternRouteChannelAffectedRouteSnapshot = {
  modelPattern: string;
  routeMode?: string | null;
  enabled?: boolean | null;
};

type SyncPatternRouteChannelsAfterAffectedRouteChangesInput = {
  affectedRouteIds?: number[];
  removedRoutes?: PatternRouteChannelAffectedRouteSnapshot[];
  allowedModelNames?: string[];
  allowedAvailabilityCandidateKeys?: string[];
  rebuildAllPatternRoutes?: boolean;
};

// Route mutations can arrive concurrently from separate requests.  Keep the
// read/modify/write of the persisted exclusion set and the corresponding
// pattern replacement together so one deletion cannot overwrite another.
let patternRouteMutationTail: Promise<void> = Promise.resolve();

async function withPatternRouteMutation<T>(operation: () => Promise<T>): Promise<T> {
  const previous = patternRouteMutationTail;
  let release!: () => void;
  patternRouteMutationTail = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    return await operation();
  } finally {
    release();
  }
}

type RouteModeModelPattern = {
  modelPattern: string;
  routeMode?: string | null;
};

function isPatternGroupRoute(route: RouteModeModelPattern): boolean {
  return normalizeTokenRouteMode(route.routeMode) !== 'explicit_group'
    && !isExactTokenRouteModelPattern(route.modelPattern);
}

function isExactSourceRoute(route: RouteModeModelPattern): boolean {
  return normalizeTokenRouteMode(route.routeMode) !== 'explicit_group'
    && isExactTokenRouteModelPattern(route.modelPattern);
}

function normalizeAffectedRouteIds(routeIds: number[] | undefined): number[] {
  const normalized: number[] = [];
  for (const rawRouteId of routeIds || []) {
    const routeId = Math.trunc(Number(rawRouteId));
    if (!Number.isFinite(routeId) || routeId <= 0 || normalized.includes(routeId)) continue;
    normalized.push(routeId);
  }
  return normalized;
}

function createEmptyPatternRouteChannelSyncResult(): PatternRouteChannelSyncResult {
  return {
    rebuiltRoutes: 0,
    routeIds: [],
    removedChannels: 0,
    createdChannels: 0,
  };
}

function collectRemovedExactModelPatterns(routes: PatternRouteChannelAffectedRouteSnapshot[] | undefined): string[] {
  const normalized: string[] = [];
  for (const route of routes || []) {
    if (!isExactSourceRoute(route) || route.enabled !== true) continue;
    const modelPattern = route.modelPattern.trim();
    const modelKey = normalizeModelKey(modelPattern);
    if (!modelKey || normalized.some((item) => normalizeModelKey(item) === modelKey)) continue;
    normalized.push(modelPattern);
  }
  return normalized;
}

function normalizeModelKey(modelName: string): string {
  return normalizeModelAlias(modelName);
}

function normalizeAllowedModelKeys(modelNames: string[] | undefined): Set<string> | undefined {
  if (modelNames === undefined) return undefined;
  return new Set(modelNames.map(normalizeModelKey).filter(Boolean));
}

function normalizeAllowedAvailabilityCandidateKeys(keys: string[] | undefined): Set<string> | undefined {
  if (keys === undefined) return undefined;
  return new Set(keys.map((key) => key.trim().toLowerCase()).filter(Boolean));
}

function buildAvailabilityCandidateKey(input: {
  accountId: number;
  tokenId: number;
  modelName: string;
}): string {
  return `${input.accountId}:${input.tokenId}:${normalizeModelKey(input.modelName)}`;
}

async function getPersistedModelExclusions(database: DbExecutor = db): Promise<Set<string>> {
  const row = await database.select({ value: schema.settings.value })
    .from(schema.settings)
    .where(eq(schema.settings.key, MODEL_EXCLUSIONS_SETTING_KEY))
    .get();
  if (!row?.value) return new Set();
  try {
    const parsed = JSON.parse(row.value);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed
      .filter((modelName): modelName is string => typeof modelName === 'string')
      .map(normalizeModelKey)
      .filter(Boolean));
  } catch {
    return new Set();
  }
}

async function savePersistedModelExclusions(
  exclusions: Set<string>,
  database: DbExecutor = db,
): Promise<void> {
  await upsertSetting(
    MODEL_EXCLUSIONS_SETTING_KEY,
    [...exclusions].sort(),
    database as typeof db,
  );
}

async function persistModelExclusions(
  modelPatterns: string[],
  database: DbExecutor = db,
): Promise<void> {
  const exclusions = new Set(modelPatterns.map(normalizeModelKey).filter(Boolean));
  if (exclusions.size === 0) return;
  const existing = await getPersistedModelExclusions(database);
  let changed = false;
  for (const modelName of exclusions) {
    if (existing.has(modelName)) continue;
    existing.add(modelName);
    changed = true;
  }
  if (changed) await savePersistedModelExclusions(existing, database);
}

async function clearModelExclusions(
  modelPatterns: string[],
  database: DbExecutor = db,
): Promise<void> {
  const exclusions = new Set(modelPatterns.map(normalizeModelKey).filter(Boolean));
  if (exclusions.size === 0) return;
  const existing = await getPersistedModelExclusions(database);
  let changed = false;
  for (const modelName of exclusions) {
    if (!existing.delete(modelName)) continue;
    changed = true;
  }
  if (changed) await savePersistedModelExclusions(existing, database);
}

function buildChannelPairKey(input: {
  accountId: number;
  tokenId: number | null;
  oauthRouteUnitId?: number | null;
  sourceModel: string | null;
}): string {
  const sourceModel = (input.sourceModel || '').trim().toLowerCase();
  if (typeof input.oauthRouteUnitId === 'number' && Number.isFinite(input.oauthRouteUnitId) && input.oauthRouteUnitId > 0) {
    return `route-unit:${input.oauthRouteUnitId}::${sourceModel}`;
  }
  const tokenId = typeof input.tokenId === 'number' && Number.isFinite(input.tokenId) ? input.tokenId : 0;
  return `account:${input.accountId}::${tokenId}::${sourceModel}`;
}

async function getPatternTokenCandidates(
  modelPattern: string,
  excludedExactModelNames: Set<string>,
  allowedModelKeys: Set<string> | undefined,
  allowedAvailabilityCandidateKeys: Set<string> | undefined,
  database: DbExecutor = db,
): Promise<PatternRouteChannelCandidate[]> {
  const rows = await database.select().from(schema.tokenModelAvailability)
    .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
    .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(
      and(
        eq(schema.tokenModelAvailability.available, true),
        eq(schema.accountTokens.enabled, true),
        eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
        eq(schema.accounts.status, 'active'),
        eq(schema.sites.status, 'active'),
      ),
    )
    .all();

  const candidates: PatternRouteChannelCandidate[] = [];
  for (const row of rows) {
    if (!isUsableAccountToken(row.account_tokens)) continue;
    const modelName = row.token_model_availability.modelName?.trim();
    if (!modelName) continue;
    if (excludedExactModelNames.has(normalizeModelKey(modelName))) continue;
    if (allowedModelKeys && !allowedModelKeys.has(normalizeModelKey(modelName))) continue;
    if (allowedAvailabilityCandidateKeys && !allowedAvailabilityCandidateKeys.has(buildAvailabilityCandidateKey({
      accountId: row.accounts.id,
      tokenId: row.account_tokens.id,
      modelName,
    }))) continue;
    if (!matchesModelPattern(modelName, modelPattern)) continue;
    candidates.push({
      tokenId: row.account_tokens.id,
      accountId: row.accounts.id,
      oauthRouteUnitId: null,
      sourceModel: modelName,
      priority: 0,
      weight: 10,
      enabled: true,
    });
  }

  return candidates;
}

async function getMatchedExactRouteChannelCandidates(
  modelPattern: string,
  excludedExactModelNames: Set<string>,
  database: DbExecutor = db,
): Promise<{
  candidates: PatternRouteChannelCandidate[];
  exactModelNames: Set<string>;
}> {
  const matchedExactRoutes = (await database.select().from(schema.tokenRoutes).all())
    .filter((route) => (
      normalizeTokenRouteMode(route.routeMode) !== 'explicit_group'
      && isExactTokenRouteModelPattern(route.modelPattern)
      && matchesModelPattern(route.modelPattern, modelPattern)
    ));

  const exactModelNames = new Set<string>(excludedExactModelNames);
  for (const route of matchedExactRoutes) {
    exactModelNames.add(normalizeModelKey(route.modelPattern));
  }

  const enabledRoutes = matchedExactRoutes.filter((route) => route.enabled);
  if (enabledRoutes.length === 0) {
    return { candidates: [], exactModelNames };
  }

  const routeMap = new Map<number, typeof enabledRoutes[number]>();
  for (const route of enabledRoutes) routeMap.set(route.id, route);

  const channels = await database.select().from(schema.routeChannels)
    .where(inArray(schema.routeChannels.routeId, enabledRoutes.map((route) => route.id)))
    .all();

  return {
    exactModelNames,
    candidates: channels.map((channel) => ({
      tokenId: channel.tokenId ?? null,
      accountId: channel.accountId,
      oauthRouteUnitId: channel.oauthRouteUnitId ?? null,
      sourceModel: (channel.sourceModel || routeMap.get(channel.routeId)?.modelPattern || '').trim(),
      priority: channel.priority ?? 0,
      weight: channel.weight ?? 10,
      enabled: !!channel.enabled,
    })).filter((candidate) => candidate.sourceModel.length > 0),
  };
}

async function populateRouteChannelsByModelPatternInternal(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
  database: DbExecutor = db,
): Promise<number> {
  const excludedExactModelNames = new Set(
    (options.excludeExactModelPatterns || [])
      .map(normalizeModelKey)
      .filter(Boolean),
  );
  if (!isExactTokenRouteModelPattern(modelPattern)) {
    for (const modelName of await getPersistedModelExclusions(database)) {
      excludedExactModelNames.add(modelName);
    }
  }
  const routeCandidates = await getMatchedExactRouteChannelCandidates(modelPattern, excludedExactModelNames, database);
  const availabilityExclusions = isExactTokenRouteModelPattern(modelPattern)
    ? excludedExactModelNames
    : routeCandidates.exactModelNames;
  const availabilityCandidates = await getPatternTokenCandidates(
    modelPattern,
    availabilityExclusions,
    normalizeAllowedModelKeys(options.allowedModelNames),
    normalizeAllowedAvailabilityCandidateKeys(options.allowedAvailabilityCandidateKeys),
    database,
  );
  const candidates = [...routeCandidates.candidates, ...availabilityCandidates];
  if (candidates.length === 0) return 0;

  const existingChannels = await database.select().from(schema.routeChannels)
    .where(eq(schema.routeChannels.routeId, routeId))
    .all();
  const existingPairs = new Set(existingChannels.map((channel) => buildChannelPairKey({
    accountId: channel.accountId,
    tokenId: channel.tokenId ?? null,
    oauthRouteUnitId: channel.oauthRouteUnitId ?? null,
    sourceModel: channel.sourceModel,
  })));

  let created = 0;
  for (const candidate of candidates) {
    const pairKey = buildChannelPairKey(candidate);
    if (existingPairs.has(pairKey)) continue;
    await database.insert(schema.routeChannels).values({
      routeId,
      accountId: candidate.accountId,
      tokenId: candidate.tokenId,
      oauthRouteUnitId: candidate.oauthRouteUnitId,
      sourceModel: candidate.sourceModel,
      priority: candidate.priority,
      weight: candidate.weight,
      enabled: candidate.enabled,
      manualOverride: false,
    }).run();
    existingPairs.add(pairKey);
    created += 1;
  }

  return created;
}

export async function populateRouteChannelsByModelPattern(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
  database: DbExecutor = db,
): Promise<number> {
  return withPatternRouteMutation(() => populateRouteChannelsByModelPatternInternal(
    routeId,
    modelPattern,
    options,
    database,
  ));
}

async function rebuildAutomaticRouteChannelsByModelPatternInternal(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  let removedChannels = 0;
  let createdChannels = 0;
  await db.transaction(async (tx) => {
    const removableChannels = await tx.select().from(schema.routeChannels)
      .where(
        and(
          eq(schema.routeChannels.routeId, routeId),
          eq(schema.routeChannels.manualOverride, false),
        ),
      )
      .all();

    for (const channel of removableChannels) {
      await tx.delete(schema.routeChannels).where(eq(schema.routeChannels.id, channel.id)).run();
    }

    createdChannels = await populateRouteChannelsByModelPatternInternal(routeId, modelPattern, options, tx);
    removedChannels = removableChannels.length;
  });
  if (removedChannels > 0 || createdChannels > 0) {
    await clearRouteDecisionSnapshot(routeId);
    invalidateTokenRouterCache();
  }

  return {
    rebuiltRoutes: 1,
    routeIds: [routeId],
    removedChannels,
    createdChannels,
  };
}

export async function rebuildAutomaticRouteChannelsByModelPattern(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  return withPatternRouteMutation(() => rebuildAutomaticRouteChannelsByModelPatternInternal(
    routeId,
    modelPattern,
    options,
  ));
}

async function rebuildAllPatternRouteChannelsInternal(
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  const includedModelPatterns = (options.includeModelPatterns || [])
    .map((modelPattern) => modelPattern.trim())
    .filter(Boolean);
  const patternRoutes = (await db.select().from(schema.tokenRoutes).all())
    .filter((route) => (
      route.enabled
      && isPatternGroupRoute(route)
      && (includedModelPatterns.length === 0
        || includedModelPatterns.some((modelPattern) => matchesModelPattern(modelPattern, route.modelPattern)))
    ));

  const result: PatternRouteChannelSyncResult = {
    rebuiltRoutes: 0,
    routeIds: [],
    removedChannels: 0,
    createdChannels: 0,
  };

  for (const route of patternRoutes) {
    const routeResult = await rebuildAutomaticRouteChannelsByModelPatternInternal(route.id, route.modelPattern, options);
    result.rebuiltRoutes += 1;
    result.routeIds.push(route.id);
    result.removedChannels += routeResult.removedChannels;
    result.createdChannels += routeResult.createdChannels;
  }

  if (result.removedChannels > 0 || result.createdChannels > 0) {
    await clearRouteDecisionSnapshots(result.routeIds);
    invalidateTokenRouterCache();
  }

  return result;
}

export async function rebuildAllPatternRouteChannels(
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  return withPatternRouteMutation(() => rebuildAllPatternRouteChannelsInternal(options));
}

async function syncPatternRouteChannelsAfterAffectedRouteChangesInternal(
  input: SyncPatternRouteChannelsAfterAffectedRouteChangesInput = {},
): Promise<PatternRouteChannelSyncResult> {
  const affectedRouteIds = normalizeAffectedRouteIds(input.affectedRouteIds);
  const removedRoutes = input.removedRoutes || [];
  const removedExactModelPatterns = collectRemovedExactModelPatterns(removedRoutes);
  const hasRemovedExactSourceRoute = removedRoutes.some(isExactSourceRoute);
  const rebuildAllPatternRoutes = input.rebuildAllPatternRoutes === true;
  if (affectedRouteIds.length === 0 && !hasRemovedExactSourceRoute && !rebuildAllPatternRoutes) {
    return createEmptyPatternRouteChannelSyncResult();
  }

  let hasAffectedExactSourceRoute = false;
  const affectedExactModelPatterns: string[] = [];
  if (affectedRouteIds.length > 0) {
    const routes = await db.select({
      id: schema.tokenRoutes.id,
      modelPattern: schema.tokenRoutes.modelPattern,
      routeMode: schema.tokenRoutes.routeMode,
    }).from(schema.tokenRoutes)
      .where(inArray(schema.tokenRoutes.id, affectedRouteIds))
      .all();

    hasAffectedExactSourceRoute = routes.some(isExactSourceRoute);
    for (const route of routes) {
      if (isExactSourceRoute(route)) affectedExactModelPatterns.push(route.modelPattern);
    }
  }

  if (!hasAffectedExactSourceRoute && !hasRemovedExactSourceRoute && !rebuildAllPatternRoutes) {
    return createEmptyPatternRouteChannelSyncResult();
  }

  await clearModelExclusions(affectedExactModelPatterns);
  await persistModelExclusions(removedExactModelPatterns);

  const rebuildOptions: RebuildPatternRouteOptions = {
    excludeExactModelPatterns: removedExactModelPatterns,
    includeModelPatterns: [...affectedExactModelPatterns, ...removedRoutes
      .filter(isExactSourceRoute)
      .map((route) => route.modelPattern)],
    allowedModelNames: input.allowedModelNames,
    allowedAvailabilityCandidateKeys: input.allowedAvailabilityCandidateKeys,
  };
  if (rebuildAllPatternRoutes) {
    delete rebuildOptions.includeModelPatterns;
  }
  return rebuildAllPatternRouteChannelsInternal(rebuildOptions);
}

export async function syncPatternRouteChannelsAfterAffectedRouteChanges(
  input: SyncPatternRouteChannelsAfterAffectedRouteChangesInput = {},
): Promise<PatternRouteChannelSyncResult> {
  return withPatternRouteMutation(() => syncPatternRouteChannelsAfterAffectedRouteChangesInternal(input));
}
