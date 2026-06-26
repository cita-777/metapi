import { and, eq, inArray } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  ACCOUNT_TOKEN_VALUE_STATUS_READY,
  isUsableAccountToken,
} from './accountTokenService.js';
import { clearRouteDecisionSnapshot, clearRouteDecisionSnapshots } from './routeDecisionSnapshotStore.js';
import { matchesModelPattern } from './tokenRouter.js';
import { normalizeTokenRouteMode } from '../../shared/tokenRouteContract.js';

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

type RebuildPatternRouteOptions = {
  excludeExactModelPatterns?: string[];
};

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
}

function isPatternGroupRoute(route: Pick<typeof schema.tokenRoutes.$inferSelect, 'routeMode' | 'modelPattern'>): boolean {
  return normalizeTokenRouteMode(route.routeMode) !== 'explicit_group'
    && !isExactModelPattern(route.modelPattern);
}

function normalizeModelKey(modelName: string): string {
  return modelName.trim().toLowerCase();
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
): Promise<PatternRouteChannelCandidate[]> {
  const rows = await db.select().from(schema.tokenModelAvailability)
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
): Promise<{
  candidates: PatternRouteChannelCandidate[];
  exactModelNames: Set<string>;
}> {
  const matchedExactRoutes = (await db.select().from(schema.tokenRoutes).all())
    .filter((route) => (
      normalizeTokenRouteMode(route.routeMode) !== 'explicit_group'
      && isExactModelPattern(route.modelPattern)
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

  const channels = await db.select().from(schema.routeChannels)
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

export async function populateRouteChannelsByModelPattern(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
): Promise<number> {
  const excludedExactModelNames = new Set(
    (options.excludeExactModelPatterns || [])
      .map(normalizeModelKey)
      .filter(Boolean),
  );
  const routeCandidates = await getMatchedExactRouteChannelCandidates(modelPattern, excludedExactModelNames);
  const availabilityExclusions = isExactModelPattern(modelPattern)
    ? excludedExactModelNames
    : routeCandidates.exactModelNames;
  const availabilityCandidates = await getPatternTokenCandidates(modelPattern, availabilityExclusions);
  const candidates = [...routeCandidates.candidates, ...availabilityCandidates];
  if (candidates.length === 0) return 0;

  const existingChannels = await db.select().from(schema.routeChannels)
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
    await db.insert(schema.routeChannels).values({
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

export async function rebuildAutomaticRouteChannelsByModelPattern(
  routeId: number,
  modelPattern: string,
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  const removableChannels = await db.select().from(schema.routeChannels)
    .where(
      and(
        eq(schema.routeChannels.routeId, routeId),
        eq(schema.routeChannels.manualOverride, false),
      ),
    )
    .all();

  for (const channel of removableChannels) {
    await db.delete(schema.routeChannels).where(eq(schema.routeChannels.id, channel.id)).run();
  }

  const createdChannels = await populateRouteChannelsByModelPattern(routeId, modelPattern, options);
  if (removableChannels.length > 0 || createdChannels > 0) {
    await clearRouteDecisionSnapshot(routeId);
  }

  return {
    rebuiltRoutes: 1,
    routeIds: [routeId],
    removedChannels: removableChannels.length,
    createdChannels,
  };
}

export async function rebuildAllPatternRouteChannels(
  options: RebuildPatternRouteOptions = {},
): Promise<PatternRouteChannelSyncResult> {
  const patternRoutes = (await db.select().from(schema.tokenRoutes).all())
    .filter((route) => route.enabled && isPatternGroupRoute(route));

  const result: PatternRouteChannelSyncResult = {
    rebuiltRoutes: 0,
    routeIds: [],
    removedChannels: 0,
    createdChannels: 0,
  };

  for (const route of patternRoutes) {
    const routeResult = await rebuildAutomaticRouteChannelsByModelPattern(route.id, route.modelPattern, options);
    result.rebuiltRoutes += 1;
    result.routeIds.push(route.id);
    result.removedChannels += routeResult.removedChannels;
    result.createdChannels += routeResult.createdChannels;
  }

  if (result.removedChannels > 0 || result.createdChannels > 0) {
    await clearRouteDecisionSnapshots(result.routeIds);
  }

  return result;
}
