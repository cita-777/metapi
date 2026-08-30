export type ServiceTierAction = 'pass' | 'filter' | 'block';

export type ServiceTierRule = {
  action: ServiceTierAction;
  tiers?: string[];
  models?: string[];
  platforms?: string[];
  accountTypes?: string[];
};

export type ServiceTierRuleContext = {
  requestedModel?: string | null;
  actualModel?: string | null;
  sitePlatform?: string | null;
  accountType?: string | null;
};

export type ServiceTierPolicyResult =
  | {
    ok: true;
    body: Record<string, unknown>;
    serviceTier?: string;
    action: 'pass' | 'filter';
  }
  | {
    ok: false;
    statusCode: 400;
    payload: {
      error: {
        message: string;
        type: 'invalid_request_error';
      };
    };
  };

const KNOWN_OPENAI_SERVICE_TIERS = new Set([
  'auto',
  'default',
  'flex',
  'priority',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeMatchList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => asTrimmedString(item).toLowerCase())
    .filter((item) => item.length > 0);
}

function normalizeRule(value: unknown): ServiceTierRule | null {
  if (!isRecord(value)) return null;
  const action = asTrimmedString(value.action).toLowerCase();
  if (action !== 'pass' && action !== 'filter' && action !== 'block') return null;
  return {
    action,
    tiers: normalizeMatchList(value.tiers),
    models: normalizeMatchList(value.models),
    platforms: normalizeMatchList(value.platforms),
    accountTypes: normalizeMatchList(value.accountTypes ?? value.account_types),
  };
}

function normalizeRules(value: unknown): ServiceTierRule[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => normalizeRule(item))
    .filter((item): item is ServiceTierRule => !!item);
}

function candidateMatches(patterns: string[] | undefined, candidates: Array<string | null | undefined>): boolean {
  if (!patterns || patterns.length <= 0) return true;
  const normalizedCandidates = candidates
    .map((item) => asTrimmedString(item).toLowerCase())
    .filter((item) => item.length > 0);
  if (normalizedCandidates.length <= 0) return false;

  return patterns.some((pattern) => {
    if (pattern === '*') return true;
    return normalizedCandidates.some((candidate) => candidate === pattern);
  });
}

function ruleMatches(
  rule: ServiceTierRule,
  serviceTier: string,
  context: ServiceTierRuleContext,
): boolean {
  return candidateMatches(rule.tiers, [serviceTier])
    && candidateMatches(rule.models, [context.actualModel, context.requestedModel])
    && candidateMatches(rule.platforms, [context.sitePlatform])
    && candidateMatches(rule.accountTypes, [context.accountType]);
}

function normalizeServiceTier(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const normalized = raw.trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === 'fast') return 'priority';
  if (!KNOWN_OPENAI_SERVICE_TIERS.has(normalized)) return null;
  return normalized;
}

function buildBlockedResult(serviceTier: string): Extract<ServiceTierPolicyResult, { ok: false }> {
  return {
    ok: false,
    statusCode: 400,
    payload: {
      error: {
        message: `service_tier '${serviceTier}' is not allowed for this upstream policy`,
        type: 'invalid_request_error',
      },
    },
  };
}

export function applyOpenAiServiceTierPolicy(input: {
  body: Record<string, unknown>;
  context?: ServiceTierRuleContext;
  rules?: unknown;
}): ServiceTierPolicyResult {
  const hasRequestedServiceTier = Object.prototype.hasOwnProperty.call(input.body, 'service_tier');
  const rawTier = input.body.service_tier;
  const serviceTier = normalizeServiceTier(rawTier);
  const next = { ...input.body };

  if (!serviceTier) {
    delete next.service_tier;
    return {
      ok: true,
      body: next,
      action: hasRequestedServiceTier ? 'filter' : 'pass',
    };
  }

  next.service_tier = serviceTier;
  const rules = normalizeRules(input.rules);
  const matchedRule = rules.find((rule) => ruleMatches(rule, serviceTier, input.context || {}));
  if (matchedRule?.action === 'block') return buildBlockedResult(serviceTier);
  if (matchedRule?.action === 'filter') {
    delete next.service_tier;
    return {
      ok: true,
      body: next,
      serviceTier,
      action: 'filter',
    };
  }

  return {
    ok: true,
    body: next,
    serviceTier,
    action: 'pass',
  };
}
