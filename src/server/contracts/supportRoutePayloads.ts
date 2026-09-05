import { z } from 'zod';

const authChangePayloadSchema = z.object({
  oldToken: z.string().optional(),
  newToken: z.string().optional(),
}).passthrough();

const monitorConfigPayloadSchema = z.object({
  ldohCookie: z.union([z.string(), z.null()]).optional(),
}).passthrough();

const oauthStartPayloadSchema = z.object({
  accountId: z.number().int().positive().optional(),
  projectId: z.string().optional(),
  proxyUrl: z.union([z.string(), z.null()]).optional(),
  useSystemProxy: z.boolean().optional(),
}).passthrough();

const oauthManualCallbackPayloadSchema = z.object({
  callbackUrl: z.string().optional(),
}).passthrough();

const oauthConnectionRebindPayloadSchema = z.object({
  proxyUrl: z.union([z.string(), z.null()]).optional(),
  useSystemProxy: z.boolean().optional(),
}).passthrough();

const oauthConnectionProxyUpdatePayloadSchema = z.object({
  proxyUrl: z.union([z.string(), z.null()]).optional(),
  useSystemProxy: z.boolean().optional(),
}).passthrough();

const oauthQuotaBatchRefreshPayloadSchema = z.object({
  accountIds: z.array(z.number().int().positive()).optional(),
}).passthrough();

const oauthImportPayloadSchema = z.object({
  data: z.unknown().optional(),
  items: z.array(z.object({}).passthrough()).optional(),
  proxyUrl: z.union([z.string(), z.null()]).optional(),
  useSystemProxy: z.boolean().optional(),
}).passthrough();

const oauthRouteUnitStrategySchema = z.preprocess((value) => {
  if (typeof value !== 'string') return value;
  return value.trim().toLowerCase();
}, z.enum(['round_robin', 'stick_until_unavailable']));

const oauthRouteUnitCreatePayloadSchema = z.object({
  accountIds: z.array(z.number().int().positive()).optional(),
  name: z.string().optional(),
  strategy: oauthRouteUnitStrategySchema.optional(),
}).passthrough();

const oauthRouteUnitUpdatePayloadSchema = z.object({
  name: z.string().optional(),
  strategy: oauthRouteUnitStrategySchema.optional(),
}).passthrough();

const updateCenterConfigPayloadSchema = z.object({
  enabled: z.boolean().optional(),
  channel: z.literal('stable').optional(),
  autoCheck: z.boolean().optional(),
}).strict();

const updateCenterCheckPayloadSchema = z.object({}).strict();

const updateCenterDeployPayloadSchema = z.object({
  targetVersion: z.string().optional(),
  // `targetTag` was the name used by the old API.  Accept it only as a
  // transport compatibility alias; the route always normalizes it to a
  // release version before invoking the local updater.
  targetTag: z.string().optional(),
}).strict();

const updateCenterRollbackPayloadSchema = z.object({
  targetVersion: z.string().optional(),
  // `targetRevision` remains a read-only compatibility alias for clients
  // that have not yet renamed their request field.
  targetRevision: z.string().optional(),
}).strict();

export type AuthChangePayload = z.output<typeof authChangePayloadSchema>;
export type MonitorConfigPayload = z.output<typeof monitorConfigPayloadSchema>;
export type OauthConnectionRebindPayload = z.output<typeof oauthConnectionRebindPayloadSchema>;
export type OauthConnectionProxyUpdatePayload = z.output<typeof oauthConnectionProxyUpdatePayloadSchema>;
export type OauthImportPayload = z.output<typeof oauthImportPayloadSchema>;
export type OauthManualCallbackPayload = z.output<typeof oauthManualCallbackPayloadSchema>;
export type OauthQuotaBatchRefreshPayload = z.output<typeof oauthQuotaBatchRefreshPayloadSchema>;
export type OauthRouteUnitCreatePayload = z.output<typeof oauthRouteUnitCreatePayloadSchema>;
export type OauthRouteUnitUpdatePayload = z.output<typeof oauthRouteUnitUpdatePayloadSchema>;
export type OauthStartPayload = z.output<typeof oauthStartPayloadSchema>;
export type UpdateCenterConfigPayload = z.output<typeof updateCenterConfigPayloadSchema>;
export type UpdateCenterCheckPayload = z.output<typeof updateCenterCheckPayloadSchema>;
export type UpdateCenterDeployPayload = z.output<typeof updateCenterDeployPayloadSchema>;
export type UpdateCenterRollbackPayload = z.output<typeof updateCenterRollbackPayloadSchema>;

function normalizeSupportRoutePayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatSupportRoutePayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  if (firstIssue?.code === 'unrecognized_keys') {
    const keys = firstIssue.keys;
    const removedKey = keys.find((key) => [
      'source',
      'targetDigest',
      'helperBaseUrl',
      'namespace',
      'releaseName',
      'chartRef',
      'imageRepository',
    ].includes(key));
    if (removedKey) return `字段 ${removedKey} 已移除，请使用官方 Release 版本。`;
    const firstUnknownKey = keys[0];
    if (firstUnknownKey) return `字段 ${firstUnknownKey} 不受支持。`;
  }
  const [firstPath] = firstIssue?.path ?? [];
  if (!firstPath) {
    return '请求体必须是对象';
  }
  if (firstPath === 'oldToken') {
    return 'Invalid oldToken. Expected string.';
  }
  if (firstPath === 'newToken') {
    return 'Invalid newToken. Expected string.';
  }
  if (firstPath === 'ldohCookie') {
    return 'Invalid ldohCookie. Expected string or null.';
  }
  if (firstPath === 'accountId') {
    return 'Invalid accountId. Expected positive number.';
  }
  if (firstPath === 'projectId') {
    return 'Invalid projectId. Expected string.';
  }
  if (firstPath === 'proxyUrl') {
    return 'Invalid proxyUrl. Expected string or null.';
  }
  if (firstPath === 'useSystemProxy') {
    return 'Invalid useSystemProxy. Expected boolean.';
  }
  if (firstPath === 'accountIds') {
    return 'Invalid accountIds. Expected positive number array.';
  }
  if (firstPath === 'name') {
    return 'Invalid name. Expected string.';
  }
  if (firstPath === 'strategy') {
    return 'Invalid strategy. Expected round_robin/stick_until_unavailable.';
  }
  if (firstPath === 'callbackUrl') {
    return 'Invalid callbackUrl. Expected string.';
  }
  if (firstPath === 'data') {
    return 'Invalid data. Expected object.';
  }
  if (firstPath === 'items') {
    return 'Invalid items. Expected object array.';
  }
  if (firstPath === 'enabled') {
    return 'Invalid enabled. Expected boolean.';
  }
  if (firstPath === 'channel') {
    return 'Invalid channel. Expected stable.';
  }
  if (firstPath === 'autoCheck') {
    return 'Invalid autoCheck. Expected boolean.';
  }
  if (firstPath === 'source' || firstPath === 'targetDigest') {
    return `字段 ${String(firstPath)} 已移除，请使用官方 Release 版本。`;
  }
  if (firstPath === 'targetVersion') {
    return 'Invalid targetVersion. Expected string.';
  }
  if (firstPath === 'targetTag') return 'Invalid targetTag. Expected string.';
  if (firstPath === 'targetRevision') {
    return 'Invalid targetRevision. Expected string.';
  }
  return 'Invalid support route payload.';
}

function parseSupportRoutePayload<T extends z.ZodTypeAny>(
  schema: T,
  input: unknown,
): { success: true; data: z.output<T> } | { success: false; error: string } {
  const result = schema.safeParse(normalizeSupportRoutePayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSupportRoutePayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseAuthChangePayload(input: unknown):
{ success: true; data: AuthChangePayload } | { success: false; error: string } {
  return parseSupportRoutePayload(authChangePayloadSchema, input);
}

export function parseMonitorConfigPayload(input: unknown):
{ success: true; data: MonitorConfigPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(monitorConfigPayloadSchema, input);
}

export function parseOauthStartPayload(input: unknown):
{ success: true; data: OauthStartPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthStartPayloadSchema, input);
}

export function parseOauthManualCallbackPayload(input: unknown):
{ success: true; data: OauthManualCallbackPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthManualCallbackPayloadSchema, input);
}

export function parseOauthConnectionRebindPayload(input: unknown):
{ success: true; data: OauthConnectionRebindPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthConnectionRebindPayloadSchema, input);
}

export function parseOauthConnectionProxyUpdatePayload(input: unknown):
{ success: true; data: OauthConnectionProxyUpdatePayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthConnectionProxyUpdatePayloadSchema, input);
}

export function parseOauthQuotaBatchRefreshPayload(input: unknown):
{ success: true; data: OauthQuotaBatchRefreshPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthQuotaBatchRefreshPayloadSchema, input);
}

export function parseOauthImportPayload(input: unknown):
{ success: true; data: OauthImportPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthImportPayloadSchema, input);
}

export function parseOauthRouteUnitCreatePayload(input: unknown):
{ success: true; data: OauthRouteUnitCreatePayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthRouteUnitCreatePayloadSchema, input);
}

export function parseOauthRouteUnitUpdatePayload(input: unknown):
{ success: true; data: OauthRouteUnitUpdatePayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthRouteUnitUpdatePayloadSchema, input);
}

export function parseUpdateCenterConfigPayload(input: unknown):
{ success: true; data: UpdateCenterConfigPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterConfigPayloadSchema, input);
}

export function parseUpdateCenterCheckPayload(input: unknown):
{ success: true; data: UpdateCenterCheckPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterCheckPayloadSchema, input);
}

export function parseUpdateCenterDeployPayload(input: unknown):
{ success: true; data: UpdateCenterDeployPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterDeployPayloadSchema, input);
}

export function parseUpdateCenterRollbackPayload(input: unknown):
{ success: true; data: UpdateCenterRollbackPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterRollbackPayloadSchema, input);
}
