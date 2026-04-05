import { z } from 'zod';

const updateCenterVersionSourceSchema = z.enum(['docker-hub-tag', 'github-release']);

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

const oauthQuotaBatchRefreshPayloadSchema = z.object({
  accountIds: z.array(z.number().int().positive()).optional(),
}).passthrough();

const oauthImportPayloadSchema = z.object({
  data: z.unknown().optional(),
}).passthrough();

const updateCenterConfigPayloadSchema = z.object({
  enabled: z.boolean().optional(),
  helperBaseUrl: z.string().optional(),
  namespace: z.string().optional(),
  releaseName: z.string().optional(),
  chartRef: z.string().optional(),
  imageRepository: z.string().optional(),
  githubReleasesEnabled: z.boolean().optional(),
  dockerHubTagsEnabled: z.boolean().optional(),
  defaultDeploySource: updateCenterVersionSourceSchema.optional(),
}).passthrough();

const updateCenterDeployPayloadSchema = z.object({
  source: updateCenterVersionSourceSchema.optional(),
  targetVersion: z.string().optional(),
  targetTag: z.string().optional(),
  targetDigest: z.string().optional(),
}).passthrough();

const updateCenterRollbackPayloadSchema = z.object({
  targetRevision: z.string().optional(),
}).passthrough();

export type AuthChangePayload = z.output<typeof authChangePayloadSchema>;
export type MonitorConfigPayload = z.output<typeof monitorConfigPayloadSchema>;
export type OauthConnectionRebindPayload = z.output<typeof oauthConnectionRebindPayloadSchema>;
export type OauthImportPayload = z.output<typeof oauthImportPayloadSchema>;
export type OauthManualCallbackPayload = z.output<typeof oauthManualCallbackPayloadSchema>;
export type OauthQuotaBatchRefreshPayload = z.output<typeof oauthQuotaBatchRefreshPayloadSchema>;
export type OauthStartPayload = z.output<typeof oauthStartPayloadSchema>;
export type UpdateCenterConfigPayload = z.output<typeof updateCenterConfigPayloadSchema>;
export type UpdateCenterDeployPayload = z.output<typeof updateCenterDeployPayloadSchema>;
export type UpdateCenterRollbackPayload = z.output<typeof updateCenterRollbackPayloadSchema>;

function normalizeSupportRoutePayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatSupportRoutePayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
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
  if (firstPath === 'callbackUrl') {
    return 'Invalid callbackUrl. Expected string.';
  }
  if (firstPath === 'data') {
    return 'Invalid data. Expected object.';
  }
  if (firstPath === 'enabled') {
    return 'Invalid enabled. Expected boolean.';
  }
  if (firstPath === 'helperBaseUrl') {
    return 'Invalid helperBaseUrl. Expected string.';
  }
  if (firstPath === 'namespace') {
    return 'Invalid namespace. Expected string.';
  }
  if (firstPath === 'releaseName') {
    return 'Invalid releaseName. Expected string.';
  }
  if (firstPath === 'chartRef') {
    return 'Invalid chartRef. Expected string.';
  }
  if (firstPath === 'imageRepository') {
    return 'Invalid imageRepository. Expected string.';
  }
  if (firstPath === 'githubReleasesEnabled') {
    return 'Invalid githubReleasesEnabled. Expected boolean.';
  }
  if (firstPath === 'dockerHubTagsEnabled') {
    return 'Invalid dockerHubTagsEnabled. Expected boolean.';
  }
  if (firstPath === 'defaultDeploySource') {
    return 'Invalid defaultDeploySource. Expected docker-hub-tag/github-release.';
  }
  if (firstPath === 'source') {
    return 'Invalid source. Expected docker-hub-tag/github-release.';
  }
  if (firstPath === 'targetVersion') {
    return 'Invalid targetVersion. Expected string.';
  }
  if (firstPath === 'targetTag') {
    return 'Invalid targetTag. Expected string.';
  }
  if (firstPath === 'targetDigest') {
    return 'Invalid targetDigest. Expected string.';
  }
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

export function parseOauthQuotaBatchRefreshPayload(input: unknown):
{ success: true; data: OauthQuotaBatchRefreshPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthQuotaBatchRefreshPayloadSchema, input);
}

export function parseOauthImportPayload(input: unknown):
{ success: true; data: OauthImportPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(oauthImportPayloadSchema, input);
}

export function parseUpdateCenterConfigPayload(input: unknown):
{ success: true; data: UpdateCenterConfigPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterConfigPayloadSchema, input);
}

export function parseUpdateCenterDeployPayload(input: unknown):
{ success: true; data: UpdateCenterDeployPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterDeployPayloadSchema, input);
}

export function parseUpdateCenterRollbackPayload(input: unknown):
{ success: true; data: UpdateCenterRollbackPayload } | { success: false; error: string } {
  return parseSupportRoutePayload(updateCenterRollbackPayloadSchema, input);
}
