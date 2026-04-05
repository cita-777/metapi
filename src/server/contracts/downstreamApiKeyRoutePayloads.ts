import { z } from 'zod';

const downstreamExcludedCredentialRefSchema = z.union([
  z.object({
    kind: z.literal('account_token'),
    siteId: z.union([z.number(), z.string()]),
    accountId: z.union([z.number(), z.string()]),
    tokenId: z.union([z.number(), z.string()]),
  }),
  z.object({
    kind: z.literal('default_api_key'),
    siteId: z.union([z.number(), z.string()]),
    accountId: z.union([z.number(), z.string()]),
  }),
]);

const downstreamApiKeyPayloadSchema = z.object({
  name: z.string().optional(),
  key: z.string().optional(),
  description: z.union([z.string(), z.null()]).optional(),
  groupName: z.union([z.string(), z.null()]).optional(),
  tags: z.union([z.string(), z.array(z.string())]).optional(),
  enabled: z.boolean().optional(),
  expiresAt: z.union([z.string(), z.null()]).optional(),
  maxCost: z.union([z.number(), z.string(), z.null()]).optional(),
  maxRequests: z.union([z.number(), z.string(), z.null()]).optional(),
  supportedModels: z.union([z.string(), z.array(z.string())]).optional(),
  allowedRouteIds: z.union([z.string(), z.array(z.union([z.number(), z.string()]))]).optional(),
  siteWeightMultipliers: z.union([
    z.string(),
    z.record(z.string(), z.union([z.number(), z.string()])),
  ]).optional(),
  excludedSiteIds: z.union([z.string(), z.array(z.union([z.number(), z.string()]))]).optional(),
  excludedCredentialRefs: z.union([z.string(), z.array(downstreamExcludedCredentialRefSchema)]).optional(),
}).passthrough();

const downstreamApiKeyBatchPayloadSchema = z.object({
  ids: z.array(z.number().int().positive()).optional(),
  action: z.string().optional(),
  groupOperation: z.string().optional(),
  groupName: z.union([z.string(), z.null()]).optional(),
  tagOperation: z.string().optional(),
  tags: z.union([z.string(), z.array(z.string())]).optional(),
}).passthrough();

export type DownstreamApiKeyBatchPayload = z.output<typeof downstreamApiKeyBatchPayloadSchema>;
export type DownstreamApiKeyPayload = z.output<typeof downstreamApiKeyPayloadSchema>;

function normalizeDownstreamApiKeyPayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatDownstreamApiKeyPayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  const [firstPath] = firstIssue?.path ?? [];
  if (!firstPath) {
    return '参数无效：请求体必须是对象';
  }
  if (firstPath === 'name') {
    return 'Invalid name. Expected string.';
  }
  if (firstPath === 'key') {
    return 'Invalid key. Expected string.';
  }
  if (firstPath === 'description') {
    return 'Invalid description. Expected string or null.';
  }
  if (firstPath === 'groupName') {
    return 'Invalid groupName. Expected string or null.';
  }
  if (firstPath === 'tags') {
    return 'Invalid tags. Expected string or string[].';
  }
  if (firstPath === 'enabled') {
    return 'Invalid enabled. Expected boolean.';
  }
  if (firstPath === 'expiresAt') {
    return 'Invalid expiresAt. Expected string or null.';
  }
  if (firstPath === 'maxCost') {
    return 'Invalid maxCost. Expected number, string, or null.';
  }
  if (firstPath === 'maxRequests') {
    return 'Invalid maxRequests. Expected number, string, or null.';
  }
  if (firstPath === 'supportedModels') {
    return 'Invalid supportedModels. Expected string or string[].';
  }
  if (firstPath === 'allowedRouteIds') {
    return 'Invalid allowedRouteIds. Expected string or array.';
  }
  if (firstPath === 'siteWeightMultipliers') {
    return 'Invalid siteWeightMultipliers. Expected JSON object or string.';
  }
  if (firstPath === 'excludedSiteIds') {
    return 'Invalid excludedSiteIds. Expected string or array.';
  }
  if (firstPath === 'excludedCredentialRefs') {
    return 'Invalid excludedCredentialRefs. Expected JSON string or array.';
  }
  if (firstPath === 'ids') {
    return 'Invalid ids. Expected number[].';
  }
  if (firstPath === 'action') {
    return 'Invalid action. Expected string.';
  }
  if (firstPath === 'groupOperation') {
    return 'Invalid groupOperation. Expected string.';
  }
  if (firstPath === 'tagOperation') {
    return 'Invalid tagOperation. Expected string.';
  }
  return '参数无效';
}

function parseDownstreamApiKeyRoutePayload<T extends z.ZodTypeAny>(
  schema: T,
  input: unknown,
): { success: true; data: z.output<T> } | { success: false; error: string } {
  const result = schema.safeParse(normalizeDownstreamApiKeyPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatDownstreamApiKeyPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseDownstreamApiKeyPayload(input: unknown):
{ success: true; data: DownstreamApiKeyPayload } | { success: false; error: string } {
  return parseDownstreamApiKeyRoutePayload(downstreamApiKeyPayloadSchema, input);
}

export function parseDownstreamApiKeyBatchPayload(input: unknown):
{ success: true; data: DownstreamApiKeyBatchPayload } | { success: false; error: string } {
  return parseDownstreamApiKeyRoutePayload(downstreamApiKeyBatchPayloadSchema, input);
}
