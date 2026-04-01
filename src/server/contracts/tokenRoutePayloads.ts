import { z } from 'zod';

const routeChannelCreatePayloadSchema = z.object({
  accountId: z.number().int().positive(),
  tokenId: z.union([z.number().int().positive(), z.null()]).optional(),
  sourceModel: z.string().optional(),
  priority: z.number().optional(),
  weight: z.number().optional(),
}).passthrough();

const routeChannelBatchCreatePayloadSchema = z.object({
  channels: z.array(z.object({
    accountId: z.number().int().positive(),
    tokenId: z.union([z.number().int().positive(), z.null()]).optional(),
    sourceModel: z.string().optional(),
  }).passthrough()).min(1),
}).passthrough();

const routeChannelUpdatePayloadSchema = z.object({
  tokenId: z.union([z.number().int().positive(), z.null()]).optional(),
  sourceModel: z.union([z.string(), z.null()]).optional(),
  priority: z.number().optional(),
  weight: z.number().optional(),
  enabled: z.boolean().optional(),
}).passthrough();

const tokenRouteCreatePayloadSchema = z.object({
  routeMode: z.string().optional(),
  modelPattern: z.string().optional(),
  displayName: z.union([z.string(), z.null()]).optional(),
  displayIcon: z.union([z.string(), z.null()]).optional(),
  modelMapping: z.union([z.string(), z.null()]).optional(),
  routingStrategy: z.string().optional(),
  enabled: z.boolean().optional(),
  sourceRouteIds: z.array(z.number().int().positive()).optional(),
}).passthrough();

const tokenRouteUpdatePayloadSchema = z.object({
  routeMode: z.string().optional(),
  modelPattern: z.string().optional(),
  displayName: z.union([z.string(), z.null()]).optional(),
  displayIcon: z.union([z.string(), z.null()]).optional(),
  modelMapping: z.union([z.string(), z.null()]).optional(),
  routingStrategy: z.string().optional(),
  enabled: z.boolean().optional(),
  sourceRouteIds: z.array(z.number().int().positive()).optional(),
}).passthrough();

const tokenRouteBatchPayloadSchema = z.object({
  ids: z.array(z.number().int().positive()).optional(),
  action: z.string().optional(),
}).passthrough();

const routeRebuildPayloadSchema = z.object({
  refreshModels: z.boolean().optional(),
  wait: z.boolean().optional(),
}).passthrough();

export type RouteChannelBatchCreatePayload = z.output<typeof routeChannelBatchCreatePayloadSchema>;
export type RouteChannelCreatePayload = z.output<typeof routeChannelCreatePayloadSchema>;
export type RouteChannelUpdatePayload = z.output<typeof routeChannelUpdatePayloadSchema>;
export type RouteRebuildPayload = z.output<typeof routeRebuildPayloadSchema>;
export type TokenRouteBatchPayload = z.output<typeof tokenRouteBatchPayloadSchema>;
export type TokenRouteCreatePayload = z.output<typeof tokenRouteCreatePayloadSchema>;
export type TokenRouteUpdatePayload = z.output<typeof tokenRouteUpdatePayloadSchema>;

function normalizeTokenRoutePayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatTokenRoutePayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  const [firstPath, secondPath, thirdPath] = firstIssue?.path ?? [];
  if (!firstPath) {
    return '请求体必须是对象';
  }
  if (firstPath === 'routeMode') {
    return 'Invalid routeMode. Expected string.';
  }
  if (firstPath === 'modelPattern') {
    return 'Invalid modelPattern. Expected string.';
  }
  if (firstPath === 'displayName') {
    return 'Invalid displayName. Expected string or null.';
  }
  if (firstPath === 'displayIcon') {
    return 'Invalid displayIcon. Expected string or null.';
  }
  if (firstPath === 'modelMapping') {
    return 'Invalid modelMapping. Expected string or null.';
  }
  if (firstPath === 'routingStrategy') {
    return 'Invalid routingStrategy. Expected string.';
  }
  if (firstPath === 'enabled') {
    return 'Invalid enabled. Expected boolean.';
  }
  if (firstPath === 'sourceRouteIds') {
    return 'Invalid sourceRouteIds. Expected number[].';
  }
  if (firstPath === 'ids') {
    return 'Invalid ids. Expected number[].';
  }
  if (firstPath === 'action') {
    return 'Invalid action. Expected string.';
  }
  if (firstPath === 'accountId') {
    return 'Invalid accountId. Expected positive number.';
  }
  if (firstPath === 'tokenId') {
    return 'Invalid tokenId. Expected positive number or null.';
  }
  if (firstPath === 'sourceModel') {
    return 'Invalid sourceModel. Expected string or null.';
  }
  if (firstPath === 'priority') {
    return 'Invalid priority. Expected number.';
  }
  if (firstPath === 'weight') {
    return 'Invalid weight. Expected number.';
  }
  if (firstPath === 'refreshModels') {
    return 'Invalid refreshModels. Expected boolean.';
  }
  if (firstPath === 'wait') {
    return 'Invalid wait. Expected boolean.';
  }
  if (firstPath === 'channels' && thirdPath === 'accountId') {
    return 'Invalid channels[].accountId. Expected positive number.';
  }
  if (firstPath === 'channels' && thirdPath === 'tokenId') {
    return 'Invalid channels[].tokenId. Expected positive number or null.';
  }
  if (firstPath === 'channels' && thirdPath === 'sourceModel') {
    return 'Invalid channels[].sourceModel. Expected string.';
  }
  if (firstPath === 'channels') {
    return 'Invalid channels. Expected channel array.';
  }
  return 'Invalid token route payload.';
}

function parseTokenRoutePayload<T extends z.ZodTypeAny>(
  schema: T,
  input: unknown,
): { success: true; data: z.output<T> } | { success: false; error: string } {
  const result = schema.safeParse(normalizeTokenRoutePayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatTokenRoutePayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseTokenRouteCreatePayload(input: unknown):
{ success: true; data: TokenRouteCreatePayload } | { success: false; error: string } {
  return parseTokenRoutePayload(tokenRouteCreatePayloadSchema, input);
}

export function parseTokenRouteUpdatePayload(input: unknown):
{ success: true; data: TokenRouteUpdatePayload } | { success: false; error: string } {
  return parseTokenRoutePayload(tokenRouteUpdatePayloadSchema, input);
}

export function parseTokenRouteBatchPayload(input: unknown):
{ success: true; data: TokenRouteBatchPayload } | { success: false; error: string } {
  return parseTokenRoutePayload(tokenRouteBatchPayloadSchema, input);
}

export function parseRouteChannelCreatePayload(input: unknown):
{ success: true; data: RouteChannelCreatePayload } | { success: false; error: string } {
  return parseTokenRoutePayload(routeChannelCreatePayloadSchema, input);
}

export function parseRouteChannelBatchCreatePayload(input: unknown):
{ success: true; data: RouteChannelBatchCreatePayload } | { success: false; error: string } {
  return parseTokenRoutePayload(routeChannelBatchCreatePayloadSchema, input);
}

export function parseRouteChannelUpdatePayload(input: unknown):
{ success: true; data: RouteChannelUpdatePayload } | { success: false; error: string } {
  return parseTokenRoutePayload(routeChannelUpdatePayloadSchema, input);
}

export function parseRouteRebuildPayload(input: unknown):
{ success: true; data: RouteRebuildPayload } | { success: false; error: string } {
  return parseTokenRoutePayload(routeRebuildPayloadSchema, input);
}
