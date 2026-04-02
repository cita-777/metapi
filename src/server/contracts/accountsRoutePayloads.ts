import { z } from 'zod';

const accountCredentialModeSchema = z.enum(['auto', 'session', 'apikey']);

const accountCreatePayloadSchema = z.object({
  siteId: z.number().int().positive(),
  username: z.string().optional(),
  accessToken: z.string(),
  apiToken: z.string().optional(),
  platformUserId: z.number().int().positive().optional(),
  checkinEnabled: z.boolean().optional(),
  credentialMode: accountCredentialModeSchema.optional(),
  refreshToken: z.string().optional(),
  tokenExpiresAt: z.union([z.number(), z.string()]).optional(),
  skipModelFetch: z.boolean().optional(),
}).passthrough();

const accountUpdatePayloadSchema = z.object({
  username: z.string().optional(),
  accessToken: z.string().optional(),
  apiToken: z.union([z.string(), z.null()]).optional(),
  status: z.string().optional(),
  checkinEnabled: z.boolean().optional(),
  unitCost: z.union([z.number(), z.null()]).optional(),
  extraConfig: z.union([z.string(), z.record(z.string(), z.unknown()), z.null()]).optional(),
  refreshToken: z.union([z.string(), z.null()]).optional(),
  tokenExpiresAt: z.union([z.number(), z.string(), z.null()]).optional(),
  isPinned: z.boolean().optional(),
  sortOrder: z.number().int().min(0).optional(),
  proxyUrl: z.union([z.string(), z.null()]).optional(),
}).passthrough();

const accountBatchPayloadSchema = z.object({
  ids: z.array(z.number().int().positive()).optional(),
  action: z.string().optional(),
}).passthrough();

const accountRebindSessionPayloadSchema = z.object({
  accessToken: z.string().optional(),
  platformUserId: z.number().int().positive().optional(),
  refreshToken: z.string().optional(),
  tokenExpiresAt: z.union([z.number(), z.string()]).optional(),
}).passthrough();

const accountHealthRefreshPayloadSchema = z.object({
  accountId: z.number().int().positive().optional(),
  wait: z.boolean().optional(),
}).passthrough();

const accountLoginPayloadSchema = z.object({
  siteId: z.number().int().positive(),
  username: z.string(),
  password: z.string(),
}).passthrough();

const accountVerifyTokenPayloadSchema = z.object({
  siteId: z.number().int().positive(),
  accessToken: z.string().optional(),
  platformUserId: z.number().int().positive().optional(),
  credentialMode: accountCredentialModeSchema.optional(),
}).passthrough();

const accountManualModelsPayloadSchema = z.object({
  models: z.array(z.string()).optional(),
}).passthrough();

export type AccountBatchPayload = z.output<typeof accountBatchPayloadSchema>;
export type AccountCreatePayload = z.output<typeof accountCreatePayloadSchema>;
export type AccountHealthRefreshPayload = z.output<typeof accountHealthRefreshPayloadSchema>;
export type AccountLoginPayload = z.output<typeof accountLoginPayloadSchema>;
export type AccountManualModelsPayload = z.output<typeof accountManualModelsPayloadSchema>;
export type AccountRebindSessionPayload = z.output<typeof accountRebindSessionPayloadSchema>;
export type AccountUpdatePayload = z.output<typeof accountUpdatePayloadSchema>;
export type AccountVerifyTokenPayload = z.output<typeof accountVerifyTokenPayloadSchema>;

function normalizeAccountsPayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatAccountsPayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  const firstPath = firstIssue?.path[0];
  if (firstPath === 'siteId') {
    return 'Invalid siteId. Expected positive number.';
  }
  if (firstPath === 'accessToken') {
    return 'Invalid accessToken. Expected string.';
  }
  if (firstPath === 'username') {
    return 'Invalid username. Expected string.';
  }
  if (firstPath === 'password') {
    return 'Invalid password. Expected string.';
  }
  if (firstPath === 'apiToken') {
    return 'Invalid apiToken. Expected string or null.';
  }
  if (firstPath === 'checkinEnabled') {
    return 'Invalid checkinEnabled. Expected boolean.';
  }
  if (firstPath === 'unitCost') {
    return 'Invalid unitCost. Expected number or null.';
  }
  if (firstPath === 'credentialMode') {
    return 'Invalid credentialMode. Expected auto/session/apikey.';
  }
  if (firstPath === 'skipModelFetch') {
    return 'Invalid skipModelFetch. Expected boolean.';
  }
  if (firstPath === 'isPinned') {
    return 'Invalid isPinned. Expected boolean.';
  }
  if (firstPath === 'sortOrder') {
    return 'Invalid sortOrder. Expected non-negative integer.';
  }
  if (firstPath === 'proxyUrl') {
    return 'Invalid proxyUrl. Expected string or null.';
  }
  if (firstPath === 'ids') {
    return 'Invalid ids. Expected number[].';
  }
  if (firstPath === 'action') {
    return 'Invalid action. Expected string.';
  }
  if (firstPath === 'platformUserId') {
    return 'Invalid platformUserId. Expected positive number.';
  }
  if (firstPath === 'refreshToken') {
    return 'Invalid refreshToken. Expected string or null.';
  }
  if (firstPath === 'tokenExpiresAt') {
    return 'Invalid tokenExpiresAt. Expected number, string, or null.';
  }
  if (firstPath === 'accountId') {
    return '账号 ID 无效';
  }
  if (firstPath === 'wait') {
    return 'Invalid wait. Expected boolean.';
  }
  if (firstPath === 'models') {
    return 'Invalid models. Expected string[].';
  }
  return 'Invalid account payload.';
}

function parseAccountsPayload<T>(schema: z.ZodType<T>, input: unknown):
{ success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(normalizeAccountsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatAccountsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseAccountCreatePayload(input: unknown):
{ success: true; data: AccountCreatePayload } | { success: false; error: string } {
  return parseAccountsPayload(accountCreatePayloadSchema, input);
}

export function parseAccountUpdatePayload(input: unknown):
{ success: true; data: AccountUpdatePayload } | { success: false; error: string } {
  return parseAccountsPayload(accountUpdatePayloadSchema, input);
}

export function parseAccountBatchPayload(input: unknown):
{ success: true; data: AccountBatchPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountBatchPayloadSchema, input);
}

export function parseAccountRebindSessionPayload(input: unknown):
{ success: true; data: AccountRebindSessionPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountRebindSessionPayloadSchema, input);
}

export function parseAccountHealthRefreshPayload(input: unknown):
{ success: true; data: AccountHealthRefreshPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountHealthRefreshPayloadSchema, input);
}

export function parseAccountLoginPayload(input: unknown):
{ success: true; data: AccountLoginPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountLoginPayloadSchema, input);
}

export function parseAccountVerifyTokenPayload(input: unknown):
{ success: true; data: AccountVerifyTokenPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountVerifyTokenPayloadSchema, input);
}

export function parseAccountManualModelsPayload(input: unknown):
{ success: true; data: AccountManualModelsPayload } | { success: false; error: string } {
  return parseAccountsPayload(accountManualModelsPayloadSchema, input);
}
