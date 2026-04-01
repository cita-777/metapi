import { z } from 'zod';

const accountTokenCreatePayloadSchema = z.object({
  accountId: z.number().int().positive(),
  name: z.string().optional(),
  token: z.string().optional(),
  enabled: z.boolean().optional(),
  isDefault: z.boolean().optional(),
  source: z.string().optional(),
  group: z.string().optional(),
  unlimitedQuota: z.boolean().optional(),
  remainQuota: z.union([z.number(), z.string()]).optional(),
  expiredTime: z.union([z.number(), z.string()]).optional(),
  allowIps: z.string().optional(),
  modelLimitsEnabled: z.boolean().optional(),
  modelLimits: z.string().optional(),
}).passthrough();

const accountTokenBatchPayloadSchema = z.object({
  ids: z.array(z.number().int().positive()).optional(),
  action: z.string().optional(),
}).passthrough();

const accountTokenUpdatePayloadSchema = z.object({
  name: z.string().optional(),
  token: z.string().optional(),
  group: z.string().optional(),
  enabled: z.boolean().optional(),
  isDefault: z.boolean().optional(),
  source: z.string().optional(),
}).passthrough();

const accountTokenSyncAllPayloadSchema = z.object({
  wait: z.boolean().optional(),
}).passthrough();

export type AccountTokenBatchPayload = z.output<typeof accountTokenBatchPayloadSchema>;
export type AccountTokenCreatePayload = z.output<typeof accountTokenCreatePayloadSchema>;
export type AccountTokenSyncAllPayload = z.output<typeof accountTokenSyncAllPayloadSchema>;
export type AccountTokenUpdatePayload = z.output<typeof accountTokenUpdatePayloadSchema>;

function normalizeAccountTokenPayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatAccountTokenPayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  const firstPath = firstIssue?.path[0];
  if (firstPath === 'accountId') {
    return 'Invalid accountId. Expected positive number.';
  }
  if (firstPath === 'token') {
    return 'Invalid token. Expected string.';
  }
  if (firstPath === 'name') {
    return 'Invalid name. Expected string.';
  }
  if (firstPath === 'enabled') {
    return 'Invalid enabled. Expected boolean.';
  }
  if (firstPath === 'isDefault') {
    return 'Invalid isDefault. Expected boolean.';
  }
  if (firstPath === 'source') {
    return 'Invalid source. Expected string.';
  }
  if (firstPath === 'group') {
    return 'Invalid group. Expected string.';
  }
  if (firstPath === 'unlimitedQuota') {
    return 'Invalid unlimitedQuota. Expected boolean.';
  }
  if (firstPath === 'modelLimitsEnabled') {
    return 'Invalid modelLimitsEnabled. Expected boolean.';
  }
  if (firstPath === 'ids') {
    return 'Invalid ids. Expected number[].';
  }
  if (firstPath === 'action') {
    return 'Invalid action. Expected string.';
  }
  if (firstPath === 'wait') {
    return 'Invalid wait. Expected boolean.';
  }
  return 'Invalid account token payload.';
}

export function parseAccountTokenCreatePayload(input: unknown):
{ success: true; data: AccountTokenCreatePayload } | { success: false; error: string } {
  const result = accountTokenCreatePayloadSchema.safeParse(normalizeAccountTokenPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatAccountTokenPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseAccountTokenBatchPayload(input: unknown):
{ success: true; data: AccountTokenBatchPayload } | { success: false; error: string } {
  const result = accountTokenBatchPayloadSchema.safeParse(normalizeAccountTokenPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatAccountTokenPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseAccountTokenUpdatePayload(input: unknown):
{ success: true; data: AccountTokenUpdatePayload } | { success: false; error: string } {
  const result = accountTokenUpdatePayloadSchema.safeParse(normalizeAccountTokenPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatAccountTokenPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseAccountTokenSyncAllPayload(input: unknown):
{ success: true; data: AccountTokenSyncAllPayload } | { success: false; error: string } {
  const result = accountTokenSyncAllPayloadSchema.safeParse(normalizeAccountTokenPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatAccountTokenPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}
