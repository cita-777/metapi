import { z } from 'zod';

const backupExportTypeSchema = z.enum(['all', 'accounts', 'preferences']);
const migrationDialectSchema = z.enum(['sqlite', 'mysql', 'postgres']);

const runtimeSettingsPayloadSchema = z.object({
  modelAvailabilityProbeEnabled: z.boolean().optional(),
  webhookEnabled: z.boolean().optional(),
  barkEnabled: z.boolean().optional(),
  serverChanEnabled: z.boolean().optional(),
  telegramEnabled: z.boolean().optional(),
  telegramUseSystemProxy: z.boolean().optional(),
  smtpEnabled: z.boolean().optional(),
  smtpSecure: z.boolean().optional(),
  logCleanupUsageLogsEnabled: z.boolean().optional(),
  logCleanupProgramLogsEnabled: z.boolean().optional(),
}).passthrough();

const systemProxyTestPayloadSchema = z.object({
  proxyUrl: z.string().optional(),
}).passthrough();

const databaseMigrationPayloadSchema = z.object({
  dialect: migrationDialectSchema,
  connectionString: z.string().trim().min(1),
  overwrite: z.boolean().optional(),
  ssl: z.boolean().optional(),
}).passthrough();

const backupWebdavConfigPayloadSchema = z.object({
  enabled: z.boolean().optional(),
  fileUrl: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  clearPassword: z.boolean().optional(),
  exportType: backupExportTypeSchema.optional(),
  autoSyncEnabled: z.boolean().optional(),
  autoSyncCron: z.string().optional(),
}).passthrough();

const backupWebdavExportPayloadSchema = z.object({
  type: backupExportTypeSchema.optional(),
}).passthrough();

const backupImportPayloadSchema = z.object({
  data: z.record(z.string(), z.unknown()),
}).passthrough();

export type BackupWebdavConfigPayload = z.output<typeof backupWebdavConfigPayloadSchema>;
export type BackupWebdavExportPayload = z.output<typeof backupWebdavExportPayloadSchema>;
export type BackupImportPayload = z.output<typeof backupImportPayloadSchema>;
export type DatabaseMigrationPayload = z.output<typeof databaseMigrationPayloadSchema>;
export type RuntimeSettingsPayload = z.output<typeof runtimeSettingsPayloadSchema>;
export type SystemProxyTestPayload = z.output<typeof systemProxyTestPayloadSchema>;

function normalizeSettingsPayloadInput(input: unknown): unknown {
  return input === undefined ? {} : input;
}

function formatSettingsPayloadError(error: z.ZodError): string {
  const firstIssue = error.issues[0];
  const firstPath = firstIssue?.path[0];
  if (firstPath === 'exportType') {
    return 'Invalid exportType. Expected all/accounts/preferences.';
  }
  if (firstPath === 'type') {
    return 'Invalid type. Expected all/accounts/preferences.';
  }
  if (firstPath === 'proxyUrl') {
    return '系统代理地址格式无效：需要 string';
  }
  if (firstPath === 'dialect') {
    return 'Invalid dialect. Expected sqlite/mysql/postgres.';
  }
  if (firstPath === 'connectionString') {
    return 'Invalid connectionString. Expected non-empty string.';
  }
  if (firstPath === 'overwrite') {
    return 'Invalid overwrite. Expected boolean.';
  }
  if (firstPath === 'ssl') {
    return 'Invalid ssl. Expected boolean.';
  }
  if (firstPath === 'data') {
    return '导入数据格式错误：需要 JSON 对象';
  }
  if (firstPath === 'webhookEnabled') {
    return 'Webhook 开关格式无效：需要 boolean';
  }
  if (firstPath === 'modelAvailabilityProbeEnabled') {
    return '批量测活开关格式无效：需要 boolean';
  }
  if (firstPath === 'barkEnabled') {
    return 'Bark 开关格式无效：需要 boolean';
  }
  if (firstPath === 'serverChanEnabled') {
    return 'Server 酱开关格式无效：需要 boolean';
  }
  if (firstPath === 'telegramEnabled') {
    return 'Telegram 开关格式无效：需要 boolean';
  }
  if (firstPath === 'telegramUseSystemProxy') {
    return 'Telegram 使用系统代理格式无效：需要 boolean';
  }
  if (firstPath === 'smtpEnabled') {
    return 'SMTP 开关格式无效：需要 boolean';
  }
  if (firstPath === 'smtpSecure') {
    return 'SMTP 安全连接格式无效：需要 boolean';
  }
  if (firstPath === 'logCleanupUsageLogsEnabled') {
    return '自动清理使用日志格式无效：需要 boolean';
  }
  if (firstPath === 'logCleanupProgramLogsEnabled') {
    return '自动清理程序日志格式无效：需要 boolean';
  }
  return 'Invalid settings payload.';
}

export function parseRuntimeSettingsPayload(input: unknown):
{ success: true; data: RuntimeSettingsPayload } | { success: false; error: string } {
  const result = runtimeSettingsPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseSystemProxyTestPayload(input: unknown):
{ success: true; data: SystemProxyTestPayload } | { success: false; error: string } {
  const result = systemProxyTestPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseDatabaseMigrationPayload(input: unknown):
{ success: true; data: DatabaseMigrationPayload } | { success: false; error: string } {
  const result = databaseMigrationPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseBackupWebdavConfigPayload(input: unknown):
{ success: true; data: BackupWebdavConfigPayload } | { success: false; error: string } {
  const result = backupWebdavConfigPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseBackupImportPayload(input: unknown):
{ success: true; data: BackupImportPayload } | { success: false; error: string } {
  const result = backupImportPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}

export function parseBackupWebdavExportPayload(input: unknown):
{ success: true; data: BackupWebdavExportPayload } | { success: false; error: string } {
  const result = backupWebdavExportPayloadSchema.safeParse(normalizeSettingsPayloadInput(input));
  if (!result.success) {
    return {
      success: false,
      error: formatSettingsPayloadError(result.error),
    };
  }
  return {
    success: true,
    data: result.data,
  };
}
