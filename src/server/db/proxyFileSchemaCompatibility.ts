export type ProxyFileSchemaDialect = 'sqlite' | 'mysql' | 'postgres';

export interface ProxyFileSchemaInspector {
  dialect: ProxyFileSchemaDialect;
  tableExists(table: string): Promise<boolean>;
  columnExists(table: string, column: string): Promise<boolean>;
  execute(sqlText: string): Promise<void>;
}

type ProxyFileColumnCompatibilitySpec = {
  table: 'proxy_files';
  column: string;
  addSql: Record<ProxyFileSchemaDialect, string>;
};

export type ProxyFileTableCompatibilitySpec = {
  table: 'proxy_files';
  createSql: Record<ProxyFileSchemaDialect, string>;
};

export const PROXY_FILE_TABLE_COMPATIBILITY_SPECS: ProxyFileTableCompatibilitySpec[] = [
  {
    table: 'proxy_files',
    createSql: {
      sqlite: 'CREATE TABLE IF NOT EXISTS "proxy_files" ("id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "public_id" TEXT NOT NULL, "owner_type" TEXT NOT NULL, "owner_id" TEXT NOT NULL, "filename" TEXT NOT NULL, "mime_type" TEXT NOT NULL, "purpose" TEXT, "byte_size" INTEGER NOT NULL, "sha256" TEXT NOT NULL, "content_base64" TEXT NOT NULL, "created_at" TEXT, "updated_at" TEXT, "deleted_at" TEXT)',
      postgres: 'CREATE TABLE IF NOT EXISTS "proxy_files" ("id" SERIAL PRIMARY KEY, "public_id" TEXT NOT NULL, "owner_type" TEXT NOT NULL, "owner_id" TEXT NOT NULL, "filename" TEXT NOT NULL, "mime_type" TEXT NOT NULL, "purpose" TEXT, "byte_size" INTEGER NOT NULL, "sha256" TEXT NOT NULL, "content_base64" TEXT NOT NULL, "created_at" TEXT, "updated_at" TEXT, "deleted_at" TEXT)',
      mysql: 'CREATE TABLE IF NOT EXISTS `proxy_files` (`id` INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY, `public_id` VARCHAR(191) NOT NULL, `owner_type` VARCHAR(64) NOT NULL, `owner_id` VARCHAR(191) NOT NULL, `filename` TEXT NOT NULL, `mime_type` VARCHAR(191) NOT NULL, `purpose` TEXT NULL, `byte_size` INTEGER NOT NULL, `sha256` VARCHAR(191) NOT NULL, `content_base64` LONGTEXT NOT NULL, `created_at` TEXT NULL, `updated_at` TEXT NULL, `deleted_at` TEXT NULL)',
    },
  },
];

export const PROXY_FILE_COLUMN_COMPATIBILITY_SPECS: ProxyFileColumnCompatibilitySpec[] = [
  {
    table: 'proxy_files',
    column: 'public_id',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "public_id" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "public_id" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `public_id` VARCHAR(191) NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'owner_type',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "owner_type" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "owner_type" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `owner_type` VARCHAR(64) NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'owner_id',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "owner_id" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "owner_id" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `owner_id` VARCHAR(191) NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'filename',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "filename" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "filename" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `filename` TEXT NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'mime_type',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "mime_type" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "mime_type" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `mime_type` VARCHAR(191) NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'purpose',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "purpose" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "purpose" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `purpose` TEXT NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'byte_size',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "byte_size" INTEGER',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "byte_size" INTEGER',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `byte_size` INTEGER NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'sha256',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "sha256" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "sha256" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `sha256` VARCHAR(191) NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'content_base64',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "content_base64" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "content_base64" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `content_base64` LONGTEXT NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'created_at',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "created_at" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "created_at" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `created_at` TEXT NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'updated_at',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "updated_at" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "updated_at" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `updated_at` TEXT NULL',
    },
  },
  {
    table: 'proxy_files',
    column: 'deleted_at',
    addSql: {
      sqlite: 'ALTER TABLE "proxy_files" ADD COLUMN "deleted_at" TEXT',
      postgres: 'ALTER TABLE "proxy_files" ADD COLUMN "deleted_at" TEXT',
      mysql: 'ALTER TABLE `proxy_files` ADD COLUMN `deleted_at` TEXT NULL',
    },
  },
];

export type ProxyFileIndexCompatibilitySpec = {
  table: 'proxy_files';
  indexName: string;
  createSql: Record<ProxyFileSchemaDialect, string>;
};

export const PROXY_FILE_INDEX_COMPATIBILITY_SPECS: ProxyFileIndexCompatibilitySpec[] = [
  {
    table: 'proxy_files',
    indexName: 'proxy_files_public_id_unique',
    createSql: {
      sqlite: 'CREATE UNIQUE INDEX IF NOT EXISTS "proxy_files_public_id_unique" ON "proxy_files" ("public_id")',
      postgres: 'CREATE UNIQUE INDEX IF NOT EXISTS "proxy_files_public_id_unique" ON "proxy_files" ("public_id")',
      mysql: 'CREATE UNIQUE INDEX `proxy_files_public_id_unique` ON `proxy_files` (`public_id`(191))',
    },
  },
  {
    table: 'proxy_files',
    indexName: 'proxy_files_owner_lookup_idx',
    createSql: {
      sqlite: 'CREATE INDEX IF NOT EXISTS "proxy_files_owner_lookup_idx" ON "proxy_files" ("owner_type", "owner_id", "deleted_at")',
      postgres: 'CREATE INDEX IF NOT EXISTS "proxy_files_owner_lookup_idx" ON "proxy_files" ("owner_type", "owner_id", "deleted_at")',
      mysql: 'CREATE INDEX `proxy_files_owner_lookup_idx` ON `proxy_files` (`owner_type`(64), `owner_id`(191), `deleted_at`(191))',
    },
  },
];

function normalizeSchemaErrorMessage(error: unknown): string {
  if (typeof error === 'object' && error && 'message' in error) {
    return String((error as { message?: unknown }).message || '');
  }
  return String(error || '');
}

function isDuplicateSchemaError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('already exists') || lowered.includes('duplicate') || lowered.includes('relation');
}

async function executeIgnoreDuplicate(inspector: ProxyFileSchemaInspector, sqlText: string): Promise<void> {
  try {
    await inspector.execute(sqlText);
  } catch (error) {
    if (!isDuplicateSchemaError(error)) {
      throw error;
    }
  }
}

export async function ensureProxyFileSchemaCompatibility(inspector: ProxyFileSchemaInspector): Promise<void> {
  const [tableSpec] = PROXY_FILE_TABLE_COMPATIBILITY_SPECS;
  if (!await inspector.tableExists(tableSpec.table)) {
    await executeIgnoreDuplicate(inspector, tableSpec.createSql[inspector.dialect]);
  } else {
    for (const spec of PROXY_FILE_COLUMN_COMPATIBILITY_SPECS) {
      if (await inspector.columnExists(spec.table, spec.column)) continue;
      await executeIgnoreDuplicate(inspector, spec.addSql[inspector.dialect]);
    }
  }

  for (const spec of PROXY_FILE_INDEX_COMPATIBILITY_SPECS) {
    await executeIgnoreDuplicate(inspector, spec.createSql[inspector.dialect]);
  }
}
