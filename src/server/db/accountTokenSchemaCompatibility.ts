export type AccountTokenSchemaDialect = 'sqlite' | 'mysql' | 'postgres';

export interface AccountTokenSchemaInspector {
  dialect: AccountTokenSchemaDialect;
  tableExists(table: string): Promise<boolean>;
  columnExists(table: string, column: string): Promise<boolean>;
  execute(sqlText: string): Promise<void>;
}

type AccountTokenColumnCompatibilitySpec = {
  table: 'account_tokens';
  column: string;
  addSql: Record<AccountTokenSchemaDialect, string>;
};

const ACCOUNT_TOKEN_COLUMN_COMPATIBILITY_SPECS: AccountTokenColumnCompatibilitySpec[] = [
  {
    table: 'account_tokens',
    column: 'token_group',
    addSql: {
      sqlite: 'ALTER TABLE account_tokens ADD COLUMN token_group text;',
      mysql: 'ALTER TABLE `account_tokens` ADD COLUMN `token_group` TEXT NULL',
      postgres: 'ALTER TABLE "account_tokens" ADD COLUMN "token_group" TEXT',
    },
  },
  {
    table: 'account_tokens',
    column: 'value_status',
    addSql: {
      sqlite: "ALTER TABLE account_tokens ADD COLUMN value_status text NOT NULL DEFAULT 'ready';",
      mysql: "ALTER TABLE `account_tokens` ADD COLUMN `value_status` VARCHAR(191) NOT NULL DEFAULT 'ready'",
      postgres: "ALTER TABLE \"account_tokens\" ADD COLUMN \"value_status\" TEXT NOT NULL DEFAULT 'ready'",
    },
  },
];

function normalizeSchemaErrorMessage(error: unknown): string {
  if (typeof error === 'object' && error && 'message' in error) {
    return String((error as { message?: unknown }).message || '');
  }
  return String(error || '');
}

function isDuplicateColumnError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate column')
    || lowered.includes('already exists')
    || lowered.includes('duplicate column name');
}

async function executeAddColumn(inspector: AccountTokenSchemaInspector, sqlText: string): Promise<void> {
  try {
    await inspector.execute(sqlText);
  } catch (error) {
    if (!isDuplicateColumnError(error)) {
      throw error;
    }
  }
}

export async function ensureAccountTokenSchemaCompatibility(inspector: AccountTokenSchemaInspector): Promise<void> {
  for (const spec of ACCOUNT_TOKEN_COLUMN_COMPATIBILITY_SPECS) {
    const hasTable = await inspector.tableExists(spec.table);
    if (!hasTable) {
      continue;
    }

    const hasColumn = await inspector.columnExists(spec.table, spec.column);
    if (!hasColumn) {
      await executeAddColumn(inspector, spec.addSql[inspector.dialect]);
    }
  }
}
