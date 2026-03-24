import { sql } from 'drizzle-orm';

type DbType = 'sqlite' | 'mysql' | 'postgres';

type CliOptions = {
  dbType?: string;
  dbUrl?: string;
};

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] || '';
    if (!arg.startsWith('--')) continue;

    const [rawKey, rawValue] = arg.slice(2).split('=', 2);
    const key = rawKey.trim();
    const value = rawValue !== undefined ? rawValue : (argv[i + 1]?.startsWith('--') ? '' : argv[++i] || '');

    if (key === 'db-type') options.dbType = value.trim();
    if (key === 'db-url') options.dbUrl = value.trim();
  }
  return options;
}

function normalizeDbType(input: string | undefined): DbType {
  const normalized = (input || '').trim().toLowerCase();
  if (normalized === 'mysql') return 'mysql';
  if (normalized === 'postgres' || normalized === 'postgresql') return 'postgres';
  return 'sqlite';
}

function normalizeFirstScalar(value: unknown): number | string | null {
  if (value === undefined || value === null) return null;
  if (typeof value === 'number' || typeof value === 'string') return value;

  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    return normalizeFirstScalar(value[0]);
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (Array.isArray(record.rows)) {
      return normalizeFirstScalar(record.rows);
    }

    const scalar = Object.values(record)[0];
    return normalizeFirstScalar(scalar);
  }

  return null;
}

async function selectScalar(db: any, query: ReturnType<typeof sql>): Promise<number | string | null> {
  if (typeof db?.get === 'function') {
    return normalizeFirstScalar(await db.get(query));
  }
  if (typeof db?.all === 'function') {
    return normalizeFirstScalar(await db.all(query));
  }
  if (typeof db?.values === 'function') {
    return normalizeFirstScalar(await db.values(query));
  }
  if (typeof db?.execute === 'function') {
    return normalizeFirstScalar(await db.execute(query));
  }
  throw new Error('database client does not expose a scalar query method');
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.dbType) process.env.DB_TYPE = options.dbType;
  if (options.dbUrl !== undefined) process.env.DB_URL = options.dbUrl;

  const { config } = await import('../../src/server/config.js');
  const { db, runtimeDbDialect, closeDbConnections } = await import('../../src/server/db/index.js');

  try {
    const dbType = normalizeDbType(config.dbType || options.dbType);
    const dbUrl = (config.dbUrl || '').trim();

    if ((dbType === 'mysql' || dbType === 'postgres') && !dbUrl) {
      throw new Error(`DB_URL is required for DB_TYPE=${dbType}`);
    }

    console.log(`[db-smoke] start dbType=${dbType} runtime=${runtimeDbDialect}`);
    if (dbUrl) {
      console.log(`[db-smoke] dbUrl=${dbUrl}`);
    } else {
      console.log('[db-smoke] dbUrl=(empty, using default sqlite path)');
    }

    const pingScalar = await selectScalar(db, sql`select 1 as ok`);
    if (Number(pingScalar) !== 1) {
      throw new Error(`unexpected ping result: ${JSON.stringify(pingScalar)}`);
    }
    console.log('[db-smoke] ping ok');

    const txScalar = await db.transaction(async (tx: any) => selectScalar(tx, sql`select 1 as ok`));
    if (Number(txScalar) !== 1) {
      throw new Error(`unexpected transaction ping result: ${JSON.stringify(txScalar)}`);
    }
    console.log('[db-smoke] transaction ok');

    const version = dbType === 'sqlite'
      ? await selectScalar(db, sql`select sqlite_version() as v`)
      : await selectScalar(db, sql`select version() as v`);
    if (typeof version !== 'string' || version.trim().length === 0) {
      throw new Error(`failed to read server version: ${JSON.stringify(version)}`);
    }
    console.log(`[db-smoke] version=${version.slice(0, 120)}`);

    console.log('[db-smoke] success');
  } finally {
    await closeDbConnections();
  }
}

main().catch((error) => {
  console.error('[db-smoke] failed');
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
