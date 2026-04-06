import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

type DbModule = typeof import('./index.js');

describe('db proxy query wrapper', () => {
  let testUtils: DbModule['__dbProxyTestUtils'];

  beforeAll(async () => {
    process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'metapi-db-proxy-wrap-'));
    const dbModule = await import('./index.js');
    testUtils = dbModule.__dbProxyTestUtils;
  });

  beforeEach(() => {
    testUtils.resetPostgresJsonTextParsersInstallStateForTests();
  });

  it('wraps thenable query builders and provides all/get shims', async () => {
    const execute = vi.fn(async () => [{ id: 1, name: 'demo' }]);
    const queryLike = {
      execute,
      where() {
        return this;
      },
      then(onFulfilled: (v: unknown) => unknown, onRejected?: (e: unknown) => unknown) {
        return Promise.resolve(execute()).then(onFulfilled, onRejected);
      },
    };

    expect(testUtils.shouldWrapObject(queryLike)).toBe(true);
    const wrapped = testUtils.wrapQueryLike(queryLike as any);

    const rows = await wrapped.where().all();
    const row = await wrapped.where().get();

    expect(execute).toHaveBeenCalledTimes(2);
    expect(rows).toEqual([{ id: 1, name: 'demo' }]);
    expect(row).toEqual({ id: 1, name: 'demo' });
  });

  it('provides run shim for thenable query builders', async () => {
    const execute = vi.fn(async () => [{ changes: 3, lastInsertRowid: 9 }]);
    const queryLike = {
      execute,
      then(onFulfilled: (v: unknown) => unknown, onRejected?: (e: unknown) => unknown) {
        return Promise.resolve(execute()).then(onFulfilled, onRejected);
      },
    };

    const wrapped = testUtils.wrapQueryLike(queryLike as any);
    const runResult = await wrapped.run();

    expect(execute).toHaveBeenCalledTimes(1);
    expect(runResult).toEqual({ changes: 3, lastInsertRowid: 9 });
    expect(testUtils.shouldWrapObject(Promise.resolve())).toBe(false);
  });

  it('normalizes postgres inserts with returning ids for numeric-id tables', async () => {
    const query = vi.fn(async () => ({
      rows: [{ id: 42 }],
      rowCount: 1,
    }));
    const executor = { query };

    const result = await testUtils.pgProxyQuery(
      executor as any,
      'insert into "sites" ("name") values ($1)',
      ['demo'],
      'execute',
    );

    expect(query).toHaveBeenCalledWith({
      text: 'insert into "sites" ("name") values ($1) returning id',
      values: ['demo'],
    });
    expect(result).toEqual({
      rows: [{ changes: 1, lastInsertRowid: 42 }],
    });
  });

  it('normalizes postgres inserts with returning ids for oauth route units', async () => {
    const query = vi.fn(async () => ({
      rows: [{ id: 7 }],
      rowCount: 1,
    }));
    const executor = { query };

    const result = await testUtils.pgProxyQuery(
      executor as any,
      'insert into "oauth_route_units" ("site_id", "provider", "name") values ($1, $2, $3)',
      [1, 'codex', 'pool-a'],
      'execute',
    );

    expect(query).toHaveBeenCalledWith({
      text: 'insert into "oauth_route_units" ("site_id", "provider", "name") values ($1, $2, $3) returning id',
      values: [1, 'codex', 'pool-a'],
    });
    expect(result).toEqual({
      rows: [{ changes: 1, lastInsertRowid: 7 }],
    });
  });

  it('builds mysql pool options with jsonStrings enabled', () => {
    expect(testUtils.buildMysqlPoolOptions('mysql://root:pass@db.example.com:3306/metapi', false)).toMatchObject({
      uri: 'mysql://root:pass@db.example.com:3306/metapi',
      jsonStrings: true,
    });
    expect(testUtils.buildMysqlPoolOptions('mysql://root:pass@db.example.com:3306/metapi', true)).toMatchObject({
      uri: 'mysql://root:pass@db.example.com:3306/metapi',
      jsonStrings: true,
      ssl: { rejectUnauthorized: false },
    });
  });

  it('builds postgres pool options with ssl when requested', () => {
    expect(testUtils.buildPostgresPoolOptions('postgres://user:pass@db.example.com:5432/metapi', false)).toEqual({
      connectionString: 'postgres://user:pass@db.example.com:5432/metapi',
    });
    expect(testUtils.buildPostgresPoolOptions('postgres://user:pass@db.example.com:5432/metapi', true)).toMatchObject({
      connectionString: 'postgres://user:pass@db.example.com:5432/metapi',
      ssl: { rejectUnauthorized: false },
    });
  });

  it('installs postgres JSON text parsers idempotently', () => {
    const setTypeParser = vi.fn();
    const fakeTypes = {
      builtins: {
        JSON: 114,
        JSONB: 3802,
      },
      setTypeParser,
    };

    testUtils.installPostgresJsonTextParsers(fakeTypes as any);
    testUtils.installPostgresJsonTextParsers(fakeTypes as any);

    expect(setTypeParser).toHaveBeenCalledTimes(2);
    expect(setTypeParser).toHaveBeenNthCalledWith(1, 114, 'text', expect.any(Function));
    expect(setTypeParser).toHaveBeenNthCalledWith(2, 3802, 'text', expect.any(Function));
    const parser = setTypeParser.mock.calls[0][2] as (value: string) => string;
    expect(parser('{"ok":true}')).toBe('{"ok":true}');
  });
});
