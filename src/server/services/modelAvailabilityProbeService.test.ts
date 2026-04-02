import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';

const resolveUpstreamEndpointCandidatesMock = vi.fn();
const buildUpstreamEndpointRequestMock = vi.fn();
const dispatchRuntimeRequestMock = vi.fn();
const resolveChannelProxyUrlMock = vi.fn();
const withSiteRecordProxyRequestInitMock = vi.fn();
const rebuildRoutesOnlyMock = vi.fn();

vi.mock('./upstreamEndpointRuntime.js', () => ({
  resolveUpstreamEndpointCandidates: (...args: unknown[]) => resolveUpstreamEndpointCandidatesMock(...args),
  buildUpstreamEndpointRequest: (...args: unknown[]) => buildUpstreamEndpointRequestMock(...args),
}));

vi.mock('./runtimeDispatch.js', () => ({
  dispatchRuntimeRequest: (...args: unknown[]) => dispatchRuntimeRequestMock(...args),
}));

vi.mock('./siteProxy.js', () => ({
  resolveChannelProxyUrl: (...args: unknown[]) => resolveChannelProxyUrlMock(...args),
  withSiteRecordProxyRequestInit: (...args: unknown[]) => withSiteRecordProxyRequestInitMock(...args),
}));

vi.mock('./routeRefreshWorkflow.js', () => ({
  rebuildRoutesOnly: (...args: unknown[]) => rebuildRoutesOnlyMock(...args),
}));

type DbModule = typeof import('../db/index.js');
type ProbeModule = typeof import('./modelAvailabilityProbeService.js');

describe('modelAvailabilityProbeService', () => {
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let executeModelAvailabilityProbe: ProbeModule['executeModelAvailabilityProbe'];
  let resetProbeExecutionState: ProbeModule['__resetModelAvailabilityProbeExecutionStateForTests'];
  let dataDir = '';
  let originalDataDir: string | undefined;

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-model-probe-'));
    originalDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;

    await import('../db/migrate.js');
    const dbModule = await import('../db/index.js');
    const probeModule = await import('./modelAvailabilityProbeService.js');

    db = dbModule.db;
    schema = dbModule.schema;
    executeModelAvailabilityProbe = probeModule.executeModelAvailabilityProbe;
    resetProbeExecutionState = probeModule.__resetModelAvailabilityProbeExecutionStateForTests;
  });

  beforeEach(async () => {
    resolveUpstreamEndpointCandidatesMock.mockReset();
    buildUpstreamEndpointRequestMock.mockReset();
    dispatchRuntimeRequestMock.mockReset();
    resolveChannelProxyUrlMock.mockReset();
    withSiteRecordProxyRequestInitMock.mockReset();
    rebuildRoutesOnlyMock.mockReset();
    rebuildRoutesOnlyMock.mockResolvedValue(undefined);
    resetProbeExecutionState();

    resolveUpstreamEndpointCandidatesMock.mockResolvedValue(['chat']);
    buildUpstreamEndpointRequestMock.mockImplementation((input: { modelName?: string; endpoint?: string }) => ({
      path: '/v1/chat/completions',
      headers: {
        'content-type': 'application/json',
      },
      body: {
        model: input.modelName || 'unknown-model',
        endpoint: input.endpoint || 'chat',
      },
      runtime: {
        executor: 'default',
        modelName: input.modelName || 'unknown-model',
        stream: false,
      },
    }));
    dispatchRuntimeRequestMock.mockImplementation(async (input: { request?: { body?: { model?: string } } }) => {
      const modelName = String(input?.request?.body?.model || '');
      if (modelName === 'gpt-ghost') {
        return new Response(JSON.stringify({
          error: {
            message: 'The model `gpt-ghost` does not exist',
          },
        }), {
          status: 404,
          headers: {
            'content-type': 'application/json',
          },
        });
      }
      return new Response(JSON.stringify({
        id: 'resp_probe',
        model: modelName,
        choices: [
          {
            message: {
              role: 'assistant',
              content: 'OK',
            },
          },
        ],
      }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      });
    });
    resolveChannelProxyUrlMock.mockReturnValue(null);
    withSiteRecordProxyRequestInitMock.mockImplementation((_site: unknown, init: unknown) => init);

    await db.delete(schema.routeChannels).run();
    await db.delete(schema.tokenRoutes).run();
    await db.delete(schema.tokenModelAvailability).run();
    await db.delete(schema.modelAvailability).run();
    await db.delete(schema.accountTokens).run();
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(() => {
    if (originalDataDir === undefined) {
      delete process.env.DATA_DIR;
    } else {
      process.env.DATA_DIR = originalDataDir;
    }
  });

  it('marks supported rows true and unsupported rows false after probing', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'probe-site',
      url: 'https://probe.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'probe-user',
      accessToken: '',
      apiToken: 'sk-account-probe',
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'apikey',
      }),
    }).returning().get();

    const token = await db.insert(schema.accountTokens).values({
      accountId: account.id,
      name: 'default',
      token: 'sk-token-probe',
      enabled: true,
      isDefault: true,
      valueStatus: 'ready',
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-real',
        available: true,
        checkedAt: '2026-03-20T00:00:00.000Z',
      },
    ]).run();

    await db.insert(schema.tokenModelAvailability).values([
      {
        tokenId: token.id,
        modelName: 'gpt-ghost',
        available: true,
        checkedAt: '2026-03-20T00:00:00.000Z',
      },
    ]).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });

    expect(result.summary).toMatchObject({
      totalAccounts: 1,
      scanned: 2,
      supported: 1,
      unsupported: 1,
      inconclusive: 0,
      skippedModels: 0,
      updatedRows: 2,
      rebuiltRoutes: false,
    });

    const accountRows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(accountRows).toHaveLength(1);
    expect(accountRows[0]?.available).toBe(true);

    const tokenRows = await db.select().from(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, token.id))
      .all();
    expect(tokenRows).toHaveLength(1);
    expect(tokenRows[0]?.available).toBe(false);
  });

  it('skips probing obvious non-conversation models', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'probe-site',
      url: 'https://probe.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'probe-user',
      accessToken: '',
      apiToken: 'sk-account-probe',
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'apikey',
      }),
    }).returning().get();

    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'text-embedding-3-large',
        available: true,
        checkedAt: '2026-03-20T00:00:00.000Z',
      },
    ]).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });

    expect(result.summary).toMatchObject({
      totalAccounts: 1,
      scanned: 1,
      supported: 0,
      unsupported: 0,
      inconclusive: 0,
      skippedModels: 1,
      updatedRows: 0,
    });
    expect(dispatchRuntimeRequestMock).not.toHaveBeenCalled();
  });

  it('does not mark a model unavailable when probe result is inconclusive', async () => {
    dispatchRuntimeRequestMock.mockImplementation(async (input: { request?: { body?: { model?: string } } }) => {
      const modelName = String(input?.request?.body?.model || '');
      if (modelName === 'gpt-flaky') {
        return new Response(JSON.stringify({
          error: {
            message: 'upstream temporary failure',
          },
        }), {
          status: 502,
          headers: {
            'content-type': 'application/json',
          },
        });
      }
      return new Response(JSON.stringify({
        id: 'resp_probe',
        model: modelName,
        choices: [
          {
            message: {
              role: 'assistant',
              content: 'OK',
            },
          },
        ],
      }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      });
    });

    const site = await db.insert(schema.sites).values({
      name: 'probe-site',
      url: 'https://probe.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'probe-user',
      accessToken: '',
      apiToken: 'sk-account-probe',
      status: 'active',
      extraConfig: JSON.stringify({
        credentialMode: 'apikey',
      }),
    }).returning().get();

    const checkedAt = '2026-03-20T00:00:00.000Z';
    await db.insert(schema.modelAvailability).values([
      {
        accountId: account.id,
        modelName: 'gpt-flaky',
        available: true,
        checkedAt,
      },
    ]).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });

    expect(result.summary).toMatchObject({
      totalAccounts: 1,
      scanned: 1,
      supported: 0,
      unsupported: 0,
      inconclusive: 1,
      skippedModels: 0,
      updatedRows: 0,
    });

    const accountRows = await db.select().from(schema.modelAvailability)
      .where(eq(schema.modelAvailability.accountId, account.id))
      .all();
    expect(accountRows).toHaveLength(1);
    expect(accountRows[0]?.available).toBe(true);
    expect(accountRows[0]?.checkedAt).toBe(checkedAt);
  });

  it('does not rebuild routes when probe only refreshes checkedAt and latency', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'stable-site',
      url: 'https://stable.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'stable-user',
      accessToken: '',
      apiToken: 'sk-stable',
      status: 'active',
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-stable',
      available: true,
      checkedAt: '2026-03-20T00:00:00.000Z',
      latencyMs: 123,
    }).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: true,
    });

    expect(result.summary.updatedRows).toBe(1);
    expect(result.summary.rebuiltRoutes).toBe(false);
    expect(rebuildRoutesOnlyMock).not.toHaveBeenCalled();
  });

  it('rebuilds routes when probe flips availability state', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'changed-site',
      url: 'https://changed.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'changed-user',
      accessToken: '',
      apiToken: 'sk-changed',
      status: 'active',
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-changed',
      available: false,
      checkedAt: '2026-03-20T00:00:00.000Z',
    }).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: true,
    });

    expect(result.summary.updatedRows).toBe(1);
    expect(result.summary.rebuiltRoutes).toBe(true);
    expect(rebuildRoutesOnlyMock).toHaveBeenCalledTimes(1);
  });

  it('does not count inactive accounts in probe results', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'inactive-site',
      url: 'https://inactive.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'inactive-user',
      accessToken: '',
      apiToken: 'sk-inactive',
      status: 'disabled',
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-inactive',
      available: true,
      checkedAt: '2026-03-20T00:00:00.000Z',
    }).run();

    const result = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });

    expect(result.summary.totalAccounts).toBe(0);
    expect(result.results).toEqual([]);
    expect(dispatchRuntimeRequestMock).not.toHaveBeenCalled();
  });

  it('skips an account when another probe already holds the execution lease', async () => {
    const site = await db.insert(schema.sites).values({
      name: 'leased-site',
      url: 'https://leased.example.com',
      platform: 'new-api',
      status: 'active',
    }).returning().get();

    const account = await db.insert(schema.accounts).values({
      siteId: site.id,
      username: 'leased-user',
      accessToken: '',
      apiToken: 'sk-leased',
      status: 'active',
    }).returning().get();

    await db.insert(schema.modelAvailability).values({
      accountId: account.id,
      modelName: 'gpt-leased',
      available: true,
      checkedAt: '2026-03-20T00:00:00.000Z',
    }).run();

    let releaseFirstProbe: (() => void) | null = null;
    const firstProbeStarted = new Promise<void>((resolve) => {
      dispatchRuntimeRequestMock.mockImplementationOnce(async () => {
        resolve();
        await new Promise<void>((release) => {
          releaseFirstProbe = release;
        });
        return new Response(JSON.stringify({
          id: 'resp_probe',
          choices: [{ message: { role: 'assistant', content: 'OK' } }],
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      });
    });

    const firstProbe = executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });
    await firstProbeStarted;

    const overlappingProbe = await executeModelAvailabilityProbe({
      accountId: account.id,
      rebuildRoutes: false,
    });

    releaseFirstProbe?.();
    await firstProbe;

    expect(overlappingProbe.summary).toMatchObject({
      totalAccounts: 1,
      skipped: 1,
      scanned: 0,
    });
    expect(overlappingProbe.results[0]).toMatchObject({
      accountId: account.id,
      siteId: site.id,
      status: 'skipped',
      message: 'model availability probe already running for account',
    });
  });
});
