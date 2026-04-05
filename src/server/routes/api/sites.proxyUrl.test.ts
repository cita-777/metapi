import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';

type DbModule = typeof import('../../db/index.js');

describe('sites proxy settings', () => {
  let app: FastifyInstance;
  let db: DbModule['db'];
  let schema: DbModule['schema'];
  let dataDir = '';

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'metapi-sites-proxy-url-'));
    process.env.DATA_DIR = dataDir;

    await import('../../db/migrate.js');
    const dbModule = await import('../../db/index.js');
    const routesModule = await import('./sites.js');
    db = dbModule.db;
    schema = dbModule.schema;

    app = Fastify();
    await app.register(routesModule.sitesRoutes);
  });

  beforeEach(async () => {
    await db.delete(schema.accounts).run();
    await db.delete(schema.sites).run();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.DATA_DIR;
  });

  it('stores proxy settings, external checkin url, and custom headers when creating a site', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'proxy-site',
        url: 'https://proxy-site.example.com',
        platform: 'new-api',
        proxyUrl: 'socks5://127.0.0.1:1080',
        useSystemProxy: true,
        customHeaders: JSON.stringify({
          'cf-access-client-id': 'site-client-id',
          'x-site-scope': 'internal',
        }),
        externalCheckinUrl: 'https://checkin.example.com/welfare',
        globalWeight: 1.5,
      },
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json() as {
      proxyUrl?: string | null;
      useSystemProxy?: boolean;
      customHeaders?: string | null;
      externalCheckinUrl?: string | null;
      globalWeight?: number;
    };
    expect(payload.proxyUrl).toBe('socks5://127.0.0.1:1080');
    expect(payload.useSystemProxy).toBe(true);
    expect(payload.customHeaders).toBe('{"cf-access-client-id":"site-client-id","x-site-scope":"internal"}');
    expect(payload.externalCheckinUrl).toBe('https://checkin.example.com/welfare');
    expect(payload.globalWeight).toBe(1.5);
  });

  it('returns a conflict response when the same platform and url already exist', async () => {
    const first = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'existing-site',
        url: 'https://duplicate-site.example.com/',
        platform: 'new-api',
      },
    });
    expect(first.statusCode).toBe(200);

    const duplicate = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'duplicate-site',
        url: 'https://duplicate-site.example.com',
        platform: 'new-api',
      },
    });

    expect(duplicate.statusCode).toBe(409);
    expect((duplicate.json() as { error?: string }).error).toContain('already exists');
  });

  it('normalizes platform before conflict checks when creating a site', async () => {
    const first = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'existing-site',
        url: 'https://duplicate-site.example.com/',
        platform: 'new-api',
      },
    });
    expect(first.statusCode).toBe(200);

    const duplicate = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'duplicate-site',
        url: 'https://duplicate-site.example.com',
        platform: '  new-api  ',
      },
    });

    expect(duplicate.statusCode).toBe(409);
    expect((duplicate.json() as { error?: string }).error).toContain('already exists');
  });

  it('rejects invalid useSystemProxy flag', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'proxy-site',
        url: 'https://proxy-site.example.com',
        platform: 'new-api',
        useSystemProxy: 'not-a-boolean',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid useSystemProxy');
  });

  it('rejects invalid proxy url', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'proxy-site',
        url: 'https://proxy-site.example.com',
        platform: 'new-api',
        proxyUrl: 'not-a-proxy',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid proxyUrl');
  });

  it('rejects invalid site global weight', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'weight-site',
        url: 'https://weight-site.example.com',
        platform: 'new-api',
        globalWeight: 0,
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid globalWeight');
  });

  it('rejects invalid external checkin url', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'welfare-site',
        url: 'https://weight-site.example.com',
        platform: 'new-api',
        externalCheckinUrl: 'ftp://invalid.example.com',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid externalCheckinUrl');
  });

  it('updates per-site proxy settings for an existing site', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'toggle-site',
        url: 'https://toggle-site.example.com',
        platform: 'new-api',
        useSystemProxy: false,
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: {
        proxyUrl: 'http://127.0.0.1:8080',
        useSystemProxy: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json() as { proxyUrl?: string | null; useSystemProxy?: boolean };
    expect(payload.proxyUrl).toBe('http://127.0.0.1:8080');
    expect(payload.useSystemProxy).toBe(true);
  });

  it('clears optional editor fields when updating a site with empty strings', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'editable-site',
        url: 'https://editable-site.example.com',
        platform: 'new-api',
        proxyUrl: 'http://127.0.0.1:8080',
        useSystemProxy: true,
        customHeaders: JSON.stringify({
          'x-site-scope': 'internal',
        }),
        externalCheckinUrl: 'https://checkin.example.com/welfare',
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: {
        proxyUrl: '',
        useSystemProxy: false,
        customHeaders: '',
        externalCheckinUrl: '',
      },
    });

    expect(response.statusCode).toBe(200);
    const payload = response.json() as {
      proxyUrl?: string | null;
      useSystemProxy?: boolean;
      customHeaders?: string | null;
      externalCheckinUrl?: string | null;
    };
    expect(payload.proxyUrl).toBeNull();
    expect(payload.useSystemProxy).toBe(false);
    expect(payload.customHeaders).toBeNull();
    expect(payload.externalCheckinUrl).toBeNull();
  });

  it('returns a conflict response when updating a site to an existing platform and url', async () => {
    const first = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'first-site',
        url: 'https://first-site.example.com',
        platform: 'new-api',
      },
    });
    expect(first.statusCode).toBe(200);

    const second = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'second-site',
        url: 'https://second-site.example.com',
        platform: 'new-api',
      },
    });
    expect(second.statusCode).toBe(200);

    const { id } = second.json() as { id: number };
    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${id}`,
      payload: {
        url: 'https://first-site.example.com/',
        platform: 'new-api',
      },
    });

    expect(response.statusCode).toBe(409);
    expect((response.json() as { error?: string }).error).toContain('already exists');
  });

  it('rejects blank platform updates instead of persisting an empty platform', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'editable-site',
        url: 'https://editable-site.example.com',
        platform: 'new-api',
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: {
        platform: '   ',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('platform');
  });

  it('rejects invalid custom headers json', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'headers-site',
        url: 'https://headers-site.example.com',
        platform: 'new-api',
        customHeaders: '{invalid-json}',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid customHeaders');
  });

  it('rejects custom headers with non-string values', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'headers-site',
        url: 'https://headers-site.example.com',
        platform: 'new-api',
        customHeaders: JSON.stringify({
          'x-site-scope': true,
        }),
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('must use a string value');
  });

  it('rejects create payloads whose name is not a string', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 123,
        url: 'https://typed-site.example.com',
        platform: 'new-api',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid name');
  });

  it('rejects update payloads whose url is not a string', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'typed-site',
        url: 'https://typed-site.example.com',
        platform: 'new-api',
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: {
        url: 123,
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid url');
  });

  it('rejects create payloads that are not objects', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: [],
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid site payload');
  });

  it('rejects update payloads that are not objects', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'typed-site',
        url: 'https://typed-site.example.com',
        platform: 'new-api',
      },
    });
    expect(created.statusCode).toBe(200);
    const site = created.json() as { id: number };

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${site.id}`,
      payload: [],
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('Invalid site payload');
  });

  it('detects Aliyun CodingPlan endpoints with initialization preset metadata', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites/detect',
      payload: {
        url: 'https://coding.dashscope.aliyuncs.com/v1',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      platform: 'openai',
      initializationPresetId: 'codingplan-openai',
    });
  });

  it('creates CodingPlan sites without explicit platform by using preset-backed detection', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Aliyun CodingPlan',
        url: 'https://coding.dashscope.aliyuncs.com/v1',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      name: 'Aliyun CodingPlan',
      platform: 'openai',
      initializationPresetId: 'codingplan-openai',
    });
  });

  it('rejects empty detect payload urls at the route boundary', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites/detect',
      payload: {
        url: '   ',
      },
    });

    expect(response.statusCode).toBe(400);
    expect((response.json() as { error?: string }).error).toContain('url');
  });

  it('does not force CodingPlan preset metadata when the user explicitly chooses generic openai', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Aliyun Generic OpenAI',
        url: 'https://coding.dashscope.aliyuncs.com/v1',
        platform: 'openai',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      name: 'Aliyun Generic OpenAI',
      platform: 'openai',
    });
    expect(response.json()).not.toHaveProperty('initializationPresetId');
  });

  it('preserves explicit preset metadata even when the preset uses a custom gateway url', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Aliyun CodingPlan Gateway',
        url: 'https://gateway.example.com/coding/v1',
        platform: 'openai',
        initializationPresetId: 'codingplan-openai',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      name: 'Aliyun CodingPlan Gateway',
      platform: 'openai',
      initializationPresetId: 'codingplan-openai',
    });
  });

  it('canonicalizes create payload url, strips known non-api api suffixes, and normalizes platform before persistence and conflict checks', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Aliyun Generic OpenAI',
        url: ' coding.dashscope.aliyuncs.com/v1/ ',
        platform: ' OPENAI ',
      },
    });

    expect(created.statusCode).toBe(200);
    expect(created.json()).toMatchObject({
      name: 'Aliyun Generic OpenAI',
      url: 'https://coding.dashscope.aliyuncs.com',
      platform: 'openai',
    });

    const duplicate = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Aliyun Generic OpenAI Duplicate',
        url: 'https://coding.dashscope.aliyuncs.com',
        platform: 'openai',
      },
    });

    expect(duplicate.statusCode).toBe(409);
    expect((duplicate.json() as { error?: string }).error).toContain('already exists');
  });

  it('canonicalizes update payload url, strips known non-api api suffixes, and normalizes platform before saving', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Update Canonicalization',
        url: 'https://update-canonicalization.example.com',
        platform: 'new-api',
      },
    });
    expect(created.statusCode).toBe(200);

    const response = await app.inject({
      method: 'PUT',
      url: `/api/sites/${(created.json() as { id: number }).id}`,
      payload: {
        url: ' coding.dashscope.aliyuncs.com/v1/ ',
        platform: ' OPENAI ',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      url: 'https://coding.dashscope.aliyuncs.com',
      platform: 'openai',
    });
  });

  it('preserves /api-prefixed main site paths instead of auto-stripping them', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'API Path Site',
        url: 'https://panel.example.com/api/v1/models',
        platform: 'openai',
      },
    });

    expect(created.statusCode).toBe(200);
    expect(created.json()).toMatchObject({
      url: 'https://panel.example.com/api/v1/models',
      platform: 'openai',
    });
  });

  it('preserves known semantic paths like codex backend-api roots', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Codex Site',
        url: 'https://chatgpt.com/backend-api/codex',
        platform: 'codex',
      },
    });

    expect(created.statusCode).toBe(200);
    expect(created.json()).toMatchObject({
      url: 'https://chatgpt.com/backend-api/codex',
      platform: 'codex',
    });
  });

  it('returns canonical root urls for detect requests that hit known non-api api suffixes', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites/detect',
      payload: {
        url: 'https://api.openai.com/v1/messages',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      url: 'https://api.openai.com',
      platform: 'openai',
    });
  });

  it('does not strip /api-prefixed paths from detect responses', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites/detect',
      payload: {
        url: 'https://api.openai.com/api/v1/models',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      url: 'https://api.openai.com/api/v1/models',
      platform: 'openai',
    });
  });

  it('detects Zhipu Coding Plan OpenAI endpoint with initialization preset metadata', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites/detect',
      payload: {
        url: 'https://open.bigmodel.cn/api/coding/paas/v4',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      platform: 'openai',
      initializationPresetId: 'zhipu-coding-plan-openai',
    });
  });

  it('detects additional vendor-specific code endpoints with initialization preset metadata', async () => {
    const cases = [
      { url: 'https://api.deepseek.com/v1', platform: 'openai', initializationPresetId: 'deepseek-openai' },
      { url: 'https://api.deepseek.com/anthropic', platform: 'claude', initializationPresetId: 'deepseek-claude' },
      { url: 'https://api.moonshot.cn/v1', platform: 'openai', initializationPresetId: 'moonshot-openai' },
      { url: 'https://api.moonshot.cn/anthropic', platform: 'claude', initializationPresetId: 'moonshot-claude' },
      { url: 'https://api.minimaxi.com/v1', platform: 'openai', initializationPresetId: 'minimax-openai' },
      { url: 'https://api.minimaxi.com/anthropic', platform: 'claude', initializationPresetId: 'minimax-claude' },
      { url: 'https://api-inference.modelscope.cn/v1', platform: 'openai', initializationPresetId: 'modelscope-openai' },
      { url: 'https://api-inference.modelscope.cn', platform: 'claude', initializationPresetId: 'modelscope-claude' },
      { url: 'https://ark.cn-beijing.volces.com/api/coding/v3', platform: 'openai', initializationPresetId: 'doubao-coding-openai' },
    ];

    for (const testCase of cases) {
      const response = await app.inject({
        method: 'POST',
        url: '/api/sites/detect',
        payload: { url: testCase.url },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({
        platform: testCase.platform,
        initializationPresetId: testCase.initializationPresetId,
      });
    }
  });

  it('creates Doubao Coding Plan sites without explicit platform by using preset-backed detection', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/sites',
      payload: {
        name: 'Doubao Coding Plan',
        url: 'https://ark.cn-beijing.volces.com/api/coding/v3',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      name: 'Doubao Coding Plan',
      platform: 'openai',
      initializationPresetId: 'doubao-coding-openai',
    });
  });
});
