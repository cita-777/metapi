import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, beforeAll, beforeEach, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { eq } from 'drizzle-orm';

type DbModule = typeof import('../../db/index.js');

describe('sites disabled models API', () => {
    let app: FastifyInstance;
    let db: DbModule['db'];
    let schema: DbModule['schema'];
    let dataDir = '';

    beforeAll(async () => {
        dataDir = mkdtempSync(join(tmpdir(), 'metapi-sites-disabled-models-'));
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
        await db.delete(schema.siteDisabledModels).run();
        await db.delete(schema.accounts).run();
        await db.delete(schema.sites).run();
    });

    afterAll(async () => {
        await app.close();
        delete process.env.DATA_DIR;
    });

    it('returns empty list for a new site', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        const resp = await app.inject({
            method: 'GET',
            url: `/api/sites/${site.id}/disabled-models`,
        });

        expect(resp.statusCode).toBe(200);
        const body = resp.json();
        expect(body.siteId).toBe(site.id);
        expect(body.models).toEqual([]);
    });

    it('sets and retrieves disabled models', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        const putResp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o', 'claude-sonnet-4-5-20250929'] },
        });

        expect(putResp.statusCode).toBe(200);
        const putBody = putResp.json();
        expect(putBody.models).toHaveLength(2);
        expect(putBody.models).toContain('gpt-4o');
        expect(putBody.models).toContain('claude-sonnet-4-5-20250929');

        const getResp = await app.inject({
            method: 'GET',
            url: `/api/sites/${site.id}/disabled-models`,
        });

        expect(getResp.statusCode).toBe(200);
        const getBody = getResp.json();
        expect(getBody.models).toHaveLength(2);
        expect(getBody.models).toContain('gpt-4o');
        expect(getBody.models).toContain('claude-sonnet-4-5-20250929');
    });

    it('replaces disabled models on subsequent PUT', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o', 'gpt-3.5-turbo'] },
        });

        const putResp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['claude-sonnet-4-5-20250929'] },
        });

        expect(putResp.statusCode).toBe(200);
        const body = putResp.json();
        expect(body.models).toEqual(['claude-sonnet-4-5-20250929']);

        // Verify old models are removed
        const getResp = await app.inject({
            method: 'GET',
            url: `/api/sites/${site.id}/disabled-models`,
        });
        const getBody = getResp.json();
        expect(getBody.models).toEqual(['claude-sonnet-4-5-20250929']);
    });

    it('clears disabled models with empty array', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o'] },
        });

        const putResp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: [] },
        });

        expect(putResp.statusCode).toBe(200);
        expect(putResp.json().models).toEqual([]);

        const getResp = await app.inject({
            method: 'GET',
            url: `/api/sites/${site.id}/disabled-models`,
        });
        expect(getResp.json().models).toEqual([]);
    });

    it('returns 404 for non-existent site', async () => {
        const getResp = await app.inject({
            method: 'GET',
            url: '/api/sites/99999/disabled-models',
        });
        expect(getResp.statusCode).toBe(404);

        const putResp = await app.inject({
            method: 'PUT',
            url: '/api/sites/99999/disabled-models',
            payload: { models: ['gpt-4o'] },
        });
        expect(putResp.statusCode).toBe(404);
    });

    it('returns 400 when models is not an array', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        const resp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: 'not-an-array' },
        });
        expect(resp.statusCode).toBe(400);
    });

    it('returns 400 when models contains non-string entries', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        const resp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o', 123] },
        });
        expect(resp.statusCode).toBe(400);
        expect(resp.json()).toMatchObject({ error: 'Invalid models. Expected string[].' });
    });

    it('deduplicates model names', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'test-site',
            url: 'https://test-site.example.com',
            platform: 'new-api',
        }).returning().get();

        const putResp = await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o', 'gpt-4o', 'gpt-4o'] },
        });

        expect(putResp.statusCode).toBe(200);
        expect(putResp.json().models).toEqual(['gpt-4o']);
    });

    it('deletes disabled models when site is deleted (cascade)', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'delete-test',
            url: 'https://delete-test.example.com',
            platform: 'new-api',
        }).returning().get();

        await app.inject({
            method: 'PUT',
            url: `/api/sites/${site.id}/disabled-models`,
            payload: { models: ['gpt-4o', 'claude-sonnet-4-5-20250929'] },
        });

        await db.delete(schema.sites).where(eq(schema.sites.id, site.id)).run();

        const rows = await db.select().from(schema.siteDisabledModels)
            .where(eq(schema.siteDisabledModels.siteId, site.id))
            .all();
        expect(rows).toHaveLength(0);
    });
});
