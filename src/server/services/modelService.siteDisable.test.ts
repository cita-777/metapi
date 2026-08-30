import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { and, eq } from 'drizzle-orm';

type DbModule = typeof import('../db/index.js');
type ModelServiceModule = typeof import('./modelService.js');

describe('rebuildTokenRoutesFromAvailability with site disabled models', () => {
    let db: DbModule['db'];
    let schema: DbModule['schema'];
    let rebuildTokenRoutesFromAvailability: ModelServiceModule['rebuildTokenRoutesFromAvailability'];
    let dataDir = '';

    beforeAll(async () => {
        dataDir = mkdtempSync(join(tmpdir(), 'metapi-site-disabled-models-'));
        process.env.DATA_DIR = dataDir;

        await import('../db/migrate.js');
        const dbModule = await import('../db/index.js');
        const modelService = await import('./modelService.js');

        db = dbModule.db;
        schema = dbModule.schema;
        rebuildTokenRoutesFromAvailability = modelService.rebuildTokenRoutesFromAvailability;
    });

    beforeEach(async () => {
        await db.delete(schema.routeChannels).run();
        await db.delete(schema.tokenRoutes).run();
        await db.delete(schema.tokenModelAvailability).run();
        await db.delete(schema.modelAvailability).run();
        await db.delete(schema.siteDisabledModels).run();
        await db.delete(schema.settings).run();
        await db.delete(schema.accountTokens).run();
        await db.delete(schema.accounts).run();
        await db.delete(schema.sites).run();
    });

    afterAll(() => {
        delete process.env.DATA_DIR;
    });

    it('does not create route/channel for a model disabled on its site', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'site-a',
            url: 'https://site-a.example.com',
            platform: 'new-api',
        }).returning().get();

        const account = await db.insert(schema.accounts).values({
            siteId: site.id,
            username: 'user-a',
            accessToken: '',
            apiToken: 'sk-test-disabled',
            status: 'active',
            extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
        }).returning().get();

        await db.insert(schema.modelAvailability).values({
            accountId: account.id,
            modelName: 'gpt-4o',
            available: true,
            latencyMs: 500,
            checkedAt: '2026-03-12T00:00:00.000Z',
        }).run();

        // Disable gpt-4o for this site
        await db.insert(schema.siteDisabledModels).values({
            siteId: site.id,
            modelName: 'gpt-4o',
        }).run();

        const rebuild = await rebuildTokenRoutesFromAvailability();

        expect(rebuild.models).toBe(0);

        const routes = await db.select().from(schema.tokenRoutes)
            .where(eq(schema.tokenRoutes.modelPattern, 'gpt-4o'))
            .all();
        expect(routes).toHaveLength(0);
    });

    it('only blocks the disabled site, not other sites providing the same model', async () => {
        const siteA = await db.insert(schema.sites).values({
            name: 'site-a',
            url: 'https://site-a.example.com',
            platform: 'new-api',
        }).returning().get();

        const siteB = await db.insert(schema.sites).values({
            name: 'site-b',
            url: 'https://site-b.example.com',
            platform: 'new-api',
        }).returning().get();

        const accountA = await db.insert(schema.accounts).values({
            siteId: siteA.id,
            username: 'user-a',
            accessToken: '',
            apiToken: 'sk-site-a',
            status: 'active',
            extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
        }).returning().get();

        const accountB = await db.insert(schema.accounts).values({
            siteId: siteB.id,
            username: 'user-b',
            accessToken: '',
            apiToken: 'sk-site-b',
            status: 'active',
            extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
        }).returning().get();

        // Both sites have the same model
        await db.insert(schema.modelAvailability).values([
            { accountId: accountA.id, modelName: 'claude-sonnet-4-5-20250929', available: true, latencyMs: 300 },
            { accountId: accountB.id, modelName: 'claude-sonnet-4-5-20250929', available: true, latencyMs: 400 },
        ]).run();

        // Disable the model only on site A
        await db.insert(schema.siteDisabledModels).values({
            siteId: siteA.id,
            modelName: 'claude-sonnet-4-5-20250929',
        }).run();

        const rebuild = await rebuildTokenRoutesFromAvailability();

        expect(rebuild.models).toBe(1);

        const route = await db.select().from(schema.tokenRoutes)
            .where(eq(schema.tokenRoutes.modelPattern, 'claude-sonnet-4-5-20250929'))
            .get();
        expect(route).toBeDefined();

        const channels = await db.select().from(schema.routeChannels)
            .where(eq(schema.routeChannels.routeId, route!.id))
            .all();

        // Only site B's channel should exist
        expect(channels).toHaveLength(1);
        expect(channels[0]?.accountId).toBe(accountB.id);
    });

    it('allows model when no disabled models are configured', async () => {
        const site = await db.insert(schema.sites).values({
            name: 'normal-site',
            url: 'https://normal.example.com',
            platform: 'new-api',
        }).returning().get();

        const account = await db.insert(schema.accounts).values({
            siteId: site.id,
            username: 'normal-user',
            accessToken: '',
            apiToken: 'sk-normal',
            status: 'active',
            extraConfig: JSON.stringify({ credentialMode: 'apikey' }),
        }).returning().get();

        await db.insert(schema.modelAvailability).values({
            accountId: account.id,
            modelName: 'gpt-5',
            available: true,
            latencyMs: 200,
        }).run();

        const rebuild = await rebuildTokenRoutesFromAvailability();

        expect(rebuild.models).toBe(1);

        const route = await db.select().from(schema.tokenRoutes)
            .where(eq(schema.tokenRoutes.modelPattern, 'gpt-5'))
            .get();
        expect(route).toBeDefined();
    });

    it('does not repopulate a pattern group with a model filtered from the rebuild', async () => {
        const disabledSite = await db.insert(schema.sites).values({
            name: 'filtered-pattern-disabled-site',
            url: 'https://filtered-pattern-disabled-site.example.com',
            platform: 'new-api',
        }).returning().get();
        const allowedSite = await db.insert(schema.sites).values({
            name: 'filtered-pattern-allowed-site',
            url: 'https://filtered-pattern-allowed-site.example.com',
            platform: 'new-api',
        }).returning().get();
        const disabledAccount = await db.insert(schema.accounts).values({
            siteId: disabledSite.id,
            username: 'filtered-pattern-disabled-user',
            accessToken: 'filtered-pattern-access',
            status: 'active',
        }).returning().get();
        const allowedAccount = await db.insert(schema.accounts).values({
            siteId: allowedSite.id,
            username: 'filtered-pattern-allowed-user',
            accessToken: 'filtered-pattern-allowed-access',
            status: 'active',
        }).returning().get();
        const disabledToken = await db.insert(schema.accountTokens).values({
            accountId: disabledAccount.id,
            name: 'default',
            token: 'sk-filtered-pattern',
            source: 'manual',
            enabled: true,
            isDefault: true,
        }).returning().get();
        const allowedToken = await db.insert(schema.accountTokens).values({
            accountId: allowedAccount.id,
            name: 'default',
            token: 'sk-filtered-pattern-allowed',
            source: 'manual',
            enabled: true,
            isDefault: true,
        }).returning().get();
        await db.insert(schema.tokenModelAvailability).values({
            tokenId: disabledToken.id,
            modelName: 'gpt-filtered',
            available: true,
        }).run();
        await db.insert(schema.tokenModelAvailability).values({
            tokenId: allowedToken.id,
            modelName: 'gpt-filtered',
            available: true,
        }).run();
        const exactRoute = await db.insert(schema.tokenRoutes).values({
            modelPattern: 'gpt-filtered',
            enabled: true,
        }).returning().get();
        const patternRoute = await db.insert(schema.tokenRoutes).values({
            modelPattern: '*',
            displayName: 'all-models',
            enabled: true,
        }).returning().get();
        await db.insert(schema.routeChannels).values([
            {
            routeId: exactRoute.id,
            accountId: disabledAccount.id,
            tokenId: disabledToken.id,
            sourceModel: 'gpt-filtered',
                enabled: true,
                manualOverride: false,
            },
            {
            routeId: patternRoute.id,
            accountId: disabledAccount.id,
            tokenId: disabledToken.id,
                sourceModel: 'gpt-filtered',
                enabled: true,
                manualOverride: false,
            },
        ]).run();
        await db.insert(schema.siteDisabledModels).values({
            siteId: disabledSite.id,
            modelName: 'gpt-filtered',
        }).run();

        const rebuild = await rebuildTokenRoutesFromAvailability();
        expect(rebuild.removedChannels).toBeGreaterThan(0);
        const patternChannels = await db.select().from(schema.routeChannels)
            .where(eq(schema.routeChannels.routeId, patternRoute.id))
            .all();
        expect(patternChannels).toHaveLength(1);
        expect(patternChannels[0]?.accountId).toBe(allowedAccount.id);
        expect(patternChannels[0]?.tokenId).toBe(allowedToken.id);
    });
});
