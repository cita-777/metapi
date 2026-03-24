import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

function expectNoDirectModelServiceRouteRefresh(source: string): void {
  expect(source).not.toMatch(/import\s*\{[^}]*\brefreshModelsAndRebuildRoutes\b[^}]*\}\s*from\s*['"][^'"]*modelService\.js['"]/m);
  expect(source).not.toMatch(/import\s*\{[^}]*\brebuildTokenRoutesFromAvailability\b[^}]*\}\s*from\s*['"][^'"]*modelService\.js['"]/m);
}

describe('route refresh workflow architecture boundaries', () => {
  it('keeps api controllers on the shared route refresh workflow instead of modelService', () => {
    const tokensSource = readSource('./tokens.ts');
    const settingsSource = readSource('./settings.ts');
    const statsSource = readSource('./stats.ts');

    expect(tokensSource).toContain("from '../../services/routeRefreshWorkflow.js'");
    expect(tokensSource).not.toContain("from '../../services/modelService.js'");

    expect(settingsSource).toContain("from '../../services/routeRefreshWorkflow.js'");
    expect(settingsSource).not.toContain("from '../../services/modelService.js'");

    expect(statsSource).toContain("from '../../services/routeRefreshWorkflow.js'");
    expectNoDirectModelServiceRouteRefresh(statsSource);
    expect(tokensSource).toContain('const rebuild = await routeRefreshWorkflow.rebuildRoutesOnly();');
    expect(statsSource).toContain('const rebuild = await routeRefreshWorkflow.rebuildRoutesOnly();');
  });

  it('keeps proxy fallback refreshes and scheduler hooks on the route refresh workflow', () => {
    const completionsSource = readSource('../proxy/completions.ts');
    const embeddingsSource = readSource('../proxy/embeddings.ts');
    const imagesSource = readSource('../proxy/images.ts');
    const modelsRouteSource = readSource('../proxy/models.ts');
    const searchSource = readSource('../proxy/search.ts');
    const videosSource = readSource('../proxy/videos.ts');
    const schedulerSource = readSource('../../services/checkinScheduler.ts');
    const oauthServiceSource = readSource('../../services/oauth/service.ts');
    const sharedSurfaceSource = readSource('../../proxy-core/surfaces/sharedSurface.ts');
    const geminiSurfaceSource = readSource('../../proxy-core/surfaces/geminiSurface.ts');

    for (const source of [
      completionsSource,
      embeddingsSource,
      imagesSource,
      modelsRouteSource,
      searchSource,
      videosSource,
      schedulerSource,
      oauthServiceSource,
      sharedSurfaceSource,
      geminiSurfaceSource,
    ]) {
      expect(source).toContain('routeRefreshWorkflow');
      expectNoDirectModelServiceRouteRefresh(source);
    }
  });
});
