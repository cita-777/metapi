import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('oauth route registration', () => {
  it('registers oauth routes in the main server entry', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/server/index.ts'), 'utf8');

    expect(source).toContain("import { oauthRoutes } from './routes/api/oauth.js';");
    expect(source).toContain('await app.register(oauthRoutes);');
  });

  it('treats oauth callback as a public API route', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/server/desktop.ts'), 'utf8');

    expect(source).toContain("url.startsWith('/api/oauth/callback/')");
  });
});
