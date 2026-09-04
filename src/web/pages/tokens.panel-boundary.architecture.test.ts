import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function readSource(relativePath: string): string {
  return readFileSync(resolve(process.cwd(), relativePath), 'utf8').replace(/\r\n/g, '\n');
}

describe('Tokens panel page boundary', () => {
  it('embeds the token domain panel without importing the legacy top-level route page', () => {
    const accounts = readSource('src/web/pages/Accounts.tsx');

    expect(accounts).toMatch(
      /import\s+\{\s*TokensPanel\s*\}\s+from\s+["']\.\/tokens\/TokensPanel\.js["']/
    );
    expect(accounts).not.toMatch(/from\s+["']\.\/Tokens\.js["']/);
  });

  it('keeps the legacy route as a thin redirect and compatibility export', () => {
    const route = readSource('src/web/pages/Tokens.tsx');

    expect(route).toMatch(
      /export\s+\{\s*TokensPanel\s*\}\s+from\s+['"]\.\/tokens\/TokensPanel\.js['"]/
    );
    expect(route).toContain('return <Navigate to={`/accounts');
    expect(route).not.toContain('function TokensPanel(');
  });
});
