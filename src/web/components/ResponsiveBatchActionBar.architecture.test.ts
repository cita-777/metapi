import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

function readPageSource(relativePath: string): string {
  return readFileSync(resolve(process.cwd(), relativePath), 'utf8').replace(/\r\n/g, '\n');
}

describe('ResponsiveBatchActionBar page adoption', () => {
  it('is used by the repeated admin list pages instead of open-coded mobile and desktop batch wrappers', () => {
    expect(readPageSource('src/web/pages/Accounts.tsx')).toContain('ResponsiveBatchActionBar');
    expect(readPageSource('src/web/pages/Sites.tsx')).toContain('ResponsiveBatchActionBar');
    expect(readPageSource('src/web/pages/Tokens.tsx')).toContain('ResponsiveBatchActionBar');
    expect(readPageSource('src/web/pages/DownstreamKeys.tsx')).toContain('ResponsiveBatchActionBar');
  });
});
