import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Tokens embedded layout', () => {
  it('reuses accounts-page-actions layout when embedded in 连接管理', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/tokens/TokensPanel.tsx'), 'utf8');

    expect(source).toContain("className={`page-actions ${embedded ? 'accounts-page-actions' : ''}`.trim()}");
  });
});
