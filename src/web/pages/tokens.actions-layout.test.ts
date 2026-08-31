import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Tokens actions layout', () => {
  it('reuses a wrapping actions cell layout so token row actions do not overflow', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/tokens/TokensPanel.tsx'), 'utf8');
    const css = readFileSync(resolve(process.cwd(), 'src/web/index.css'), 'utf8');

    expect(source).toContain('className="token-actions-cell"');
    expect(css).toContain('.token-actions-cell');
    expect(css).toContain('.token-table-actions {');
    expect(css).toContain('flex-wrap: wrap;');
    expect(css).toContain('.token-table {');
    expect(css).toContain('table-layout: fixed;');
  });
});
