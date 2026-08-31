import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Tokens centered modal adoption', () => {
  it('uses CenteredModal for add/edit token flows instead of inline form cards', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/tokens/TokensPanel.tsx'), 'utf8');

    expect(source).toContain("import CenteredModal from '../../components/CenteredModal.js'");
    expect(source).toContain('<CenteredModal');
    expect(source).not.toContain('addPanelPresence.shouldRender && (');
  });
});
