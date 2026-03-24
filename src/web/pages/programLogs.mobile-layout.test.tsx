import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('ProgramLogs mobile layout', () => {
  it('uses the shared mobile primitives for filters and list cards', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/ProgramLogs.tsx'), 'utf8');

    expect(source).toContain("import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js'");
    expect(source).toContain("import { MobileCard, MobileField } from '../components/MobileCard.js'");
    expect(source).toContain("import { useIsMobile } from '../components/useIsMobile.js'");
    expect(source).toContain('const isMobile = useIsMobile()');
    expect(source).toContain('mobile-card-list');
    expect(source).toContain('<ResponsiveFilterPanel');
  });
});
