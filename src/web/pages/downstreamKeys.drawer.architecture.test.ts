import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('DownstreamKeys drawer extraction', () => {
  it('delegates the downstream key detail drawer to a dedicated component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/DownstreamKeys.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import DownstreamKeyDrawer from './downstream-keys/DownstreamKeyDrawer.js'");
    expect(source).not.toContain('function Drawer({');
    expect(source).not.toContain('return createPortal(panel, document.body);');
  });
});
