import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('ModelTester debug panel extraction', () => {
  it('delegates the debug sidebar to a dedicated model-tester component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/ModelTester.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import DebugPanel from './model-tester/DebugPanel.js'");
    expect(source).not.toContain('时间线');
  });

  it('keeps the debug timestamp prop aligned with the ISO string state used by ModelTester', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/model-tester/DebugPanel.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain('debugTimestamp: string | null;');
  });
});
