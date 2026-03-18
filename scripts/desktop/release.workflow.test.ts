import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('release workflow', () => {
  it('builds macOS arm64 and x64 on dedicated runners and verifies packaged app architecture', () => {
    const workflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');

    expect(workflow).toContain('runner: macos-15-intel');
    expect(workflow).toContain('runner: macos-15');
    expect(workflow).toContain('expectedMacArch: x64');
    expect(workflow).toContain('expectedMacArch: arm64');
    expect(workflow).toContain('Verify packaged macOS architecture');
    expect(workflow).toContain('lipo -archs');
  });
});
