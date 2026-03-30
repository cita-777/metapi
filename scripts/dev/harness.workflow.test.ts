import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('harness workflows', () => {
  it('keeps repo drift checks wired into ci and scheduled reporting', () => {
    const ciWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const driftWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/harness-drift-report.yml'), 'utf8');

    expect(ciWorkflow).toContain('name: Repo Drift Check');
    expect(ciWorkflow).toContain('npm run repo:drift-check');
    expect(ciWorkflow).toContain('name: Test Core');
    expect(ciWorkflow).toContain('name: Build Web');
    expect(ciWorkflow).toContain('name: Typecheck');

    expect(driftWorkflow).toContain('schedule:');
    expect(driftWorkflow).toContain('workflow_dispatch:');
    expect(driftWorkflow).toContain('npm run repo:drift-check -- --format markdown --output tmp/repo-drift-report.md --report-only');
    expect(driftWorkflow).toMatch(/actions\/upload-artifact@v\d+/);
    expect(driftWorkflow).toContain('repo-drift-report');
  });
});
