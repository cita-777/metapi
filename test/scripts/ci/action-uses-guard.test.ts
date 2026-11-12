import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { evaluateActionUses, formatActionUsesReport, parseUsesValues } from './action-uses-guard.mjs';

const sha = 'a'.repeat(40);

function writeWorkflow(root: string, source: string) {
  const dir = join(root, '.github', 'workflows');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'ci.yml'), source);
}

describe('action uses guard', () => {
  it('accepts a 40-character SHA and a local action, and rejects a floating tag when enforced', () => {
    expect(parseUsesValues(`
      # uses: actions/checkout@v1
      - uses: actions/checkout@${sha} # v7
      - uses: ./.github/actions/local
      uses: actions/setup-node@v7
    `)).toEqual([
      `actions/checkout@${sha}`,
      './.github/actions/local',
      'actions/setup-node@v7',
    ]);

    const root = mkdtempSync(join(tmpdir(), 'metapi-uses-'));
    writeWorkflow(root, `jobs:\n  test:\n    steps:\n      - uses: actions/checkout@${sha}\n      - uses: ./.github/actions/local\n`);
    expect(evaluateActionUses({ root, enforce: true }).exitCode).toBe(0);

    writeWorkflow(root, 'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7\n');
    const floating = evaluateActionUses({ root, enforce: true });
    expect(floating.exitCode).toBe(1);
    expect(floating.floating[0].value).toBe('actions/checkout@v7');
    expect(evaluateActionUses({ root, enforce: false }).exitCode).toBe(0);
  });

  it('warns on this repository until the release.yml pin PR', () => {
    const result = evaluateActionUses({ root: process.cwd(), enforce: false });
    expect(result.floating.length).toBeGreaterThan(0);
    expect(result.exitCode).toBe(0);
    expect(formatActionUsesReport(result)).toContain('release.yml pin PR');
    const enforced = evaluateActionUses({ root: process.cwd(), enforce: true });
    expect(enforced.exitCode).toBe(1);
  });

  it('exits 0 in the default warn mode', () => {
    const result = spawnSync(process.execPath, [new URL('./action-uses-guard.mjs', import.meta.url).pathname], {
      encoding: 'utf8',
      cwd: process.cwd(),
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('warn');
  });
});
