import { describe, expect, it } from 'vitest';
import { DRILL_NAMES, probeRunner, runDrill } from './docker-runner-drills.mjs';

const probe = probeRunner();
const drill = probe.available ? it : it.skip;

describe('docker runner drills', () => {
  it('lists the drills and stays skipped until run() exists', () => {
    expect(DRILL_NAMES).toEqual([
      'first-start',
      'upgrade',
      'health-check-failure-rollback-db',
      'tampered-volume-rollback',
      'node-major-mismatch',
      'image-newer-than-runtime',
      'wrong-volume-ownership',
      'pg-dump-missing',
      'pg-dump-wrong-version',
      'backup-write-failure',
    ]);
    if (!probe.available) {
      expect(probe.reason).toContain('runner PR');
    } else {
      expect(probe.file).toContain('docker-runner.mjs');
    }
  });

  for (const name of DRILL_NAMES) {
    drill(name, async () => {
      await runDrill(name);
    }, 15000);
  }
});
