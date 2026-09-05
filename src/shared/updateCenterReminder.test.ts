import { describe, expect, it } from 'vitest';

import {
  buildUpdateReminderCandidateKey,
  compareStableVersions,
  resolveUpdateReminderCandidate,
} from './updateCenterReminder.js';

describe('updateCenterReminder shared logic', () => {
  it('detects a newer stable release', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      latestRelease: { normalizedVersion: '1.3.0', displayVersion: '1.3.0', tagName: 'v1.3.0' },
    })).toEqual(expect.objectContaining({
      source: 'github-release',
      kind: 'new-version',
      candidateKey: 'github-release:v1.3.0',
    }));
  });

  it('does not flag equal or older versions', () => {
    expect(compareStableVersions('1.3.0', '1.3.0')).toBe(0);
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.3.0',
      latestRelease: { normalizedVersion: '1.2.9', tagName: 'v1.2.9' },
    })).toBeNull();
  });

  it('builds a stable candidate key', () => {
    expect(buildUpdateReminderCandidateKey('github-release', { tagName: 'v2.0.0' })).toBe('github-release:v2.0.0');
  });
});
