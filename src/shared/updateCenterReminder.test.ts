import { describe, expect, it } from 'vitest';

import {
  buildUpdateReminderCandidateKey,
  resolveUpdateReminderCandidate,
} from './updateCenterReminder.js';

describe('updateCenterReminder shared logic', () => {
  it('prefers a newer GitHub release when the current runtime is behind', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.2.3',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
        tagName: 'v1.3.0',
      },
      dockerHubTag: {
        normalizedVersion: 'latest',
        displayVersion: 'latest @ sha256:efb2ee655386',
        tagName: 'latest',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
    })).toEqual(expect.objectContaining({
      source: 'github-release',
      kind: 'new-version',
      candidateKey: 'github-release:v1.3.0',
      displayVersion: '1.3.0',
    }));
  });

  it('treats a same-version Docker target with a different digest as a reminder-worthy new digest', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.2.3',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      githubRelease: null,
      dockerHubTag: {
        normalizedVersion: '1.2.3',
        displayVersion: '1.2.3 @ sha256:bbbbbbbbbbbb',
        tagName: '1.2.3',
        digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    })).toEqual(expect.objectContaining({
      source: 'docker-hub-tag',
      kind: 'new-digest',
      candidateKey: 'docker-hub-tag:1.2.3@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    }));
  });

  it('treats semver tags with and without a v prefix as the same digest-tracked image target', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: 'v1.2.3',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      githubRelease: null,
      dockerHubTag: {
        normalizedVersion: '1.2.3',
        displayVersion: '1.2.3 @ sha256:bbbbbbbbbbbb',
        tagName: '1.2.3',
        digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    })).toEqual(expect.objectContaining({
      source: 'docker-hub-tag',
      kind: 'new-digest',
      candidateKey: 'docker-hub-tag:1.2.3@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    }));
  });

  it('treats alias tags like latest as digest-tracked targets when the digest changes', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: 'latest',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      githubRelease: null,
      dockerHubTag: {
        normalizedVersion: 'latest',
        displayVersion: 'latest @ sha256:bbbbbbbbbbbb',
        tagName: 'latest',
        digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    })).toEqual(expect.objectContaining({
      source: 'docker-hub-tag',
      kind: 'new-digest',
      candidateKey: 'docker-hub-tag:latest@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    }));
  });

  it('does not return an older GitHub candidate when the helper is already ahead of it', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.4.0',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
        tagName: 'v1.3.0',
      },
      dockerHubTag: null,
    })).toBeNull();
  });

  it('returns null when the discovered targets do not differ meaningfully from the current runtime', () => {
    expect(resolveUpdateReminderCandidate({
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.2.3',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      githubRelease: {
        normalizedVersion: '1.2.3',
        displayVersion: '1.2.3',
        tagName: 'v1.2.3',
      },
      dockerHubTag: {
        normalizedVersion: '1.2.3',
        displayVersion: '1.2.3 @ sha256:aaaaaaaaaaaa',
        tagName: '1.2.3',
        digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    })).toBeNull();
  });

  it('builds stable candidate keys for both source types', () => {
    expect(buildUpdateReminderCandidateKey('github-release', {
      tagName: 'v1.3.0',
      digest: null,
    })).toBe('github-release:v1.3.0');

    expect(buildUpdateReminderCandidateKey('docker-hub-tag', {
      tagName: 'latest',
      digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
    })).toBe('docker-hub-tag:latest@sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35');
  });
});
