import { describe, expect, it } from 'vitest';

import {
  executeUpdateHelperDeploy,
  executeUpdateHelperRollback,
  getUpdateHelperStatus,
} from './service.js';

describe('update helper service', () => {
  it('builds helm upgrade and rollout verification commands with the configured release metadata', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const summary = await executeUpdateHelperDeploy(
      {
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        targetSource: 'github-release',
        targetTag: '1.3.0',
        targetDigest: null,
      },
      {
        runCommand: async ({ command, args }) => {
          calls.push({ command, args });
          if (command === 'helm' && args[0] === 'history') {
            return {
              stdout: JSON.stringify([{ revision: '12' }]),
            };
          }
          if (command === 'helm' && args[0] === 'status') {
            return {
              stdout: JSON.stringify({
                version: 13,
              }),
            };
          }
          return { stdout: '' };
        },
      },
    );

    expect(calls).toEqual([
      {
        command: 'helm',
        args: ['history', 'metapi', '-n', 'ai', '-o', 'json'],
      },
      {
        command: 'helm',
        args: [
          'upgrade',
          'metapi',
          'oci://ghcr.io/cita-777/charts/metapi',
          '--namespace',
          'ai',
          '--reuse-values',
          '--set',
          'image.repository=1467078763/metapi',
          '--set',
          'image.tag=1.3.0',
          '--set-string',
          'image.digest=',
        ],
      },
      {
        command: 'kubectl',
        args: [
          'rollout',
          'status',
          'deployment',
          '-n',
          'ai',
          '-l',
          'app.kubernetes.io/instance=metapi',
          '--timeout=300s',
        ],
      },
      {
        command: 'helm',
        args: ['status', 'metapi', '-n', 'ai', '-o', 'json'],
      },
    ]);
    expect(summary).toMatchObject({
      success: true,
      targetSource: 'github-release',
      targetTag: '1.3.0',
      targetDigest: null,
      previousRevision: '12',
      finalRevision: '13',
      rolledBack: false,
    });
  });

  it('passes image digest overrides through helm when a digest-aware deployment is requested', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const summary = await executeUpdateHelperDeploy(
      {
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        targetSource: 'docker-hub-tag',
        targetTag: 'latest',
        targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
      {
        runCommand: async ({ command, args }) => {
          calls.push({ command, args });
          if (command === 'helm' && args[0] === 'history') {
            return {
              stdout: JSON.stringify([{ revision: '18' }]),
            };
          }
          if (command === 'helm' && args[0] === 'status') {
            return {
              stdout: JSON.stringify({
                version: 19,
              }),
            };
          }
          return { stdout: '' };
        },
      },
    );

    expect(calls).toContainEqual({
      command: 'helm',
      args: [
        'upgrade',
        'metapi',
        'oci://ghcr.io/cita-777/charts/metapi',
        '--namespace',
        'ai',
        '--reuse-values',
        '--set',
        'image.repository=1467078763/metapi',
        '--set',
        'image.tag=latest',
        '--set-string',
        'image.digest=sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      ],
    });
    expect(summary).toMatchObject({
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      finalRevision: '19',
    });
  });

  it('rolls back to the previous revision when rollout verification fails', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];

    await expect(() => executeUpdateHelperDeploy(
      {
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        targetSource: 'docker-hub-tag',
        targetTag: '1.3.1',
        targetDigest: null,
      },
      {
        runCommand: async ({ command, args }) => {
          calls.push({ command, args });
          if (command === 'helm' && args[0] === 'history') {
            return {
              stdout: JSON.stringify([{ revision: '22' }]),
            };
          }
          if (command === 'kubectl' && args[0] === 'rollout') {
            throw new Error('rollout status timed out');
          }
          return { stdout: '' };
        },
      },
    )).rejects.toThrow('rollout status timed out');

    expect(calls).toEqual(expect.arrayContaining([
      {
        command: 'helm',
        args: ['rollback', 'metapi', '22', '-n', 'ai'],
      },
    ]));
  });

  it('runs an explicit rollback workflow for a chosen revision', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const summary = await executeUpdateHelperRollback(
      {
        namespace: 'ai',
        releaseName: 'metapi',
        targetRevision: '16',
      },
      {
        runCommand: async ({ command, args }) => {
          calls.push({ command, args });
          if (command === 'helm' && args[0] === 'status') {
            return {
              stdout: JSON.stringify({
                version: 20,
              }),
            };
          }
          return { stdout: '' };
        },
      },
    );

    expect(calls).toEqual([
      {
        command: 'helm',
        args: ['rollback', 'metapi', '16', '-n', 'ai'],
      },
      {
        command: 'kubectl',
        args: [
          'rollout',
          'status',
          'deployment',
          '-n',
          'ai',
          '-l',
          'app.kubernetes.io/instance=metapi',
          '--timeout=300s',
        ],
      },
      {
        command: 'helm',
        args: ['status', 'metapi', '-n', 'ai', '-o', 'json'],
      },
    ]);

    expect(summary).toMatchObject({
      success: true,
      targetRevision: '16',
      finalRevision: '20',
    });
  });

  it('parses helper status from helm status, runtime image ids, and recent helm history', async () => {
    const status = await getUpdateHelperStatus(
      {
        namespace: 'ai',
        releaseName: 'metapi',
      },
      {
        runCommand: async ({ command, args }) => {
          if (command === 'helm' && args[0] === 'status') {
            return {
              stdout: JSON.stringify({
                version: 17,
                info: {
                  status: 'deployed',
                },
              }),
            };
          }
          if (command === 'helm' && args[0] === 'get') {
            const revision = args.includes('--revision')
              ? args[args.indexOf('--revision') + 1]
              : null;
            if (revision === '16') {
              return {
                stdout: JSON.stringify({
                  image: {
                    repository: '1467078763/metapi',
                    tag: 'latest',
                    digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                  },
                }),
              };
            }
            if (revision === '17') {
              return {
                stdout: JSON.stringify({
                  image: {
                    repository: '1467078763/metapi',
                    tag: 'main',
                    digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                  },
                }),
              };
            }
            return {
              stdout: JSON.stringify({
                image: {
                  repository: '1467078763/metapi',
                  tag: 'latest',
                },
              }),
            };
          }
          if (command === 'helm' && args[0] === 'history') {
            return {
              stdout: JSON.stringify([
                { revision: '17', updated: '2026-03-29T12:00:00Z', status: 'deployed', description: 'Upgrade complete' },
                { revision: '16', updated: '2026-03-28T12:00:00Z', status: 'superseded', description: 'Rollback to stable digest' },
              ]),
            };
          }
          if (command === 'kubectl' && args[0] === 'get') {
            return {
              stdout: JSON.stringify({
                items: [
                  {
                    status: {
                      containerStatuses: [
                        {
                          imageID: 'docker-pullable://1467078763/metapi@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                        },
                      ],
                    },
                  },
                ],
              }),
            };
          }
          throw new Error('unexpected command');
        },
      },
    );

    expect(status).toEqual({
      ok: true,
      releaseName: 'metapi',
      namespace: 'ai',
      revision: '17',
      imageRepository: '1467078763/metapi',
      imageTag: 'latest',
      imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      healthy: true,
      history: [
        {
          revision: '17',
          updatedAt: '2026-03-29T12:00:00Z',
          status: 'deployed',
          description: 'Upgrade complete',
          imageRepository: '1467078763/metapi',
          imageTag: 'main',
          imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
        {
          revision: '16',
          updatedAt: '2026-03-28T12:00:00Z',
          status: 'superseded',
          description: 'Rollback to stable digest',
          imageRepository: '1467078763/metapi',
          imageTag: 'latest',
          imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
      ],
    });
  });
});
