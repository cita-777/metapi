import { beforeEach, describe, expect, it, vi } from 'vitest';

const { fetchMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
}));

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return {
    ...actual,
    fetch: (...args: unknown[]) => fetchMock(...args),
  };
});

import {
  getUpdateCenterHelperStatus,
  streamUpdateCenterDeploy,
  streamUpdateCenterRollback,
} from './updateCenterHelperClient.js';

describe('update center helper client', () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it('maps helper status aborts to a timeout error', async () => {
    const abortError = new Error('aborted');
    (abortError as Error & { name: string }).name = 'AbortError';
    fetchMock.mockRejectedValue(abortError);

    await expect(getUpdateCenterHelperStatus({
      enabled: true,
      helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
      namespace: 'ai',
      releaseName: 'metapi',
      chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
      imageRepository: '1467078763/metapi',
      githubReleasesEnabled: true,
      dockerHubTagsEnabled: true,
      defaultDeploySource: 'github-release',
    }, 'helper-token')).rejects.toThrow('deploy helper status timeout');
  });

  it('posts digest-aware deploy payloads to the helper and parses the streamed result', async () => {
    fetchMock.mockResolvedValue(new Response([
      'event: log',
      'data: {"message":"Running helm upgrade"}',
      '',
      'event: result',
      'data: {"success":true,"targetSource":"docker-hub-tag","targetTag":"latest","targetDigest":"sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35","previousRevision":"17","finalRevision":"18","rolledBack":false,"logLines":["Running helm upgrade"]}',
      '',
    ].join('\n'), {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    }));

    const messages: string[] = [];
    const result = await streamUpdateCenterDeploy({
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      helperToken: 'helper-token',
      source: 'docker-hub-tag',
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
    }, (message) => {
      messages.push(message);
    });

    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toBe('http://metapi-deploy-helper.ai.svc.cluster.local:9850/deploy');
    const deployRequest = fetchMock.mock.calls[0]?.[1] as { method?: string; body?: string };
    expect(deployRequest?.method).toBe('POST');
    expect(JSON.parse(String(deployRequest?.body || '{}'))).toMatchObject({
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
    });
    expect(messages).toEqual(['Running helm upgrade']);
    expect(result).toMatchObject({
      targetTag: 'latest',
      targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      finalRevision: '18',
    });
  });

  it('posts rollback requests to the helper and parses the streamed result', async () => {
    fetchMock.mockResolvedValue(new Response([
      'event: log',
      'data: {"message":"Running helm rollback"}',
      '',
      'event: result',
      'data: {"success":true,"targetRevision":"16","finalRevision":"20","logLines":["Running helm rollback"]}',
      '',
    ].join('\n'), {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    }));

    const messages: string[] = [];
    const result = await streamUpdateCenterRollback({
      config: {
        enabled: true,
        helperBaseUrl: 'http://metapi-deploy-helper.ai.svc.cluster.local:9850',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      helperToken: 'helper-token',
      targetRevision: '16',
    }, (message) => {
      messages.push(message);
    });

    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toBe('http://metapi-deploy-helper.ai.svc.cluster.local:9850/rollback');
    const rollbackRequest = fetchMock.mock.calls[0]?.[1] as { method?: string; body?: string };
    expect(rollbackRequest?.method).toBe('POST');
    expect(JSON.parse(String(rollbackRequest?.body || '{}'))).toMatchObject({
      targetRevision: '16',
    });
    expect(messages).toEqual(['Running helm rollback']);
    expect(result).toMatchObject({
      targetRevision: '16',
      finalRevision: '20',
    });
  });
});
