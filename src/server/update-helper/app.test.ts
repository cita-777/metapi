import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildUpdateHelperApp } from './app.js';

describe('update helper app', () => {
  const apps: Array<Awaited<ReturnType<typeof buildUpdateHelperApp>>> = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  it('requires bearer auth for protected helper routes', async () => {
    const app = await buildUpdateHelperApp({
      token: 'helper-token',
      getStatus: vi.fn(),
      deploy: vi.fn(),
    });
    apps.push(app);

    const response = await app.inject({
      method: 'GET',
      url: '/status?namespace=ai&releaseName=metapi',
    });

    expect(response.statusCode).toBe(401);
  });

  it('allows unauthenticated health checks', async () => {
    const app = await buildUpdateHelperApp({
      token: 'helper-token',
      getStatus: vi.fn(),
      deploy: vi.fn(),
    });
    apps.push(app);

    const response = await app.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
  });

  it('returns helper status for authorized requests', async () => {
    const getStatus = vi.fn().mockResolvedValue({
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
          revision: '16',
          updatedAt: '2026-03-28T12:00:00Z',
          status: 'superseded',
          description: 'Rollback to stable digest',
          imageRepository: '1467078763/metapi',
          imageTag: 'main',
          imageDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
    });

    const app = await buildUpdateHelperApp({
      token: 'helper-token',
      getStatus,
      deploy: vi.fn(),
    });
    apps.push(app);

    const response = await app.inject({
      method: 'GET',
      url: '/status?namespace=ai&releaseName=metapi',
      headers: {
        authorization: 'Bearer helper-token',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      healthy: true,
      releaseName: 'metapi',
      namespace: 'ai',
      imageDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    });
    expect(getStatus).toHaveBeenCalledWith({
      namespace: 'ai',
      releaseName: 'metapi',
    });
  });

  it('streams deploy logs and final result as SSE when requested', async () => {
    const deploy = vi.fn().mockImplementation(async (input, onLog) => {
      onLog?.('Running helm upgrade');
      onLog?.('Waiting for rollout');
      return {
        success: true,
        targetSource: input.targetSource,
        targetTag: input.targetTag,
        targetDigest: input.targetDigest,
        previousRevision: '17',
        finalRevision: '18',
        rolledBack: false,
        logLines: ['Running helm upgrade', 'Waiting for rollout'],
      };
    });

    const app = await buildUpdateHelperApp({
      token: 'helper-token',
      getStatus: vi.fn(),
      deploy,
    });
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: '/deploy',
      headers: {
        authorization: 'Bearer helper-token',
        accept: 'text/event-stream',
      },
      payload: {
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        source: 'github-release',
        targetTag: 'latest',
        targetDigest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('event: log');
    expect(response.body).toContain('Running helm upgrade');
    expect(response.body).toContain('event: result');
    expect(response.body).toContain('"targetTag":"latest"');
    expect(response.body).toContain('"targetDigest":"sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35"');
  });

  it('streams rollback logs and final result as SSE when requested', async () => {
    const rollback = vi.fn().mockImplementation(async (input, onLog) => {
      onLog?.('Running helm rollback');
      onLog?.('Waiting for rollout');
      return {
        success: true,
        targetRevision: input.targetRevision,
        finalRevision: '20',
        logLines: ['Running helm rollback', 'Waiting for rollout'],
      };
    });

    const app = await buildUpdateHelperApp({
      token: 'helper-token',
      getStatus: vi.fn(),
      deploy: vi.fn(),
      rollback,
    });
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: '/rollback',
      headers: {
        authorization: 'Bearer helper-token',
        accept: 'text/event-stream',
      },
      payload: {
        namespace: 'ai',
        releaseName: 'metapi',
        targetRevision: '16',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/event-stream');
    expect(response.body).toContain('event: log');
    expect(response.body).toContain('Running helm rollback');
    expect(response.body).toContain('event: result');
    expect(response.body).toContain('"targetRevision":"16"');
  });
});
