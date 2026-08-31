import type { FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EMPTY_DOWNSTREAM_ROUTING_POLICY } from './downstreamPolicyTypes.js';

const mocks = vi.hoisted(() => ({
  getProxyAuthContext: vi.fn(),
  isModelAllowedByPolicyOrAllowedRoutes: vi.fn(),
  recordManagedKeyCostUsage: vi.fn(),
}));

vi.mock('../middleware/auth.js', () => ({
  getProxyAuthContext: mocks.getProxyAuthContext,
}));
vi.mock('./downstreamApiKeyService.js', () => ({
  isModelAllowedByPolicyOrAllowedRoutes: mocks.isModelAllowedByPolicyOrAllowedRoutes,
  recordManagedKeyCostUsage: mocks.recordManagedKeyCostUsage,
}));

import {
  ensureModelAllowedForDownstreamKey,
  getDownstreamRoutingPolicy,
  recordDownstreamCostUsage,
} from './downstreamPolicyService.js';

const request = {} as FastifyRequest;

function replyFixture(): FastifyReply & {
  code: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
} {
  const reply = {
    code: vi.fn(),
    send: vi.fn(),
  };
  reply.code.mockReturnValue(reply);
  return reply as unknown as FastifyReply & {
    code: ReturnType<typeof vi.fn>;
    send: ReturnType<typeof vi.fn>;
  };
}

describe('downstreamPolicyService', () => {
  beforeEach(() => {
    mocks.getProxyAuthContext.mockReset();
    mocks.isModelAllowedByPolicyOrAllowedRoutes.mockReset();
    mocks.recordManagedKeyCostUsage.mockReset();
    mocks.recordManagedKeyCostUsage.mockResolvedValue(undefined);
  });

  it.each([
    { name: 'missing auth context', context: null },
    { name: 'global context with empty policy', context: {
      token: 'global-token',
      source: 'global',
      keyId: null,
      keyName: 'global',
      policy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
    } },
  ])('returns a stable policy for $name', ({ context }) => {
    mocks.getProxyAuthContext.mockReturnValue(context);

    const policy = getDownstreamRoutingPolicy(request);
    expect(policy).toEqual(context?.policy || EMPTY_DOWNSTREAM_ROUTING_POLICY);
  });

  it('preserves allow/deny response semantics for managed keys', async () => {
    const context = {
      token: 'managed-token',
      source: 'managed' as const,
      keyId: 7,
      keyName: 'managed',
      policy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
    };
    mocks.getProxyAuthContext.mockReturnValue(context);
    mocks.isModelAllowedByPolicyOrAllowedRoutes.mockResolvedValueOnce(false);
    const reply = replyFixture();

    await expect(ensureModelAllowedForDownstreamKey(request, reply, 'gpt-test'))
      .resolves.toBe(false);
    expect(reply.code).toHaveBeenCalledWith(403);
    expect(reply.send).toHaveBeenCalledWith({
      error: {
        message: 'Model not allowed for this API key: gpt-test',
        type: 'permission_error',
      },
    });

    mocks.isModelAllowedByPolicyOrAllowedRoutes.mockResolvedValueOnce(true);
    await expect(ensureModelAllowedForDownstreamKey(request, reply, 'gpt-test'))
      .resolves.toBe(true);
    expect(reply.send).toHaveBeenCalledTimes(1);
  });

  it('records cost only for managed contexts with a key id', () => {
    mocks.getProxyAuthContext.mockReturnValue({
      token: 'managed-token',
      source: 'managed',
      keyId: 11,
      keyName: 'managed',
      policy: EMPTY_DOWNSTREAM_ROUTING_POLICY,
    });

    recordDownstreamCostUsage(request, 1.25);
    expect(mocks.recordManagedKeyCostUsage).toHaveBeenCalledWith(11, 1.25);

    mocks.getProxyAuthContext.mockReturnValue(null);
    recordDownstreamCostUsage(request, 2);
    expect(mocks.recordManagedKeyCostUsage).toHaveBeenCalledTimes(1);
  });
});
