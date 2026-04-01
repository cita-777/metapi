import { describe, expect, it } from 'vitest';
import type { RouteChannel } from './types.js';
import {
  applyPriorityBucketDrag,
  buildPriorityBuckets,
  createPriorityBucketSeparatorId,
  splitPriorityBucketAfterChannel,
} from './priorityBuckets.js';

function buildChannel(id: number, priority: number): RouteChannel {
  return {
    id,
    routeId: 1,
    accountId: 100 + id,
    tokenId: 200 + id,
    sourceModel: id % 2 === 0 ? 'model-b' : 'model-a',
    priority,
    weight: 10,
    enabled: true,
    manualOverride: false,
    successCount: 0,
    failCount: 0,
    cooldownUntil: null,
    account: { username: `user-${id}` },
    site: { id: 300 + id, name: `site-${id}`, platform: 'new-api' },
    token: { id: 200 + id, name: `token-${id}`, accountId: 100 + id, enabled: true, isDefault: true },
  };
}

describe('priority bucket helpers', () => {
  it('groups duplicate priorities into the same bucket', () => {
    const buckets = buildPriorityBuckets([
      buildChannel(1, 0),
      buildChannel(2, 0),
      buildChannel(3, 2),
      buildChannel(4, 2),
    ]);

    expect(buckets).toHaveLength(2);
    expect(buckets[0]).toMatchObject({ priority: 0 });
    expect(buckets[0].channels.map((channel) => channel.id)).toEqual([1, 2]);
    expect(buckets[1]).toMatchObject({ priority: 2 });
    expect(buckets[1].channels.map((channel) => channel.id)).toEqual([3, 4]);
  });

  it('moves a channel across a separator and preserves duplicate priorities', () => {
    const reordered = applyPriorityBucketDrag(
      [
        buildChannel(1, 0),
        buildChannel(2, 0),
        buildChannel(3, 1),
        buildChannel(4, 2),
      ],
      3,
      1,
    );

    expect(reordered.map((channel) => ({ id: channel.id, priority: channel.priority }))).toEqual([
      { id: 1, priority: 0 },
      { id: 2, priority: 0 },
      { id: 3, priority: 0 },
      { id: 4, priority: 1 },
    ]);
  });

  it('moves a separator within adjacent buckets and dense-renormalizes priorities', () => {
    const reordered = applyPriorityBucketDrag(
      [
        buildChannel(1, 0),
        buildChannel(2, 0),
        buildChannel(3, 1),
        buildChannel(4, 2),
        buildChannel(5, 2),
      ],
      createPriorityBucketSeparatorId(0),
      3,
    );

    expect(reordered.map((channel) => ({ id: channel.id, priority: channel.priority }))).toEqual([
      { id: 1, priority: 0 },
      { id: 2, priority: 0 },
      { id: 3, priority: 0 },
      { id: 4, priority: 1 },
      { id: 5, priority: 1 },
    ]);
  });

  it('can split a single shared-priority bucket into a new next bucket', () => {
    const reordered = splitPriorityBucketAfterChannel(
      [
        buildChannel(1, 0),
        buildChannel(2, 0),
        buildChannel(3, 0),
      ],
      1,
    );

    expect(reordered.map((channel) => ({ id: channel.id, priority: channel.priority }))).toEqual([
      { id: 1, priority: 0 },
      { id: 2, priority: 1 },
      { id: 3, priority: 1 },
    ]);
  });
});
