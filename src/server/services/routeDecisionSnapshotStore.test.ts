import { describe, expect, it } from 'vitest';
import { parseRouteDecisionSnapshot } from './routeDecisionSnapshotStore.js';

describe('routeDecisionSnapshotStore', () => {
  it('accepts parsed decision snapshot objects', () => {
    expect(parseRouteDecisionSnapshot({
      matched: true,
      candidates: [{ routeId: 1 }],
    })).toEqual({
      matched: true,
      candidates: [{ routeId: 1 }],
    });
  });
});
