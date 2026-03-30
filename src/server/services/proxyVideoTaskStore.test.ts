import { describe, expect, it } from 'vitest';
import { __proxyVideoTaskStoreTestUtils } from './proxyVideoTaskStore.js';

describe('proxyVideoTaskStore', () => {
  it('accepts parsed object input for JSON column helpers', () => {
    expect(__proxyVideoTaskStoreTestUtils.parseJsonColumn({
      status: 'done',
      id: 'video-1',
    })).toEqual({
      status: 'done',
      id: 'video-1',
    });
  });
});
