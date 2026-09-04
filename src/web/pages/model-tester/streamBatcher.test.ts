import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createStreamUpdateBatcher,
  STREAM_UPDATE_BATCH_MS,
  type StreamUpdateBatch,
} from './streamBatcher.js';

describe('stream update batcher', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('keeps delta/raw-event order while committing one batch per window', () => {
    const batches: StreamUpdateBatch[] = [];
    const batcher = createStreamUpdateBatcher((batch) => batches.push(batch));

    batcher.enqueueRawEvent('{"n":1}');
    batcher.enqueueDelta({ contentDelta: 'a' });
    batcher.enqueueRawEvent('{"n":2}');
    batcher.enqueueDelta({ reasoningDelta: '思' });

    expect(batches).toHaveLength(0);
    vi.advanceTimersByTime(STREAM_UPDATE_BATCH_MS - 1);
    expect(batches).toHaveLength(0);

    vi.advanceTimersByTime(1);
    expect(batches).toEqual([{
      deltas: [
        { contentDelta: 'a' },
        { reasoningDelta: '思' },
      ],
      rawEvents: ['{"n":1}', '{"n":2}'],
    }]);
  });

  it('flushes synchronously and cancels the scheduled timer', () => {
    const onFlush = vi.fn();
    const batcher = createStreamUpdateBatcher(onFlush, 40);

    batcher.enqueueDelta({ contentDelta: 'final' });
    batcher.flush();
    expect(onFlush).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(100);
    expect(onFlush).toHaveBeenCalledTimes(1);
  });

  it('disposes pending work without invoking a callback later', () => {
    const onFlush = vi.fn();
    const batcher = createStreamUpdateBatcher(onFlush);

    batcher.enqueueRawEvent('pending');
    batcher.dispose();
    vi.runAllTimers();

    expect(onFlush).not.toHaveBeenCalled();
    batcher.enqueueDelta({ contentDelta: 'ignored' });
    batcher.flush();
    expect(onFlush).not.toHaveBeenCalled();
  });
});
