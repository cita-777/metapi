/**
 * Coalesces high-frequency stream updates into a small number of React state
 * commits.  The queue deliberately keeps each delta as a separate item: some
 * upstream protocols send cumulative text, so concatenating deltas before the
 * consumer sees them would change the overlap/deduplication semantics.
 */
export type StreamDelta = {
  contentDelta?: string;
  reasoningDelta?: string;
};
export type StreamUpdateBatch = {
  deltas: StreamDelta[];
  rawEvents: string[];
};

export type StreamUpdateBatcher = {
  enqueueDelta: (delta: StreamDelta) => void;
  enqueueRawEvent: (rawEvent: string) => void;
  flush: () => void;
  dispose: () => void;
};

/**
 * Keep the window below the 50ms interaction budget while avoiding one React
 * render for every SSE frame.  A timer (instead of only rAF) also works in
 * background tabs and in the jsdom test environment.
 */
export const STREAM_UPDATE_BATCH_MS = 24;

export function createStreamUpdateBatcher(
  onFlush: (batch: StreamUpdateBatch) => void,
  delayMs = STREAM_UPDATE_BATCH_MS,
): StreamUpdateBatcher {
  let deltaQueue: StreamDelta[] = [];
  let rawEventQueue: string[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;

  const clearScheduledFlush = () => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
  };

  const flush = () => {
    if (disposed) return;
    clearScheduledFlush();
    if (deltaQueue.length === 0 && rawEventQueue.length === 0) return;

    const batch: StreamUpdateBatch = {
      deltas: deltaQueue,
      rawEvents: rawEventQueue,
    };
    deltaQueue = [];
    rawEventQueue = [];
    onFlush(batch);
  };

  const scheduleFlush = () => {
    if (timer !== null || disposed) return;
    timer = setTimeout(() => {
      timer = null;
      flush();
    }, Math.max(0, delayMs));
  };

  return {
    enqueueDelta: (delta) => {
      if (disposed) return;
      if (delta.contentDelta || delta.reasoningDelta) {
        deltaQueue.push(delta);
        scheduleFlush();
      }
    },
    enqueueRawEvent: (rawEvent) => {
      if (disposed) return;
      rawEventQueue.push(rawEvent);
      scheduleFlush();
    },
    flush,
    dispose: () => {
      if (disposed) return;
      clearScheduledFlush();
      deltaQueue = [];
      rawEventQueue = [];
      disposed = true;
    },
  };
}
