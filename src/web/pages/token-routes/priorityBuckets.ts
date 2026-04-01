import type { RouteChannel } from './types.js';
import { normalizeChannels } from './utils.js';

export const PRIORITY_BUCKET_SEPARATOR_PREFIX = 'priority-separator:';

export type PriorityBucket = {
  priority: number;
  channels: RouteChannel[];
};

type PriorityBucketEditorChannelItem = {
  id: number;
  kind: 'channel';
  channel: RouteChannel;
};

type PriorityBucketEditorSeparatorItem = {
  id: string;
  kind: 'separator';
};

export type PriorityBucketEditorItem = PriorityBucketEditorChannelItem | PriorityBucketEditorSeparatorItem;

export function createPriorityBucketSeparatorId(index: number): string {
  return `${PRIORITY_BUCKET_SEPARATOR_PREFIX}${index}`;
}

export function isPriorityBucketSeparatorId(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(PRIORITY_BUCKET_SEPARATOR_PREFIX);
}

export function buildPriorityBuckets(channels: RouteChannel[]): PriorityBucket[] {
  const grouped = new Map<number, RouteChannel[]>();
  for (const channel of normalizeChannels(channels || [])) {
    const priority = channel.priority ?? 0;
    if (!grouped.has(priority)) grouped.set(priority, []);
    grouped.get(priority)!.push(channel);
  }
  return Array.from(grouped.entries()).map(([priority, bucketChannels]) => ({
    priority,
    channels: bucketChannels,
  }));
}

export function buildPriorityBucketEditorItems(channels: RouteChannel[]): PriorityBucketEditorItem[] {
  const buckets = buildPriorityBuckets(channels);
  const items: PriorityBucketEditorItem[] = [];
  buckets.forEach((bucket, index) => {
    for (const channel of bucket.channels) {
      items.push({ id: channel.id, kind: 'channel', channel });
    }
    if (index < buckets.length - 1) {
      items.push({ id: createPriorityBucketSeparatorId(index), kind: 'separator' });
    }
  });
  return items;
}

export function splitPriorityBucketAfterChannel(
  channels: RouteChannel[],
  channelId: number,
): RouteChannel[] {
  const normalized = normalizeChannels(channels || []);
  if (normalized.length <= 1) return normalized;

  const items = buildPriorityBucketEditorItems(normalized);
  const channelIndex = items.findIndex((item) => item.kind === 'channel' && item.id === channelId);
  if (channelIndex < 0) return normalized;

  const nextItem = items[channelIndex + 1];
  if (!nextItem || nextItem.kind === 'separator') {
    return normalized;
  }

  const next = [...items];
  next.splice(channelIndex + 1, 0, {
    id: `${PRIORITY_BUCKET_SEPARATOR_PREFIX}split:${channelId}`,
    kind: 'separator',
  });
  return denseRenormalizeChannels(next);
}

function moveItem<T>(items: T[], fromIndex: number, toIndex: number): T[] {
  const next = [...items];
  const [item] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, item);
  return next;
}

function denseRenormalizeChannels(items: PriorityBucketEditorItem[]): RouteChannel[] {
  let rawBucketIndex = 0;
  let nextPriority = 0;
  const rawToDense = new Map<number, number>();
  const reordered: RouteChannel[] = [];

  for (const item of items) {
    if (item.kind === 'separator') {
      rawBucketIndex += 1;
      continue;
    }
    if (!rawToDense.has(rawBucketIndex)) {
      rawToDense.set(rawBucketIndex, nextPriority);
      nextPriority += 1;
    }
    reordered.push({
      ...item.channel,
      priority: rawToDense.get(rawBucketIndex)!,
    });
  }

  return normalizeChannels(reordered);
}

export function applyPriorityBucketDrag(
  channels: RouteChannel[],
  activeId: string | number,
  overId: string | number,
): RouteChannel[] {
  const normalized = normalizeChannels(channels || []);
  if (normalized.length === 0 || activeId === overId) return normalized;

  const items = buildPriorityBucketEditorItems(normalized);
  const activeIndex = items.findIndex((item) => item.id === activeId);
  const overIndex = items.findIndex((item) => item.id === overId);
  if (activeIndex < 0 || overIndex < 0 || activeIndex === overIndex) {
    return normalized;
  }

  const activeItem = items[activeIndex];
  if (activeItem.kind === 'separator') {
    const targetItem = items[overIndex];
    if (targetItem.kind !== 'channel') {
      return normalized;
    }

    let previousSeparatorIndex = -1;
    for (let index = activeIndex - 1; index >= 0; index -= 1) {
      if (items[index]?.kind === 'separator') {
        previousSeparatorIndex = index;
        break;
      }
    }

    let nextSeparatorIndex = items.length;
    for (let index = activeIndex + 1; index < items.length; index += 1) {
      if (items[index]?.kind === 'separator') {
        nextSeparatorIndex = index;
        break;
      }
    }

    if (overIndex <= previousSeparatorIndex || overIndex >= nextSeparatorIndex) {
      return normalized;
    }
  }

  return denseRenormalizeChannels(moveItem(items, activeIndex, overIndex));
}
