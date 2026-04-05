import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import DownstreamKeyTrendChart from './DownstreamKeyTrendChart.js';
import { formatDateTimeMinuteLocal } from '../../pages/helpers/checkinLogTime.js';

const vChartSpy = vi.fn();

vi.mock('@visactor/react-vchart', () => ({
  VChart: (props: Record<string, unknown>) => {
    vChartSpy(props);
    return null;
  },
}));

function pad2(value: number): string {
  return String(value).padStart(2, '0');
}

function formatExpectedAxisLabel(raw: string, bucketSeconds: number): string {
  const parsed = new Date(raw);
  const month = pad2(parsed.getMonth() + 1);
  const day = pad2(parsed.getDate());
  if (bucketSeconds >= 86400) return `${month}/${day}`;
  return `${month}/${day} ${pad2(parsed.getHours())}:${pad2(parsed.getMinutes())}`;
}

describe('DownstreamKeyTrendChart', () => {
  const originalDocument = globalThis.document;
  const originalGetComputedStyle = globalThis.getComputedStyle;
  const originalMutationObserver = globalThis.MutationObserver;

  beforeEach(() => {
    vChartSpy.mockClear();
    globalThis.document = {
      documentElement: {
        getAttribute: vi.fn(),
      },
    } as unknown as Document;
    Reflect.deleteProperty(globalThis as typeof globalThis & Record<string, unknown>, 'getComputedStyle');
    Reflect.deleteProperty(globalThis as typeof globalThis & Record<string, unknown>, 'MutationObserver');
  });

  afterEach(() => {
    globalThis.document = originalDocument;
    globalThis.getComputedStyle = originalGetComputedStyle;
    globalThis.MutationObserver = originalMutationObserver;
  });

  it('formats trend bucket timestamps with local display time', async () => {
    const bucketStart = '2026-04-05T15:00:00.000Z';
    let renderer!: ReactTestRenderer;

    await expect(act(async () => {
      renderer = create(
        <DownstreamKeyTrendChart
          bucketSeconds={3600}
          buckets={[
            {
              startUtc: bucketStart,
              totalRequests: 2,
              totalTokens: 2128425,
              totalCost: 2.128425,
              successRate: 100,
            },
          ]}
        />,
      );
    })).resolves.toBeUndefined();

    expect(vChartSpy).toHaveBeenCalledTimes(1);
    const spec = vChartSpy.mock.calls[0]?.[0]?.spec as {
      data?: Array<{ values?: Array<{ date?: string; tooltipDate?: string }> }>;
      axes?: Array<{
        label?: {
          formatMethod?: (value: string) => string;
        };
      }>;
      tooltip?: {
        dimension?: {
          title?: {
            value?: (datum: Record<string, unknown>) => string;
          };
        };
      };
    };

    const expectedLabel = formatDateTimeMinuteLocal(bucketStart);
    expect(spec.data?.[0]?.values?.[0]?.tooltipDate).toBe(expectedLabel);
    expect(spec.tooltip?.dimension?.title?.value?.({ tooltipDate: expectedLabel })).toBe(expectedLabel);
    expect(spec.axes?.[0]?.label?.formatMethod?.(bucketStart)).toBe(formatExpectedAxisLabel(bucketStart, 3600));

    renderer.unmount();
  });

  it('uses day-only axis labels for daily buckets', async () => {
    const bucketStart = '2026-04-05T16:00:00.000Z';
    let renderer!: ReactTestRenderer;

    await expect(act(async () => {
      renderer = create(
        <DownstreamKeyTrendChart
          bucketSeconds={86400}
          buckets={[
            {
              startUtc: bucketStart,
              totalRequests: 3,
              totalTokens: 600,
              totalCost: 0.06,
              successRate: 66.7,
            },
          ]}
        />,
      );
    })).resolves.toBeUndefined();

    const spec = vChartSpy.mock.calls[0]?.[0]?.spec as {
      axes?: Array<{
        label?: {
          formatMethod?: (value: string) => string;
        };
      }>;
    };

    expect(spec.axes?.[0]?.label?.formatMethod?.(bucketStart)).toBe(formatExpectedAxisLabel(bucketStart, 86400));

    renderer.unmount();
  });
});
