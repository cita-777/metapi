import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import SiteDistributionChart from './SiteDistributionChart.js';

vi.mock('@visactor/react-vchart', () => ({
  VChart: () => null,
}));

describe('SiteDistributionChart', () => {
  const originalDocument = globalThis.document;
  const originalGetComputedStyle = globalThis.getComputedStyle;
  const originalMutationObserver = globalThis.MutationObserver;

  beforeEach(() => {
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

  it('renders with fallback label color when browser theme APIs are unavailable', async () => {
    let renderer!: WebTestRenderer;

    await expect(act(async () => {
      renderer = create(
        <SiteDistributionChart
          data={[
            {
              siteName: 'Demo Site',
              platform: 'demo',
              totalBalance: 12.34,
              totalSpend: 1.23,
              accountCount: 2,
            },
          ]}
        />,
      );
    })).resolves.toBeUndefined();

    renderer.unmount();
  });
});
