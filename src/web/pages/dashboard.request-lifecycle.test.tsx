import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, create } from "react-test-renderer";
import { ToastProvider } from "../components/Toast.js";
import Dashboard from "./Dashboard.js";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getDashboardSnapshot: vi.fn(),
    getDashboardInsights: vi.fn(),
    getSiteSnapshot: vi.fn(),
  },
}));

vi.mock("../api.js", () => ({ api: apiMock }));

function dashboardSnapshot() {
  return {
    totalBalance: 0,
    totalUsed: 0,
    todaySpend: 0,
    todayReward: 0,
    activeAccounts: 0,
    totalAccounts: 0,
    todayCheckin: { success: 0, total: 0 },
    proxy24h: { success: 0, total: 0, totalTokens: 0 },
    performance: { windowSeconds: 60, requestsPerMinute: 0, tokensPerMinute: 0 },
    modelAnalysis: null,
  };
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe("Dashboard request lifecycle", () => {
  const originalDocument = globalThis.document;
  const originalWindow = globalThis.window;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    const listeners = new Map<string, EventListener>();
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        visibilityState: "visible",
        addEventListener: vi.fn((type: string, listener: EventListener) => {
          listeners.set(type, listener);
        }),
        removeEventListener: vi.fn((type: string) => {
          listeners.delete(type);
        }),
        dispatchEvent: vi.fn((event: Event) => {
          listeners.get(event.type)?.(event);
          return true;
        }),
        getElementById: vi.fn(() => null),
      },
    });
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        innerWidth: 1280,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        matchMedia: vi.fn(() => ({
          matches: false,
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          addListener: vi.fn(),
          removeListener: vi.fn(),
        })),
      },
    });
    apiMock.getDashboardSnapshot.mockResolvedValue(dashboardSnapshot());
    apiMock.getDashboardInsights.mockResolvedValue({ modelAnalysis: null });
    apiMock.getSiteSnapshot.mockResolvedValue({
      distribution: [],
      trend: [],
      sites: [],
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: originalDocument,
    });
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: originalWindow,
    });
    vi.clearAllMocks();
  });

  it("does not issue a duplicate summary request on visible mount", async () => {
    let root!: ReturnType<typeof create>;
    await act(async () => {
      root = create(
        <ToastProvider>
          <Dashboard />
        </ToastProvider>,
      );
    });
    expect(apiMock.getDashboardSnapshot).toHaveBeenCalledTimes(1);
    await flush();
    expect(apiMock.getDashboardSnapshot).toHaveBeenCalledTimes(1);
    await act(async () => root.unmount());
  });

  it("keeps polling single-flight when a refresh is slower than the interval", async () => {
    let resolvePoll!: (value: ReturnType<typeof dashboardSnapshot>) => void;
    apiMock.getDashboardSnapshot
      .mockResolvedValueOnce(dashboardSnapshot())
      .mockImplementationOnce(
        () => new Promise((resolve) => { resolvePoll = resolve; }),
      );
    let root!: ReturnType<typeof create>;
    await act(async () => {
      root = create(
        <ToastProvider>
          <Dashboard />
        </ToastProvider>,
      );
    });
    await flush();

    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });
    await flush();
    await act(async () => {
      vi.advanceTimersByTime(60_000);
    });
    await flush();
    expect(apiMock.getDashboardSnapshot).toHaveBeenCalledTimes(2);

    await act(async () => resolvePoll(dashboardSnapshot()));
    await flush();
    await act(async () => root.unmount());
  });

  it("stops while hidden and performs one refresh on the next visible transition", async () => {
    let root!: ReturnType<typeof create>;
    await act(async () => {
      root = create(
        <ToastProvider>
          <Dashboard />
        </ToastProvider>,
      );
    });
    await flush();
    const initialCalls = apiMock.getDashboardSnapshot.mock.calls.length;

    (globalThis.document as Document & { visibilityState: string }).visibilityState = "hidden";
    await act(async () => {
      globalThis.document.dispatchEvent(new Event("visibilitychange"));
      vi.advanceTimersByTime(90_000);
    });
    expect(apiMock.getDashboardSnapshot).toHaveBeenCalledTimes(initialCalls);

    (globalThis.document as Document & { visibilityState: string }).visibilityState = "visible";
    await act(async () => {
      globalThis.document.dispatchEvent(new Event("visibilitychange"));
      await Promise.resolve();
    });
    const afterVisible = apiMock.getDashboardSnapshot.mock.calls.length;
    await act(async () => {
      globalThis.document.dispatchEvent(new Event("visibilitychange"));
      await Promise.resolve();
    });
    expect(apiMock.getDashboardSnapshot).toHaveBeenCalledTimes(afterVisible);
    await act(async () => root.unmount());
  });

  it("aborts the summary request on unmount", async () => {
    let signal!: AbortSignal;
    apiMock.getDashboardSnapshot.mockImplementation((options?: { signal?: AbortSignal }) => {
      signal = options?.signal as AbortSignal;
      return new Promise(() => {});
    });
    let root!: ReturnType<typeof create>;
    await act(async () => {
      root = create(
        <ToastProvider>
          <Dashboard />
        </ToastProvider>,
      );
      await Promise.resolve();
    });
    await act(async () => root.unmount());
    expect(signal.aborted).toBe(true);
  });

  it("disables site speed actions while a probe is in flight", async () => {
    apiMock.getSiteSnapshot.mockResolvedValue({
      distribution: [],
      trend: [],
      sites: [{ id: 1, name: "主站", url: "https://site.test" }],
    });
    let resolveFetch!: (response: Response) => void;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      () => new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      }),
    );

    let root!: ReturnType<typeof create>;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <Dashboard />
          </ToastProvider>,
        );
      });
      await flush();

      const allProbeButton = root.root.findByProps({ "aria-label": "一键测速" });
      expect(allProbeButton.props.disabled).toBe(false);

      await act(async () => {
        allProbeButton.props.onClick();
        await Promise.resolve();
      });
      const inFlightButton = root.root.findByProps({ "aria-label": "一键测速" });
      expect(inFlightButton.props.disabled).toBe(true);
      expect(fetchSpy).toHaveBeenCalledWith(
        "https://site.test/v1/models",
        expect.objectContaining({ mode: "no-cors" }),
      );

      await act(async () => {
        resolveFetch(new Response(null, { status: 200 }));
        await Promise.resolve();
      });
      await flush();
      const completedButton = root.root.findByProps({ "aria-label": "一键测速" });
      expect(completedButton.props.disabled).toBe(false);
    } finally {
      await act(async () => root?.unmount());
      fetchSpy.mockRestore();
    }
  });

  it("clears stale loading states when a new single-site probe replaces a batch", async () => {
    apiMock.getSiteSnapshot.mockResolvedValue({
      distribution: [],
      trend: [],
      sites: [
        { id: 1, name: "主站", url: "https://site.test" },
        { id: 2, name: "备用站", url: "https://backup.test" },
      ],
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      () => new Promise<Response>(() => {}),
    );

    const buttonText = (node: unknown): string => {
      if (typeof node === "string") return node;
      if (!node || typeof node !== "object") return "";
      const children = (node as { children?: unknown[] }).children;
      return Array.isArray(children) ? children.map(buttonText).join("") : "";
    };

    let root!: ReturnType<typeof create>;
    try {
      await act(async () => {
        root = create(
          <ToastProvider>
            <Dashboard />
          </ToastProvider>,
        );
      });
      await flush();

      const allProbeButton = root.root.findByProps({ "aria-label": "一键测速" });
      await act(async () => {
        allProbeButton.props.onClick();
        await Promise.resolve();
      });
      await flush();

      const siteButtons = () => root.root.findAllByType("button")
        .filter((button) => button.props["aria-label"] !== "一键测速")
        .filter((button) => typeof button.props.onClick === "function")
        .filter((button) => {
          const text = buttonText(button);
          return text.includes("主站") || text.includes("备用站") || text === "..." || text === "测速";
        });
      const beforeReplacement = siteButtons();
      expect(beforeReplacement.some((button) => buttonText(button).includes("..."))).toBe(true);

      const primaryButton = beforeReplacement.find((button) => buttonText(button) === "...");
      expect(primaryButton).toBeDefined();
      // Invoke the handler directly to model a replacement action even while
      // the UI's shared in-flight guard has disabled the control.
      await act(async () => {
        primaryButton!.props.onClick();
        await Promise.resolve();
      });
      await flush();

      const replacementButtons = siteButtons();
      const backupButton = replacementButtons.find((button) => buttonText(button) === "测速");
      expect(backupButton).toBeDefined();
      expect(buttonText(backupButton!)).toContain("测速");
      expect(buttonText(backupButton!)).not.toContain("...");
    } finally {
      await act(async () => root?.unmount());
      fetchSpy.mockRestore();
    }
  });
});
