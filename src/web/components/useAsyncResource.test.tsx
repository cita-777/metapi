import { afterEach, describe, expect, it, vi } from "vitest";
import { act, create } from "react-test-renderer";
import {
  useAsyncResource,
  type AsyncLoader,
  type AsyncResource,
} from "./useAsyncResource.js";

type HarnessProps<T> = {
  loader: AsyncLoader<T>;
  autoLoad?: boolean;
  onState: (resource: AsyncResource<T>) => void;
};

function Harness<T>({ loader, autoLoad = false, onState }: HarnessProps<T>) {
  const resource = useAsyncResource(loader, { autoLoad });
  onState(resource);
  return null;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("useAsyncResource", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("ignores stale results and aborts the previous request", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const signals: AbortSignal[] = [];
    const loader = vi.fn<AsyncLoader<string>>((signal) => {
      signals.push(signal);
      return signals.length === 1 ? first.promise : second.promise;
    });
    let latest!: AsyncResource<string>;
    let root!: ReturnType<typeof create>;

    await act(async () => {
      root = create(<Harness loader={loader} onState={(next) => (latest = next)} />);
    });

    let firstRequest!: Promise<string | undefined>;
    let secondRequest!: Promise<string | undefined>;
    await act(async () => {
      firstRequest = latest.reload();
      secondRequest = latest.reload();
    });

    expect(signals[0]?.aborted).toBe(true);
    await act(async () => {
      first.resolve("stale");
      second.resolve("fresh");
      await Promise.all([firstRequest, secondRequest]);
    });

    expect(latest.data).toBe("fresh");
    expect(latest.error).toBeNull();
    expect(latest.errorKind).toBe("none");
    await act(async () => {
      root.unmount();
    });
  });

  it("keeps data during silent refresh and dedupes polling calls", async () => {
    const initial = deferred<string>();
    const refresh = deferred<string>();
    let callCount = 0;
    const loader = vi.fn<AsyncLoader<string>>(() => {
      callCount += 1;
      return callCount === 1 ? initial.promise : refresh.promise;
    });
    let latest!: AsyncResource<string>;
    let root!: ReturnType<typeof create>;

    await act(async () => {
      root = create(<Harness loader={loader} onState={(next) => (latest = next)} />);
    });

    await act(async () => {
      const firstRequest = latest.reload();
      initial.resolve("cached");
      await firstRequest;
    });
    expect(latest.data).toBe("cached");

    let refreshRequest!: Promise<string | undefined>;
    await act(async () => {
      refreshRequest = latest.reload({ silent: true, dedupe: true });
    });
    expect(latest.data).toBe("cached");
    expect(latest.refreshing).toBe(true);

    const duplicate = latest.reload({ silent: true, dedupe: true });
    expect(duplicate).toBe(refreshRequest);

    await act(async () => {
      refresh.resolve("updated");
      await refreshRequest;
    });
    expect(latest.data).toBe("updated");
    expect(latest.refreshing).toBe(false);
    expect(callCount).toBe(2);
    root.unmount();
  });

  it("classifies timeout separately and treats cancellation as non-error", async () => {
    const loader = vi
      .fn<AsyncLoader<string>>()
      .mockRejectedValueOnce(new Error("请求超时（15s）"))
      .mockRejectedValueOnce(
        Object.assign(new Error("aborted"), { name: "AbortError" }),
      );
    let latest!: AsyncResource<string>;
    let root!: ReturnType<typeof create>;

    await act(async () => {
      root = create(<Harness loader={loader} onState={(next) => (latest = next)} />);
    });

    await act(async () => {
      await latest.reload();
    });
    expect(latest.errorKind).toBe("timeout");
    expect(latest.error?.message).toContain("超时");

    await act(async () => {
      await latest.reload();
    });
    expect(latest.errorKind).toBe("abort");
    expect(latest.error).toBeNull();
    expect(latest.cancelled).toBe(true);
    root.unmount();
  });

  it("aborts an in-flight request when the component unmounts", async () => {
    const pending = deferred<string>();
    let signal!: AbortSignal;
    const loader = vi.fn<AsyncLoader<string>>((nextSignal) => {
      signal = nextSignal;
      return pending.promise;
    });
    let latest!: AsyncResource<string>;
    let root!: ReturnType<typeof create>;

    await act(async () => {
      root = create(<Harness loader={loader} onState={(next) => (latest = next)} />);
    });
    await act(async () => {
      void latest.reload();
      await Promise.resolve();
    });
    await act(async () => {
      root.unmount();
    });

    expect(signal.aborted).toBe(true);
    pending.resolve("late");
    await act(async () => {
      await Promise.resolve();
    });
  });
});
