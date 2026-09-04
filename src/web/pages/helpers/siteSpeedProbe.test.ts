import { afterEach, describe, expect, it, vi } from "vitest";
import {
  probeSiteSpeed,
  probeSiteSpeeds,
} from "./siteSpeedProbe.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("site speed probe", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps no-cors GET semantics and measures each result", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({ ok: false });
    let now = 100;
    const resultPromise = probeSiteSpeed(" https://example.test/// ", {
      fetchImpl,
      now: () => now,
    });
    now = 142;
    const result = await resultPromise;

    expect(result).toEqual({ status: "done", ms: 42 });
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://example.test/v1/models",
      expect.objectContaining({ method: "GET", mode: "no-cors" }),
    );
  });

  it("limits batch concurrency to four and preserves stable site keys", async () => {
    let active = 0;
    let maxActive = 0;
    const fetchImpl = vi.fn(async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      return new Response();
    });
    const sites = Array.from({ length: 9 }, (_, index) => ({
      id: index + 1,
      url: `https://site-${index + 1}.test`,
    }));
    const resultsPromise = probeSiteSpeeds(sites, {
      concurrency: 4,
      fetchImpl,
    });
    const results = await resultsPromise;

    expect(maxActive).toBeLessThanOrEqual(4);
    expect(results.size).toBe(9);
    expect(results.get("1")?.status).toBe("done");
    expect(results.get("9")?.status).toBe("done");
  });

  it("settles immediately for an empty site list", async () => {
    const fetchImpl = vi.fn();
    const results = await probeSiteSpeeds([], { fetchImpl });

    expect(results.size).toBe(0);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("reports timeout and clears its timer", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(
      (_url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const pending = deferred<Response>();
        init?.signal?.addEventListener("abort", () => {
          pending.reject(
            Object.assign(new Error("aborted"), { name: "AbortError" }),
          );
        });
        return pending.promise;
      },
    );
    const resultPromise = probeSiteSpeed("https://slow.test", {
      fetchImpl,
      timeoutMs: 25,
    });
    await vi.advanceTimersByTimeAsync(25);
    await expect(resultPromise).resolves.toEqual({ status: "timeout" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("settles on timeout even when a fetch implementation ignores abort", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(() => new Promise<Response>(() => {}));
    const resultPromise = probeSiteSpeed("https://noncooperative.test", {
      fetchImpl,
      timeoutMs: 10,
    });
    await vi.advanceTimersByTimeAsync(10);
    await expect(resultPromise).resolves.toEqual({ status: "timeout" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("distinguishes caller cancellation from timeout", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(() => new Promise<Response>(() => {}));
    const external = new AbortController();
    const resultPromise = probeSiteSpeed("https://cancelled.test", {
      fetchImpl,
      signal: external.signal,
      timeoutMs: 100,
    });
    external.abort();
    await expect(resultPromise).resolves.toEqual({ status: "aborted" });
    expect(vi.getTimerCount()).toBe(0);
  });
});
