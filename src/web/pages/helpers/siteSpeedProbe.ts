export type SiteSpeedProbeStatus = "done" | "timeout" | "error" | "aborted";

export type SiteSpeedProbeResult = {
  status: SiteSpeedProbeStatus;
  ms?: number;
  error?: Error;
};

export type SiteSpeedProbeOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Dependency injection keeps browser-only probing deterministic in tests. */
  fetchImpl?: typeof fetch;
  now?: () => number;
};

export type SiteSpeedProbeSite = {
  id?: number | string | null;
  url?: string | null;
};

export type SiteSpeedProbeBatchOptions = SiteSpeedProbeOptions & {
  concurrency?: number;
  onResult?: (key: string, result: SiteSpeedProbeResult) => void;
};

function toError(value: unknown): Error {
  if (value instanceof Error) return value;
  if (typeof value === "string") return new Error(value);
  if (typeof value === "object" && value !== null) {
    const message = (value as { message?: unknown }).message;
    if (typeof message === "string") return new Error(message);
  }
  return new Error("测速失败");
}

function isAbortError(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { name?: unknown }).name === "AbortError"
  );
}

function readNow(now?: () => number): number {
  if (now) return now();
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

/**
 * Probe one site using the existing opaque no-cors capability.  A resolved
 * opaque response is considered reachable; response.ok/body are intentionally
 * not inspected because browsers do not expose them for no-cors responses.
 */
export async function probeSiteSpeed(
  url: string,
  options: SiteSpeedProbeOptions = {},
): Promise<SiteSpeedProbeResult> {
  const baseUrl = url.trim();
  if (!baseUrl) {
    return { status: "error", error: new Error("站点地址为空") };
  }
  const requestedTimeoutMs = options.timeoutMs ?? 10_000;
  const timeoutMs = Number.isFinite(requestedTimeoutMs)
    ? Math.max(1, Math.trunc(requestedTimeoutMs))
    : 10_000;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return { status: "error", error: new Error("当前环境不支持测速") };
  }

  const controller = new AbortController();
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  let rejectLifecycle: ((reason?: unknown) => void) | null = null;
  let timedOut = false;
  const lifecyclePromise = new Promise<never>((_, reject) => {
    rejectLifecycle = reject;
  });
  timeoutHandle = setTimeout(() => {
    timedOut = true;
    controller.abort();
    rejectLifecycle?.(Object.assign(new Error("请求超时"), { name: "TimeoutError" }));
  }, timeoutMs);
  let externalAbortHandler: (() => void) | null = null;
  let externallyAborted = options.signal?.aborted === true;
  if (options.signal) {
    externalAbortHandler = () => {
      externallyAborted = true;
      controller.abort();
      rejectLifecycle?.(Object.assign(new Error("aborted"), { name: "AbortError" }));
    };
    if (options.signal.aborted) {
      externalAbortHandler();
    } else {
      options.signal.addEventListener("abort", externalAbortHandler, {
        once: true,
      });
    }
  }

  const startedAt = readNow(options.now);
  try {
    if (externallyAborted) return { status: "aborted" };
    const fetchPromise = fetchImpl(`${baseUrl.replace(/\/+$/, "")}/v1/models`, {
      method: "GET",
      mode: "no-cors",
      signal: controller.signal,
    });
    await Promise.race([fetchPromise, lifecyclePromise]);
    if (externallyAborted || options.signal?.aborted) {
      return { status: "aborted" };
    }
    if (timedOut || controller.signal.aborted) {
      return { status: "timeout" };
    }
    return {
      status: "done",
      ms: Math.max(0, Math.round(readNow(options.now) - startedAt)),
    };
  } catch (value) {
    if (timedOut) {
      return { status: "timeout" };
    }
    if (externallyAborted || options.signal?.aborted) {
      return {
        status: "aborted",
      };
    }
    if (isAbortError(value)) return { status: "error", error: toError(value) };
    return { status: "error", error: toError(value) };
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = null;
    }
    if (externalAbortHandler && options.signal) {
      options.signal.removeEventListener("abort", externalAbortHandler);
    }
  }
}

function siteKey(site: SiteSpeedProbeSite, index: number): string {
  return String(site.id ?? index);
}

/** Probe a list with a bounded worker pool and stable result keys. */
export async function probeSiteSpeeds<T extends SiteSpeedProbeSite>(
  sites: readonly T[],
  options: SiteSpeedProbeBatchOptions = {},
): Promise<Map<string, SiteSpeedProbeResult>> {
  const results = new Map<string, SiteSpeedProbeResult>();
  const requestedConcurrency =
    typeof options.concurrency === "number" &&
    Number.isFinite(options.concurrency)
      ? Math.trunc(options.concurrency)
      : 4;
  const concurrency = Math.max(
    1,
    Math.min(sites.length || 1, requestedConcurrency),
  );
  let cursor = 0;

  const worker = async () => {
    while (true) {
      if (options.signal?.aborted) return;
      const index = cursor++;
      if (index >= sites.length) return;
      const site = sites[index];
      if (!site) continue;
      const url = typeof site.url === "string" ? site.url : "";
      const result = url
        ? await probeSiteSpeed(url, options)
        : { status: "error" as const, error: new Error("站点地址为空") };
      const key = siteKey(site, index);
      results.set(key, result);
      try {
        options.onResult?.(key, result);
      } catch {
        // A presentation callback must not make the whole batch reject.
      }
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return results;
}
