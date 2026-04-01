import { config } from '../config.js';
import {
  getCredentialModeFromExtraConfig,
  hasOauthProvider,
} from './accountExtraConfig.js';

type StickyEntry = {
  channelId: number;
  expiresAtMs: number;
};

type ActiveLeaseState = {
  release: () => void;
};

type ChannelWaiter = {
  cancelled: boolean;
  resolve: (result: AcquireProxyChannelLeaseResult) => void;
  timer: ReturnType<typeof setTimeout> | null;
};

type ChannelRuntimeState = {
  activeLeaseIds: Set<number>;
  queue: ChannelWaiter[];
};

export type ProxyChannelLoadSnapshot = {
  channelId: number;
  sessionScoped: boolean;
  concurrencyLimit: number;
  activeLeaseCount: number;
  waitingCount: number;
  loadRatio: number;
  saturated: boolean;
};

export type ProxyChannelLease = {
  channelId: number;
  isActive(): boolean;
  release(): void;
  touch(): void;
};

export type AcquireProxyChannelLeaseResult =
  | { status: 'acquired'; lease: ProxyChannelLease }
  | { status: 'timeout'; waitMs: number };

const stickySessionBindings = new Map<string, StickyEntry>();
const channelRuntimeStates = new Map<number, ChannelRuntimeState>();
let nextLeaseId = 1;
type SessionScopedChannelInput =
  | string
  | null
  | undefined
  | {
    extraConfig?: string | null;
    oauthProvider?: string | null;
  };

function shouldUnrefTimer(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>) {
  if (typeof (timer as { unref?: () => void }).unref === 'function') {
    (timer as { unref: () => void }).unref();
  }
}

function cleanupExpiredStickyBindings(nowMs = Date.now()): void {
  for (const [key, entry] of stickySessionBindings.entries()) {
    if (entry.expiresAtMs <= nowMs) {
      stickySessionBindings.delete(key);
    }
  }
}

function getSessionScopedExtraConfig(input?: SessionScopedChannelInput): string | null | undefined {
  if (typeof input === 'string' || input == null) return input;
  return input.extraConfig;
}

function isSessionScopedChannel(input?: SessionScopedChannelInput): boolean {
  return getCredentialModeFromExtraConfig(getSessionScopedExtraConfig(input)) === 'session'
    || hasOauthProvider(input);
}

function getStickySessionTtlMs(): number {
  return Math.max(30_000, Math.trunc(config.proxyStickySessionTtlMs || 0));
}

function getChannelLeaseTtlMs(): number {
  return Math.max(5_000, Math.trunc(config.proxySessionChannelLeaseTtlMs || 0));
}

function getChannelLeaseKeepaliveMs(): number {
  return Math.max(1_000, Math.trunc(config.proxySessionChannelLeaseKeepaliveMs || 0));
}

function getChannelQueueWaitMs(): number {
  return Math.max(0, Math.trunc(config.proxySessionChannelQueueWaitMs || 0));
}

function getChannelConcurrencyLimit(input?: SessionScopedChannelInput): number {
  if (!isSessionScopedChannel(input)) return 0;
  return Math.max(0, Math.trunc(config.proxySessionChannelConcurrencyLimit || 0));
}

function getOrCreateChannelRuntimeState(channelId: number): ChannelRuntimeState {
  let state = channelRuntimeStates.get(channelId);
  if (!state) {
    state = {
      activeLeaseIds: new Set<number>(),
      queue: [],
    };
    channelRuntimeStates.set(channelId, state);
  }
  return state;
}

function pruneCancelledWaiters(state: ChannelRuntimeState): void {
  if (state.queue.length <= 0) return;
  state.queue = state.queue.filter((waiter) => !waiter.cancelled);
}

function maybeDeleteChannelRuntimeState(channelId: number): void {
  const state = channelRuntimeStates.get(channelId);
  if (!state) return;
  pruneCancelledWaiters(state);
  if (state.activeLeaseIds.size <= 0 && state.queue.every((waiter) => waiter.cancelled)) {
    channelRuntimeStates.delete(channelId);
  }
}

function createNoopLease(channelId: number): ProxyChannelLease {
  return {
    channelId,
    isActive: () => false,
    release: () => {},
    touch: () => {},
  };
}

class ProxyChannelCoordinator {
  buildStickySessionKey(input: {
    clientKind?: string | null;
    sessionId?: string | null;
    requestedModel: string;
    downstreamPath: string;
    downstreamApiKeyId?: number | null;
  }): string | null {
    if (!config.proxyStickySessionEnabled) return null;
    const sessionId = String(input.sessionId || '').trim();
    if (!sessionId) return null;
    const requestedModel = String(input.requestedModel || '').trim().toLowerCase();
    if (!requestedModel) return null;
    const downstreamPath = String(input.downstreamPath || '').trim().toLowerCase() || 'unknown';
    const clientKind = String(input.clientKind || 'generic').trim().toLowerCase() || 'generic';
    const owner = typeof input.downstreamApiKeyId === 'number' && Number.isFinite(input.downstreamApiKeyId)
      ? `key:${Math.trunc(input.downstreamApiKeyId)}`
      : 'key:anonymous';
    return [owner, clientKind, downstreamPath, requestedModel, sessionId].join('|');
  }

  getStickyChannelId(stickySessionKey?: string | null, nowMs = Date.now()): number | null {
    cleanupExpiredStickyBindings(nowMs);
    const normalizedKey = String(stickySessionKey || '').trim();
    if (!normalizedKey) return null;
    const entry = stickySessionBindings.get(normalizedKey);
    if (!entry || entry.expiresAtMs <= nowMs) {
      stickySessionBindings.delete(normalizedKey);
      return null;
    }
    return entry.channelId;
  }

  bindStickyChannel(stickySessionKey: string | null | undefined, channelId: number, accountIdentity?: SessionScopedChannelInput): void {
    if (!config.proxyStickySessionEnabled) return;
    if (!isSessionScopedChannel(accountIdentity)) return;
    const normalizedKey = String(stickySessionKey || '').trim();
    if (!normalizedKey || !Number.isFinite(channelId) || channelId <= 0) return;
    cleanupExpiredStickyBindings();
    stickySessionBindings.set(normalizedKey, {
      channelId: Math.trunc(channelId),
      expiresAtMs: Date.now() + getStickySessionTtlMs(),
    });
  }

  clearStickyChannel(stickySessionKey?: string | null, channelId?: number | null): void {
    const normalizedKey = String(stickySessionKey || '').trim();
    if (!normalizedKey) return;
    const existing = stickySessionBindings.get(normalizedKey);
    if (!existing) return;
    if (typeof channelId === 'number' && Number.isFinite(channelId) && existing.channelId !== Math.trunc(channelId)) {
      return;
    }
    stickySessionBindings.delete(normalizedKey);
  }

  getActiveChannelIds(): number[] {
    const ids: number[] = [];
    for (const [channelId, state] of channelRuntimeStates.entries()) {
      pruneCancelledWaiters(state);
      if (state.activeLeaseIds.size > 0) {
        ids.push(channelId);
      }
    }
    return ids;
  }

  getChannelLoadSnapshot(input: {
    channelId: number;
    accountExtraConfig?: string | null;
    accountOauthProvider?: string | null;
  }): ProxyChannelLoadSnapshot {
    const channelId = Math.trunc(input.channelId || 0);
    const sessionScoped = isSessionScopedChannel({
      extraConfig: input.accountExtraConfig,
      oauthProvider: input.accountOauthProvider,
    });
    const concurrencyLimit = getChannelConcurrencyLimit({
      extraConfig: input.accountExtraConfig,
      oauthProvider: input.accountOauthProvider,
    });
    const state = channelId > 0 ? channelRuntimeStates.get(channelId) : null;
    if (state) {
      pruneCancelledWaiters(state);
    }
    const activeLeaseCount = state?.activeLeaseIds.size ?? 0;
    const waitingCount = state?.queue.length ?? 0;
    const denominator = concurrencyLimit > 0 ? concurrencyLimit : 1;
    return {
      channelId,
      sessionScoped,
      concurrencyLimit,
      activeLeaseCount,
      waitingCount,
      loadRatio: (activeLeaseCount + waitingCount) / denominator,
      saturated: concurrencyLimit > 0 && activeLeaseCount >= concurrencyLimit,
    };
  }

  getChannelLoadSnapshots(input: Array<{
    channelId: number;
    accountExtraConfig?: string | null;
    accountOauthProvider?: string | null;
  }>): Map<number, ProxyChannelLoadSnapshot> {
    const snapshots = new Map<number, ProxyChannelLoadSnapshot>();
    for (const item of input) {
      const snapshot = this.getChannelLoadSnapshot(item);
      snapshots.set(snapshot.channelId, snapshot);
    }
    return snapshots;
  }

  async acquireChannelLease(input: {
    channelId: number;
    accountExtraConfig?: string | null;
    accountOauthProvider?: string | null;
  }): Promise<AcquireProxyChannelLeaseResult> {
    const channelId = Math.trunc(input.channelId || 0);
    if (channelId <= 0) {
      return {
        status: 'acquired',
        lease: createNoopLease(0),
      };
    }

    const concurrencyLimit = getChannelConcurrencyLimit({
      extraConfig: input.accountExtraConfig,
      oauthProvider: input.accountOauthProvider,
    });
    if (concurrencyLimit <= 0) {
      return {
        status: 'acquired',
        lease: createNoopLease(channelId),
      };
    }

    const state = getOrCreateChannelRuntimeState(channelId);
    pruneCancelledWaiters(state);
    if (state.activeLeaseIds.size < concurrencyLimit) {
      return {
        status: 'acquired',
        lease: this.createTrackedLease(channelId, state),
      };
    }

    const waitMs = getChannelQueueWaitMs();
    if (waitMs <= 0) {
      return {
        status: 'timeout',
        waitMs: 0,
      };
    }

    return await new Promise<AcquireProxyChannelLeaseResult>((resolve) => {
      const waiter: ChannelWaiter = {
        cancelled: false,
        resolve,
        timer: null,
      };
      waiter.timer = setTimeout(() => {
        waiter.cancelled = true;
        waiter.timer = null;
        pruneCancelledWaiters(state);
        maybeDeleteChannelRuntimeState(channelId);
        resolve({
          status: 'timeout',
          waitMs,
        });
      }, waitMs);
      shouldUnrefTimer(waiter.timer);
      state.queue.push(waiter);
    });
  }

  private createTrackedLease(channelId: number, state: ChannelRuntimeState): ProxyChannelLease {
    const leaseId = nextLeaseId++;
    state.activeLeaseIds.add(leaseId);

    let released = false;
    let expiryTimer: ReturnType<typeof setTimeout> | null = null;
    let keepaliveTimer: ReturnType<typeof setInterval> | null = null;

    const release = () => {
      if (released) return;
      released = true;
      if (expiryTimer) clearTimeout(expiryTimer);
      if (keepaliveTimer) clearInterval(keepaliveTimer);
      state.activeLeaseIds.delete(leaseId);
      this.drainQueue(channelId);
      maybeDeleteChannelRuntimeState(channelId);
    };

    const touch = () => {
      if (released) return;
      if (expiryTimer) clearTimeout(expiryTimer);
      expiryTimer = setTimeout(() => {
        release();
      }, getChannelLeaseTtlMs());
      shouldUnrefTimer(expiryTimer);
    };

    touch();

    const keepaliveMs = getChannelLeaseKeepaliveMs();
    if (keepaliveMs > 0) {
      keepaliveTimer = setInterval(() => {
        touch();
      }, keepaliveMs);
      shouldUnrefTimer(keepaliveTimer);
    }

    return {
      channelId,
      isActive: () => !released,
      release,
      touch,
    };
  }

  private drainQueue(channelId: number): void {
    const state = channelRuntimeStates.get(channelId);
    if (!state) return;
    pruneCancelledWaiters(state);
    const concurrencyLimit = Math.max(0, Math.trunc(config.proxySessionChannelConcurrencyLimit || 0));
    while (state.activeLeaseIds.size < concurrencyLimit && state.queue.length > 0) {
      const waiter = state.queue.shift();
      if (!waiter || waiter.cancelled) continue;
      if (waiter.timer) clearTimeout(waiter.timer);
      waiter.timer = null;
      waiter.resolve({
        status: 'acquired',
        lease: this.createTrackedLease(channelId, state),
      });
    }
  }
}

export function resetProxyChannelCoordinatorState(): void {
  stickySessionBindings.clear();
  channelRuntimeStates.clear();
  nextLeaseId = 1;
}

export function isProxyChannelSessionScoped(input?: SessionScopedChannelInput): boolean {
  return isSessionScopedChannel(input);
}

export const proxyChannelCoordinator = new ProxyChannelCoordinator();
