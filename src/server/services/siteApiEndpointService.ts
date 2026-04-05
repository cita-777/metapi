import { asc, eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { RETRYABLE_TIMEOUT_PATTERNS } from './proxyRetryPolicy.js';

const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);
const NON_RETRYABLE_STATUS_CODES = new Set([400, 401, 403, 404, 422]);
const NETWORK_FAILURE_PATTERNS = [
  /network error/i,
  /fetch failed/i,
  /socket hang up/i,
  /econnreset/i,
  /econnrefused/i,
  /enotfound/i,
  /ehostunreach/i,
  /ecanceled/i,
  ...RETRYABLE_TIMEOUT_PATTERNS,
];

export const SITE_API_ENDPOINT_COOLDOWN_MS = 5 * 60 * 1000;

type SiteRow = typeof schema.sites.$inferSelect;
type SiteApiEndpointRow = typeof schema.siteApiEndpoints.$inferSelect;

export interface SiteApiEndpointTarget {
  kind: 'site-fallback' | 'endpoint';
  siteId: number;
  endpointId: number | null;
  baseUrl: string;
  configuredEndpointCount: number;
  endpoint: SiteApiEndpointRow | null;
}

export interface SiteApiEndpointFailureInput {
  status?: number | null;
  message?: string | null;
  error?: unknown;
}

export interface SiteApiEndpointFailureDisposition {
  retryable: boolean;
  rotateToNextEndpoint: boolean;
  failureReason: string;
}

export interface RecordedSiteApiEndpointFailure extends SiteApiEndpointFailureDisposition {
  cooldownUntil: string | null;
}

export class SiteApiEndpointRequestError extends Error {
  readonly status: number | null;
  readonly rawErrText: string | null;
  readonly firstByteLatencyMs: number | null;

  constructor(message: string, options?: {
    status?: number | null;
    rawErrText?: string | null;
    firstByteLatencyMs?: number | null;
    cause?: unknown;
  }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'SiteApiEndpointRequestError';
    this.status = typeof options?.status === 'number' ? options.status : null;
    this.rawErrText = typeof options?.rawErrText === 'string' && options.rawErrText.trim()
      ? options.rawErrText
      : null;
    this.firstByteLatencyMs = typeof options?.firstByteLatencyMs === 'number' && Number.isFinite(options.firstByteLatencyMs)
      ? options.firstByteLatencyMs
      : null;
  }
}

export function normalizeSiteApiEndpointBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().replace(/\/+$/, '');
  } catch {
    return trimmed.replace(/\/+$/, '');
  }
}

function toIsoTimestamp(now?: string | Date): string {
  if (typeof now === 'string' && now.trim()) return now;
  if (now instanceof Date) return now.toISOString();
  return new Date().toISOString();
}

function compareNullableTimeAsc(left?: string | null, right?: string | null): number {
  if (!left && !right) return 0;
  if (!left) return -1;
  if (!right) return 1;
  return left.localeCompare(right);
}

function isEndpointCoolingDown(endpoint: SiteApiEndpointRow, nowIso: string): boolean {
  return !!endpoint.cooldownUntil && endpoint.cooldownUntil > nowIso;
}

function extractFailureMessage(input: SiteApiEndpointFailureInput): string {
  const direct = typeof input.message === 'string' ? input.message.trim() : '';
  if (direct) return direct;
  const errorMessage = input.error instanceof Error ? input.error.message.trim() : '';
  return errorMessage;
}

function formatFailureReason(status: number | null, message: string): string {
  if (status && message) {
    if (message.match(new RegExp(`^HTTP\\s+${status}\\b`, 'i'))) {
      return message;
    }
    return `HTTP ${status}: ${message}`;
  }
  if (status) return `HTTP ${status}`;
  return message || 'endpoint failure';
}

function parseStatusFromFailureMessage(message: string): number | null {
  const matched = message.match(/\bHTTP\s+(\d{3})\b/i);
  if (!matched) return null;
  const status = Number.parseInt(matched[1] || '', 10);
  return Number.isFinite(status) ? status : null;
}

export function classifySiteApiEndpointFailure(
  input: SiteApiEndpointFailureInput,
): SiteApiEndpointFailureDisposition {
  const message = extractFailureMessage(input);
  const status = typeof input.status === 'number'
    ? input.status
    : parseStatusFromFailureMessage(message);
  const failureReason = formatFailureReason(status, message);

  if (status !== null) {
    if (RETRYABLE_STATUS_CODES.has(status)) {
      return { retryable: true, rotateToNextEndpoint: true, failureReason };
    }
    if (NON_RETRYABLE_STATUS_CODES.has(status)) {
      return { retryable: false, rotateToNextEndpoint: false, failureReason };
    }
  }

  if (NETWORK_FAILURE_PATTERNS.some((pattern) => pattern.test(message))) {
    return { retryable: true, rotateToNextEndpoint: true, failureReason };
  }

  return { retryable: false, rotateToNextEndpoint: false, failureReason };
}

export async function selectSiteApiEndpointTarget(
  site: SiteRow,
  now?: string | Date,
): Promise<SiteApiEndpointTarget | null> {
  const nowIso = toIsoTimestamp(now);
  const endpoints = await db.select().from(schema.siteApiEndpoints)
    .where(eq(schema.siteApiEndpoints.siteId, site.id))
    .orderBy(asc(schema.siteApiEndpoints.sortOrder), asc(schema.siteApiEndpoints.id))
    .all();

  if (endpoints.length === 0) {
    return {
      kind: 'site-fallback',
      siteId: site.id,
      endpointId: null,
      baseUrl: normalizeSiteApiEndpointBaseUrl(site.url),
      configuredEndpointCount: 0,
      endpoint: null,
    };
  }

  const eligible = endpoints
    .filter((endpoint) => (endpoint.enabled ?? true) && !isEndpointCoolingDown(endpoint, nowIso))
    .sort((left, right) => {
      const sortOrder = (left.sortOrder ?? 0) - (right.sortOrder ?? 0);
      if (sortOrder !== 0) return sortOrder;
      const selectionOrder = compareNullableTimeAsc(left.lastSelectedAt, right.lastSelectedAt);
      if (selectionOrder !== 0) return selectionOrder;
      return (left.id ?? 0) - (right.id ?? 0);
    });

  const selected = eligible[0];
  if (!selected) return null;

  return {
    kind: 'endpoint',
    siteId: site.id,
    endpointId: selected.id,
    baseUrl: normalizeSiteApiEndpointBaseUrl(selected.url),
    configuredEndpointCount: endpoints.length,
    endpoint: selected,
  };
}

export async function resolveSiteApiBaseUrl(
  site: SiteRow,
  now?: string | Date,
): Promise<string | null> {
  const target = await selectSiteApiEndpointTarget(site, now);
  return target?.baseUrl || null;
}

export async function requireSiteApiBaseUrl(
  site: SiteRow,
  now?: string | Date,
): Promise<string> {
  const baseUrl = await resolveSiteApiBaseUrl(site, now);
  if (baseUrl) return baseUrl;
  throw new Error('当前站点的 API 请求地址均不可用');
}

export async function recordSiteApiEndpointFailure(
  endpointId: number,
  input: SiteApiEndpointFailureInput,
  now?: string | Date,
): Promise<RecordedSiteApiEndpointFailure> {
  const nowIso = toIsoTimestamp(now);
  const disposition = classifySiteApiEndpointFailure(input);
  const cooldownUntil = disposition.retryable
    ? new Date(Date.parse(nowIso) + SITE_API_ENDPOINT_COOLDOWN_MS).toISOString()
    : null;

  await db.update(schema.siteApiEndpoints).set({
    cooldownUntil,
    lastFailedAt: nowIso,
    lastFailureReason: disposition.failureReason,
    updatedAt: nowIso,
  }).where(eq(schema.siteApiEndpoints.id, endpointId)).run();

  return {
    ...disposition,
    cooldownUntil,
  };
}

export async function recordSiteApiEndpointSuccess(
  endpointId: number,
  now?: string | Date,
): Promise<void> {
  const nowIso = toIsoTimestamp(now);
  await db.update(schema.siteApiEndpoints).set({
    cooldownUntil: null,
    lastSelectedAt: nowIso,
    lastFailureReason: null,
    updatedAt: nowIso,
  }).where(eq(schema.siteApiEndpoints.id, endpointId)).run();
}

export async function runWithSiteApiEndpointPool<T>(
  site: SiteRow,
  operation: (target: SiteApiEndpointTarget) => Promise<T>,
): Promise<T> {
  const attemptedEndpointIds = new Set<number>();
  let lastError: unknown;

  while (true) {
    const target = await selectSiteApiEndpointTarget(site);
    if (!target) {
      if (lastError) throw lastError;
      throw new Error('当前站点的 API 请求地址均不可用');
    }
    if (target.endpointId && attemptedEndpointIds.has(target.endpointId)) {
      if (lastError) throw lastError;
      throw new Error('当前站点的 API 请求地址均不可用');
    }

    try {
      const result = await operation(target);
      if (target.endpointId) {
        try {
          await recordSiteApiEndpointSuccess(target.endpointId);
        } catch (error) {
          console.warn('[siteApiEndpointService] failed to record endpoint success', error);
        }
      }
      return result;
    } catch (error) {
      lastError = error;
      if (!target.endpointId) {
        throw error;
      }

      const recordedFailure = await recordSiteApiEndpointFailure(target.endpointId, {
        status: error instanceof SiteApiEndpointRequestError ? error.status : undefined,
        message: error instanceof Error ? error.message : String(error ?? ''),
        error,
      });
      if (!recordedFailure.rotateToNextEndpoint) {
        throw error;
      }

      attemptedEndpointIds.add(target.endpointId);
    }
  }
}
