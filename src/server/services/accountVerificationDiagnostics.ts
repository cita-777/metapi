import type { RequestInit as UndiciRequestInit } from 'undici';

/**
 * Failure categories surfaced by the account verification route.
 *
 * Keep this contract deliberately small: the route maps these categories to
 * its existing response payloads, while this service owns the probing details.
 */
export type AccountVerificationFailureReason =
  | 'needs-user-id'
  | 'invalid-user-id'
  | 'shield-blocked'
  | null;

export interface AccountVerificationDiagnosticResponse {
  text(): Promise<string>;
  headers: {
    get(name: string): string | null;
  };
  status?: number;
}

export type AccountVerificationFetch = (
  url: string,
  init: UndiciRequestInit,
) => Promise<AccountVerificationDiagnosticResponse>;

export type AccountVerificationRequestInitFactory = (
  headers: Record<string, string>,
  signal: AbortSignal,
) => UndiciRequestInit;

export interface AccountVerificationDiagnosticOptions {
  /** A single, already selected panel/API base URL. */
  baseUrl: string;
  accessToken: string;
  platformUserId?: number;
  skipRawShieldDetection?: boolean;
  timeoutMs?: number;
  requestInit?: AccountVerificationRequestInitFactory;
  /** Injectable for deterministic service tests; production uses undici. */
  fetchImpl?: AccountVerificationFetch;
}

export interface AccountVerificationDiagnosticResult {
  reason: AccountVerificationFailureReason;
  /** True when at least one request returned a response object. */
  sawResponse: boolean;
  /** True when one or more candidate requests failed before a response. */
  sawNetworkError: boolean;
  /** Last observed HTTP status, if a response supplied one. */
  status: number | null;
  /** Base URL selected by the caller for the probe. */
  endpoint: string | null;
  /** All candidate requests failed without receiving a response. */
  timedOut: boolean;
  /** Whether retrying the diagnostic probe may produce a different result. */
  retryable: boolean;
}

const DEFAULT_DIAGNOSTIC_TIMEOUT_MS = 2_500;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function resolveUserIdFailureReason(
  message: string,
  hasProvidedUserId: boolean,
): Exclude<AccountVerificationFailureReason, 'shield-blocked' | null> | null {
  const lowered = String(message || '')
    .trim()
    .toLowerCase();
  if (!lowered) return null;

  if (
    lowered.includes('mismatch') ||
    lowered.includes('not match') ||
    lowered.includes('invalid user id') ||
    lowered.includes('wrong user id')
  ) {
    return 'invalid-user-id';
  }

  if (
    lowered.includes('missing new-api-user') ||
    lowered.includes('new-api-user required') ||
    lowered.includes('requires user id') ||
    lowered.includes('missing user id')
  ) {
    return 'needs-user-id';
  }

  if (lowered.includes('new-api-user') || lowered.includes('user id')) {
    return hasProvidedUserId ? 'invalid-user-id' : 'needs-user-id';
  }

  return null;
}

/**
 * Parse one `/api/user/self` response for a user-id or anti-bot diagnosis.
 * This is pure so all verification entry points share exactly the same rules.
 */
export function parseAccountVerificationFailureReason(
  bodyText: string,
  contentType: string,
  options: {
    hasProvidedUserId: boolean;
    skipRawShieldDetection?: boolean;
  },
): AccountVerificationFailureReason {
  const text = bodyText || '';
  const normalizedContentType = (contentType || '').toLowerCase();
  const skipRawShieldDetection = options.skipRawShieldDetection === true;

  if (
    !skipRawShieldDetection &&
    normalizedContentType.includes('text/html') &&
    /var\s+arg1\s*=|acw_sc__v2|cdn_sec_tc|<script/i.test(text)
  ) {
    return 'shield-blocked';
  }

  try {
    const parsed: unknown = JSON.parse(text);
    const message = isRecord(parsed) && typeof parsed.message === 'string'
      ? parsed.message
      : '';
    const userIdReason = resolveUserIdFailureReason(
      message,
      options.hasProvidedUserId,
    );
    if (userIdReason) return userIdReason;
    if (
      !skipRawShieldDetection &&
      /shield|challenge|captcha|acw_sc__v2|arg1/i.test(message)
    ) {
      return 'shield-blocked';
    }
  } catch {
    // Non-JSON responses are only meaningful when they match the raw shield
    // signature above; otherwise the caller should retain the generic reason.
  }

  return null;
}

/**
 * Build the Bearer/Cookie candidates used by both preflight and post-failure
 * diagnostics. Ordering is part of the compatibility contract.
 */
export function buildAccountVerificationHeaderVariants(
  accessToken: string,
  platformUserId?: number,
): Array<Record<string, string>> {
  const hasProvidedUserId = platformUserId !== undefined;
  const candidates = new Set<string>();
  const raw = accessToken.startsWith('Bearer ')
    ? accessToken.slice(7).trim()
    : accessToken;
  if (raw) {
    if (raw.includes('=')) candidates.add(raw);
    candidates.add(`session=${raw}`);
    candidates.add(`token=${raw}`);
  }

  const diagnosticUserId = hasProvidedUserId
    ? String(platformUserId)
    : '0';
  const headerVariants: Array<Record<string, string>> = [
    {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'New-Api-User': diagnosticUserId,
    },
  ];

  for (const cookie of candidates) {
    headerVariants.push({
      Cookie: cookie,
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(hasProvidedUserId
        ? { 'New-Api-User': diagnosticUserId }
        : {}),
    });
  }

  return headerVariants;
}

function createEmptyResult(endpoint: string | null = null): AccountVerificationDiagnosticResult {
  return {
    reason: null,
    sawResponse: false,
    sawNetworkError: false,
    status: null,
    endpoint,
    timedOut: false,
    retryable: false,
  };
}

/**
 * Probe `/api/user/self` at one selected base URL and classify a verification failure.
 *
 * The service intentionally reports network/timeout state instead of throwing
 * it away. The existing route still maps only `reason`, preserving its public
 * response behavior while allowing callers/tests to distinguish a no-response
 * timeout from an ordinary unknown payload. Endpoint-pool selection remains in
 * the route adapter (`requireSiteApiBaseUrl`) so this owner stays protocol- and
 * database-independent.
 */
export async function diagnoseAccountVerificationFailure(
  options: AccountVerificationDiagnosticOptions,
): Promise<AccountVerificationDiagnosticResult> {
  const result = createEmptyResult();
  const hasProvidedUserId = options.platformUserId !== undefined;
  const timeoutMs = Number.isFinite(options.timeoutMs) && (options.timeoutMs || 0) > 0
    ? Math.max(1, Math.trunc(options.timeoutMs as number))
    : DEFAULT_DIAGNOSTIC_TIMEOUT_MS;

  const endpoint = options.baseUrl;
  result.endpoint = endpoint;
  const requestBaseUrl = endpoint.replace(/\/+$/, '');
  let fetchImpl = options.fetchImpl;
  if (!fetchImpl) {
    try {
      const undici = await import('undici');
      fetchImpl = async (url, init) => undici.fetch(url, init);
    } catch {
      result.sawNetworkError = true;
      result.timedOut = true;
      result.retryable = true;
      return result;
    }
  }

  const headerVariants = buildAccountVerificationHeaderVariants(
    options.accessToken,
    options.platformUserId,
  );
  for (const headers of headerVariants) {
    try {
      const response = await fetchImpl(
        `${requestBaseUrl}/api/user/self`,
        options.requestInit
          ? options.requestInit(headers, AbortSignal.timeout(timeoutMs))
          : { headers, signal: AbortSignal.timeout(timeoutMs) },
      );
      result.sawResponse = true;
      result.status = typeof response.status === 'number' && Number.isFinite(response.status)
        ? response.status
        : null;
      const bodyText = await response.text();
      const contentType = response.headers.get('content-type') || '';
      const reason = parseAccountVerificationFailureReason(
        bodyText,
        contentType,
        {
          hasProvidedUserId,
          skipRawShieldDetection: options.skipRawShieldDetection,
        },
      );
      if (reason) {
        result.reason = reason;
        return result;
      }
    } catch {
      result.sawNetworkError = true;
    }
  }

  result.timedOut = result.sawNetworkError && !result.sawResponse;
  result.retryable = result.timedOut;
  return result;
}
