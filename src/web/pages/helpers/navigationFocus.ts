import { isTruthyFlag } from './accountConnection.js';

const FOCUS_SITE_ID_KEY = 'focusSiteId';
const FOCUS_ANNOUNCEMENT_ID_KEY = 'focusAnnouncementId';
const FOCUS_ACCOUNT_ID_KEY = 'focusAccountId';
const FOCUS_TOKEN_ID_KEY = 'focusTokenId';
const OPEN_REBIND_KEY = 'openRebind';

function normalizePositiveId(input: unknown): number | null {
  const value = Number.parseInt(String(input ?? ''), 10);
  if (!Number.isFinite(value) || value <= 0) return null;
  return value;
}

export function buildSiteFocusPath(siteId: number): string {
  const normalizedId = normalizePositiveId(siteId);
  if (!normalizedId) return '/sites';
  return `/sites?${FOCUS_SITE_ID_KEY}=${normalizedId}`;
}

export function buildAnnouncementFocusPath(announcementId: number): string {
  const normalizedId = normalizePositiveId(announcementId);
  if (!normalizedId) return '/site-announcements';
  return `/site-announcements?${FOCUS_ANNOUNCEMENT_ID_KEY}=${normalizedId}`;
}

export function buildAccountFocusPath(
  accountId: number,
  options?: { openRebind?: boolean; segment?: 'session' | 'apikey' | 'tokens' },
): string {
  const normalizedId = normalizePositiveId(accountId);
  if (!normalizedId) return '/accounts';
  const params = new URLSearchParams();
  if (options?.segment && options.segment !== 'session') params.set('segment', options.segment);
  params.set(FOCUS_ACCOUNT_ID_KEY, String(normalizedId));
  if (options?.openRebind) params.set(OPEN_REBIND_KEY, '1');
  return `/accounts?${params.toString()}`;
}

export function buildTokenFocusPath(tokenId: number): string {
  const normalizedId = normalizePositiveId(tokenId);
  if (!normalizedId) return '/accounts?segment=tokens';
  const params = new URLSearchParams();
  params.set('segment', 'tokens');
  params.set(FOCUS_TOKEN_ID_KEY, String(normalizedId));
  return `/accounts?${params.toString()}`;
}

export function readFocusSiteId(search: string): number | null {
  const params = new URLSearchParams(search);
  return normalizePositiveId(params.get(FOCUS_SITE_ID_KEY));
}

export function readFocusAnnouncementId(search: string): number | null {
  const params = new URLSearchParams(search);
  return normalizePositiveId(params.get(FOCUS_ANNOUNCEMENT_ID_KEY));
}

export function readFocusAccountIntent(search: string): { accountId: number | null; openRebind: boolean } {
  const params = new URLSearchParams(search);
  return {
    accountId: normalizePositiveId(params.get(FOCUS_ACCOUNT_ID_KEY)),
    openRebind: isTruthyFlag(params.get(OPEN_REBIND_KEY)),
  };
}

export function readFocusTokenId(search: string): number | null {
  const params = new URLSearchParams(search);
  return normalizePositiveId(params.get(FOCUS_TOKEN_ID_KEY));
}

export function clearFocusParams(search: string): string {
  const params = new URLSearchParams(search);
  params.delete(FOCUS_SITE_ID_KEY);
  params.delete(FOCUS_ANNOUNCEMENT_ID_KEY);
  params.delete(FOCUS_ACCOUNT_ID_KEY);
  params.delete(FOCUS_TOKEN_ID_KEY);
  params.delete(OPEN_REBIND_KEY);
  const next = params.toString();
  return next ? `?${next}` : '';
}

export function buildEventNavigationPath(event: {
  relatedType?: string | null;
  relatedId?: number | null;
  type?: string | null;
}): string {
  const relatedType = (event.relatedType || '').toLowerCase();
  const relatedId = normalizePositiveId(event.relatedId);
  const eventType = (event.type || '').toLowerCase();

  if (relatedType === 'account' && relatedId) {
    return buildAccountFocusPath(relatedId, { openRebind: eventType === 'token' });
  }
  if (relatedType === 'site' && relatedId) {
    return buildSiteFocusPath(relatedId);
  }
  if (relatedType === 'site_announcement' && relatedId) {
    return buildAnnouncementFocusPath(relatedId);
  }
  if (relatedType === 'route') {
    return '/routes';
  }
  if (eventType === 'proxy') {
    return '/logs';
  }
  if (eventType === 'checkin') {
    return '/checkin';
  }
  if (eventType === 'site_notice') {
    return '/site-announcements';
  }

  return '/events';
}
