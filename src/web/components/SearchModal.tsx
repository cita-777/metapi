import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import { formatDateLocal, formatDateTimeMinuteLocal } from '../pages/helpers/checkinLogTime.js';
import { buildAccountFocusPath, buildSiteFocusPath, buildTokenFocusPath } from '../pages/helpers/navigationFocus.js';
import { useI18n } from '../i18n.js';
import { useAsyncResource } from './useAsyncResource.js';
import { Dialog } from './ui/Dialog.js';

interface SiteResult {
  id: number;
  name: string;
  url: string;
}

interface AccountResult {
  id: number;
  username: string | null;
  status?: string | null;
  balance?: number | null;
  segment?: 'session' | 'apikey';
  site?: { name: string } | null;
}

interface AccountTokenResult {
  id: number;
  accountId: number;
  name: string;
  tokenGroup?: string | null;
  account?: {
    username?: string | null;
    segment?: 'session' | 'apikey';
  } | null;
  site?: { name: string } | null;
}

interface CheckinLogResult {
  id: number;
  accountId: number;
  message?: string | null;
  createdAt?: string | null;
  account?: { username?: string | null } | null;
}

interface ProxyLogResult {
  id: number;
  modelRequested?: string | null;
  status?: string | null;
  latencyMs?: number | null;
  createdAt?: string | null;
}

interface ModelSearchResult {
  name: string;
  accountCount: number;
  tokenCount: number;
  siteCount: number;
}

interface SearchResult {
  accounts: AccountResult[];
  accountTokens: AccountTokenResult[];
  sites: SiteResult[];
  checkinLogs: CheckinLogResult[];
  proxyLogs: ProxyLogResult[];
  models: ModelSearchResult[];
}

type TimerHandle = ReturnType<typeof globalThis.setTimeout>;

function normalizeSearchResult(value: unknown): SearchResult {
  const payload = (
    typeof value === 'object' && value !== null
      ? value
      : {}
  ) as Record<string, unknown>;

  const readArray = <T,>(key: keyof SearchResult): T[] => {
    const candidate = payload[key];
    return Array.isArray(candidate) ? candidate as T[] : [];
  };

  return {
    models: readArray<ModelSearchResult>('models'),
    accounts: readArray<AccountResult>('accounts'),
    accountTokens: readArray<AccountTokenResult>('accountTokens'),
    sites: readArray<SiteResult>('sites'),
    checkinLogs: readArray<CheckinLogResult>('checkinLogs'),
    proxyLogs: readArray<ProxyLogResult>('proxyLogs'),
  };
}

export default function SearchModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [debouncing, setDebouncing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const debounceTimerRef = useRef<TimerHandle | null>(null);
  const focusTimerRef = useRef<TimerHandle | null>(null);
  const queryRef = useRef('');
  const requestQueryRef = useRef('');
  const openRef = useRef(open);
  const mountedRef = useRef(true);
  openRef.current = open;

  // The shared lifecycle hook owns the AbortController; this ref only carries
  // the immutable query selected by the debounce callback into that loader.
  const searchLoader = useCallback(
    (signal: AbortSignal) => api.search(requestQueryRef.current, { signal })
      .then(normalizeSearchResult),
    [],
  );
  const searchResource = useAsyncResource<SearchResult>(searchLoader, {
    autoLoad: false,
  });
  const activeQuery = open && submittedQuery !== '' && submittedQuery === query.trim();
  const loading = activeQuery && searchResource.loading;
  const error = activeQuery ? searchResource.error : null;
  const results = activeQuery && !loading && !error ? searchResource.data : null;

  const clearDebounceTimer = useCallback(() => {
    if (debounceTimerRef.current === null) return;
    globalThis.clearTimeout(debounceTimerRef.current);
    debounceTimerRef.current = null;
  }, []);

  const clearFocusTimer = useCallback(() => {
    if (focusTimerRef.current === null) return;
    globalThis.clearTimeout(focusTimerRef.current);
    focusTimerRef.current = null;
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearDebounceTimer();
      clearFocusTimer();
    };
  }, [clearDebounceTimer, clearFocusTimer]);

  const handleInput = useCallback((val: string) => {
    queryRef.current = val;
    setQuery(val);
    setSubmittedQuery('');
    clearDebounceTimer();
    searchResource.cancel();

    if (!val.trim() || !openRef.current) {
      setDebouncing(false);
      return;
    }
    setDebouncing(true);
    debounceTimerRef.current = globalThis.setTimeout(() => {
      debounceTimerRef.current = null;
      const normalizedQuery = val.trim();
      if (
        !mountedRef.current
        || !openRef.current
        || queryRef.current.trim() !== normalizedQuery
      ) return;
      // Preserve the original input for the API; the server owns trimming and
      // normalization while the UI uses the trimmed value for stale matching.
      requestQueryRef.current = val;
      setSubmittedQuery(normalizedQuery);
      setDebouncing(false);
      void searchResource.reload();
    }, 300);
  }, [clearDebounceTimer, searchResource.cancel, searchResource.reload]);

  const handleClose = useCallback(() => {
    queryRef.current = '';
    requestQueryRef.current = '';
    clearDebounceTimer();
    clearFocusTimer();
    searchResource.cancel();
    setQuery('');
    setSubmittedQuery('');
    setDebouncing(false);
    onClose();
  }, [clearDebounceTimer, clearFocusTimer, onClose, searchResource.cancel]);

  useEffect(() => {
    clearFocusTimer();
    clearDebounceTimer();
    if (!open) {
      searchResource.cancel();
      queryRef.current = '';
      requestQueryRef.current = '';
      setQuery('');
      setSubmittedQuery('');
      setDebouncing(false);
      return undefined;
    }

    searchResource.cancel();
    queryRef.current = '';
    requestQueryRef.current = '';
    setQuery('');
    setSubmittedQuery('');
    setDebouncing(false);
    focusTimerRef.current = globalThis.setTimeout(() => {
      focusTimerRef.current = null;
      if (mountedRef.current && openRef.current) inputRef.current?.focus();
    }, 100);

    return clearFocusTimer;
  }, [clearDebounceTimer, clearFocusTimer, open, searchResource.cancel]);

  const goTo = (path: string) => {
    handleClose();
    navigate(path);
  };

  const hasResults = results && (
    results.models.length
    || results.accounts.length
    || results.accountTokens.length
    || results.sites.length
    || results.checkinLogs.length
    || results.proxyLogs.length
  );
  const hasQuery = query.trim().length > 0;

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      title={null}
      ariaLabel={t('搜索')}
      closeOnBackdrop
      closeOnEscape
      showCloseButton={false}
      animationDuration={180}
      contentStyle={{ maxWidth: 560, padding: 0 }}
      bodyStyle={{ padding: 0 }}
    >
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 16px', borderBottom: '1px solid var(--color-border-light)' }}>
          <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="var(--color-text-muted)">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => handleInput(e.target.value)}
            placeholder={t('搜索站点、账号、模型、日志...')}
            style={{ flex: 1, border: 'none', outline: 'none', fontSize: 14, background: 'transparent', color: 'var(--color-text-primary)' }}
          />
          {(loading || debouncing) && <span className="spinner spinner-sm" />}
          <kbd style={{ fontSize: 11, padding: '2px 6px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 4, color: 'var(--color-text-muted)' }}>ESC</kbd>
        </div>

        <div style={{ maxHeight: 400, overflow: 'auto', padding: '8px 0' }}>
          {hasQuery && !loading && !debouncing && error && (
            <div
              role="alert"
              className="alert alert-error"
              style={{ margin: '8px 16px', textAlign: 'center' }}
            >
              <div className="alert-title">{t('请求失败')}</div>
              <div>{error.message || t('请求失败')}</div>
            </div>
          )}

          {hasQuery && !loading && !debouncing && !error && !hasResults && (
            <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: 13 }}>
              {t('没有找到匹配结果')}
            </div>
          )}

          {results?.models.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('模型广场')}</div>
              {results.models.map((m) => (
                <button key={m.name} className="search-result-item" onClick={() => goTo(`/models?q=${encodeURIComponent(m.name)}`)}>
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L4 12l5.75-5M14.25 7L20 12l-5.75 5M14 4l-4 16" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{m.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {m.accountCount} {t('个账号')} · {m.tokenCount} {t('个令牌')} · {m.siteCount} {t('个站点')}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}

          {results?.sites.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('站点')}</div>
              {results.sites.map((s) => (
                <button key={s.id} className="search-result-item" onClick={() => goTo(buildSiteFocusPath(s.id))}>
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{s.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{s.url}</div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}

          {results?.accounts.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('账号')}</div>
              {results.accounts.map((a) => (
                <button
                  key={a.id}
                  className="search-result-item"
                  onClick={() => goTo(buildAccountFocusPath(a.id, {
                    openRebind: a.status === 'expired',
                    segment: a.segment,
                  }))}
                >
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>
                      {a.username?.trim() || (a.segment === 'apikey' ? t('API Key 连接') : `ID:${a.id}`)}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {a.site?.name || t('未关联站点')}
                      {a.segment === 'apikey' ? ` · ${t('API Key 连接')}` : ''}
                      {' · '}
                      {t('余额')} ${(a.balance || 0).toFixed(2)}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}

          {results?.accountTokens.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('账号令牌')}</div>
              {results.accountTokens.map((token) => (
                <button
                  key={token.id}
                  className="search-result-item"
                  onClick={() => goTo(buildTokenFocusPath(token.id))}
                >
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{token.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {(token.account?.username?.trim() || (token.account?.segment === 'apikey' ? t('API Key 连接') : t('未命名')))}
                      {' · '}
                      {token.site?.name || t('未关联站点')}
                      {token.tokenGroup ? ` · ${token.tokenGroup}` : ''}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}

          {results?.checkinLogs.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('签到记录')}</div>
              {results.checkinLogs.map((l) => (
                <button key={l.id} className="search-result-item" onClick={() => goTo('/checkin')}>
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{l.account?.username || `ID:${l.accountId}`}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {l.message || '-'} · {formatDateLocal(l.createdAt)}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}

          {results?.proxyLogs.length ? (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text-muted)', padding: '8px 16px 4px', textTransform: 'uppercase' }}>{t('使用日志')}</div>
              {results.proxyLogs.map((l) => (
                <button key={l.id} className="search-result-item" onClick={() => goTo('/logs')}>
                  <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{l.modelRequested || '-'}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      {l.status || '-'} · {l.latencyMs || 0}ms · {formatDateTimeMinuteLocal(l.createdAt)}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : null}
        </div>

        <div style={{ padding: '8px 16px', borderTop: '1px solid var(--color-border-light)', fontSize: 11, color: 'var(--color-text-muted)', display: 'flex', gap: 12 }}>
          <span><kbd style={{ padding: '1px 4px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 3 }}>↑↓</kbd> {t('导航')}</span>
          <span><kbd style={{ padding: '1px 4px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 3 }}>Enter</kbd> {t('打开')}</span>
          <span><kbd style={{ padding: '1px 4px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 3 }}>Esc</kbd> {t('关闭')}</span>
        </div>
      </div>
    </Dialog>
  );
}
