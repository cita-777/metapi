import React, { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import CenteredModal from '../components/CenteredModal.js';
import DeleteConfirmModal from '../components/DeleteConfirmModal.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js';
import ResponsiveBatchActionBar from '../components/ResponsiveBatchActionBar.js';
import { useToast } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
import { useIsMobile } from '../components/useIsMobile.js';
import { tr } from '../i18n.js';
import DownstreamKeyEditorModal, {
  TagInput,
  type DownstreamCredentialOption,
  type DownstreamExcludedCredentialRef,
  type DownstreamKeyEditorForm,
  type DownstreamSiteOption,
} from './downstream-keys/DownstreamKeyEditorModal.js';
import DownstreamKeyDrawer from './downstream-keys/DownstreamKeyDrawer.js';
import {
  formatCompactTokens,
  formatIso,
  formatMoney,
  RangeToggle,
  StatusBadge,
  TagChips,
  type Range,
  type SummaryItem,
} from './downstream-keys/shared.js';

type Status = 'all' | 'enabled' | 'disabled';

type DownstreamApiKeyItem = {
  id: number;
  name: string;
  key: string;
  keyMasked: string;
  description: string | null;
  groupName: string | null;
  tags: string[];
  enabled: boolean;
  expiresAt: string | null;
  maxCost: number | null;
  usedCost: number;
  maxRequests: number | null;
  usedRequests: number;
  supportedModels: string[];
  allowedRouteIds: number[];
  siteWeightMultipliers: Record<number, number>;
  excludedSiteIds: number[];
  excludedCredentialRefs: DownstreamExcludedCredentialRef[];
  lastUsedAt: string | null;
};

type ManagedItem = SummaryItem & {
  key?: string;
};

type RouteSelectorItem = {
  id: number;
  modelPattern: string;
  displayName?: string | null;
  enabled: boolean;
};

type DeleteConfirmState =
  | null
  | { mode: 'single'; item: ManagedItem }
  | { mode: 'batch'; ids: number[] };

type TagMatchMode = 'any' | 'all';

type BatchMetadataForm = {
  groupOperation: 'keep' | 'set' | 'clear';
  groupName: string;
  tagOperation: 'keep' | 'append';
  tags: string[];
};

type DefaultRouteSelections = Pick<DownstreamKeyEditorForm, 'selectedModels' | 'selectedGroupRouteIds'>;
function toDateTimeLocal(isoString: string | null | undefined): string {
  if (!isoString) return '';
  const ts = Date.parse(isoString);
  if (!Number.isFinite(ts)) return '';
  const date = new Date(ts);
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  const hh = String(date.getHours()).padStart(2, '0');
  const mi = String(date.getMinutes()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
}

function routeTitle(route: RouteSelectorItem): string {
  const displayName = (route.displayName || '').trim();
  return displayName || route.modelPattern;
}

function isGroupRouteOption(route: RouteSelectorItem): boolean {
  return !isExactModelPattern(route.modelPattern);
}

function uniqStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => String(value || '').trim()).filter(Boolean))];
}

function normalizeTags(values: string[]): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = String(raw || '').trim();
    if (!value) continue;
    const normalized = value.slice(0, 32);
    const dedupeKey = normalized.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    result.push(normalized);
    if (result.length >= 20) break;
  }
  return result;
}

function uniqIds(values: number[]): number[] {
  return [...new Set(values.map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0).map((value) => Math.trunc(value)))];
}

function buildExcludedCredentialRefKey(ref: DownstreamExcludedCredentialRef): string {
  return ref.kind === 'account_token'
    ? `${ref.kind}:${ref.siteId}:${ref.accountId}:${ref.tokenId}`
    : `${ref.kind}:${ref.siteId}:${ref.accountId}`;
}

function normalizeExcludedSiteIds(values: number[]): number[] {
  return uniqIds(values).sort((left, right) => left - right);
}

function normalizeExcludedCredentialRefs(values: DownstreamExcludedCredentialRef[]): DownstreamExcludedCredentialRef[] {
  const deduped = new Map<string, DownstreamExcludedCredentialRef>();
  for (const value of values) {
    if (!value || !Number.isFinite(value.siteId) || !Number.isFinite(value.accountId)) continue;
    if (value.kind === 'account_token') {
      if (!Number.isFinite(value.tokenId)) continue;
      const normalized: DownstreamExcludedCredentialRef = {
        kind: 'account_token',
        siteId: Math.trunc(value.siteId),
        accountId: Math.trunc(value.accountId),
        tokenId: Math.trunc(value.tokenId),
      };
      deduped.set(buildExcludedCredentialRefKey(normalized), normalized);
      continue;
    }
    const normalized: DownstreamExcludedCredentialRef = {
      kind: 'default_api_key',
      siteId: Math.trunc(value.siteId),
      accountId: Math.trunc(value.accountId),
    };
    deduped.set(buildExcludedCredentialRefKey(normalized), normalized);
  }
  return Array.from(deduped.values()).sort((left, right) => buildExcludedCredentialRefKey(left).localeCompare(buildExcludedCredentialRefKey(right)));
}

function buildDefaultRouteSelections(routeOptions: RouteSelectorItem[]): DefaultRouteSelections {
  return {
    selectedModels: uniqStrings(
      routeOptions
        .filter((item) => isExactModelPattern(item.modelPattern))
        .map((item) => item.modelPattern),
    ).sort((a, b) => a.localeCompare(b)),
    selectedGroupRouteIds: uniqIds(
      routeOptions
        .filter(isGroupRouteOption)
        .map((item) => item.id),
    ),
  };
}

function parseTagText(value: string): string[] {
  return normalizeTags(value.split(/[\r\n,，]+/g));
}

function parseInlineRegex(value: string): RegExp | null {
  const text = value.trim();
  if (!text.startsWith('/') || text.length < 2) return null;
  const lastSlash = text.lastIndexOf('/');
  if (lastSlash <= 0) return null;
  const pattern = text.slice(1, lastSlash);
  const flags = text.slice(lastSlash + 1);
  if (!pattern) return null;
  if (!/^[dgimsuvy]*$/i.test(flags)) return null;
  try {
    return new RegExp(pattern, flags || 'i');
  } catch {
    return null;
  }
}

function buildSearchMatcher(search: string): ((haystack: string) => boolean) | null {
  const text = search.trim();
  if (!text) return null;
  const regex = parseInlineRegex(text);
  if (regex) {
    return (haystack: string) => regex.test(haystack);
  }
  const normalized = text.toLowerCase();
  return (haystack: string) => haystack.toLowerCase().includes(normalized);
}

function splitSearchInput(value: string): { textSearch: string; inlineTags: string[] } {
  const raw = value.trim();
  if (!raw) return { textSearch: '', inlineTags: [] };
  if (parseInlineRegex(raw)) return { textSearch: raw, inlineTags: [] };

  const parts = raw.split(/[\r\n,，]+/g).map((item) => item.trim()).filter(Boolean);
  if (parts.length <= 1) return { textSearch: raw, inlineTags: [] };

  return {
    textSearch: '',
    inlineTags: normalizeTags(parts),
  };
}

function tagChipStyle(kind: 'normal' | 'accent' = 'normal'): React.CSSProperties {
  return {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 11,
    border: '1px solid var(--color-border-light)',
    color: kind === 'accent' ? 'var(--color-primary)' : 'var(--color-text-secondary)',
    background: kind === 'accent'
      ? 'color-mix(in srgb, var(--color-primary) 10%, transparent)'
      : 'var(--color-bg-card)',
  };
}

async function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

function DownstreamKeyCopyIconButton({ fullKey }: { fullKey: string | undefined }) {
  const toast = useToast();
  const [pressed, setPressed] = useState(false);

  const disabled = !fullKey?.trim();
  const release = () => setPressed(false);

  return (
    <button
      type="button"
      title="复制完整密钥"
      aria-label="复制完整密钥"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 2,
        lineHeight: 0,
        flexShrink: 0,
        border: 'none',
        background: 'transparent',
        color: disabled
          ? 'var(--color-text-muted)'
          : pressed
            ? 'var(--color-text-primary)'
            : 'var(--color-text-muted)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.4 : 1,
        borderRadius: 'var(--radius-sm)',
      }}
      disabled={disabled}
      onMouseDown={() => {
        if (!disabled) setPressed(true);
      }}
      onMouseUp={release}
      onMouseLeave={release}
      onTouchStart={() => {
        if (!disabled) setPressed(true);
      }}
      onTouchEnd={release}
      onTouchCancel={release}
      onClick={async (e) => {
        e.stopPropagation();
        const full = fullKey?.trim();
        if (!full) {
          toast.info('完整密钥暂不可用，请刷新页面后重试');
          return;
        }
        try {
          await copyToClipboard(full);
          toast.success('已复制到剪贴板');
        } catch {
          toast.error('复制失败');
        }
      }}
    >
      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
      </svg>
    </button>
  );
}

function buildEditorForm(
  item?: ManagedItem | DownstreamApiKeyItem | null,
  routeOptions: RouteSelectorItem[] = [],
  selectAllByDefault = false,
): DownstreamKeyEditorForm {
  const defaultSelections = selectAllByDefault
    ? buildDefaultRouteSelections(routeOptions)
    : { selectedModels: [], selectedGroupRouteIds: [] };
  const selectedModels = Array.isArray(item?.supportedModels)
    ? item.supportedModels
    : defaultSelections.selectedModels;
  const selectedGroupRouteIds = Array.isArray(item?.allowedRouteIds)
    ? item.allowedRouteIds
    : defaultSelections.selectedGroupRouteIds;

  return {
    name: item?.name || '',
    key: item?.key || '',
    description: item?.description || '',
    groupName: item?.groupName || '',
    tags: normalizeTags(Array.isArray(item?.tags) ? item!.tags : []),
    maxCost: item?.maxCost === null || item?.maxCost === undefined ? '' : String(item.maxCost),
    maxRequests: item?.maxRequests === null || item?.maxRequests === undefined ? '' : String(item.maxRequests),
    expiresAt: toDateTimeLocal(item?.expiresAt),
    enabled: item?.enabled ?? true,
    selectedModels: uniqStrings(selectedModels),
    selectedGroupRouteIds: uniqIds(selectedGroupRouteIds),
    siteWeightMultipliersText: JSON.stringify(item?.siteWeightMultipliers || {}, null, 2),
    excludedSiteIds: normalizeExcludedSiteIds(Array.isArray(item?.excludedSiteIds) ? item.excludedSiteIds : []),
    excludedCredentialRefs: normalizeExcludedCredentialRefs(Array.isArray(item?.excludedCredentialRefs) ? item.excludedCredentialRefs : []),
  };
}

function summarizeModelLimit(models: string[]): string {
  if (!Array.isArray(models) || models.length === 0) return '未授权模型';
  if (models.length === 1) return models[0];
  return `${models[0]} +${models.length - 1}`;
}

function summarizeRouteLimit(routeIds: number[], routeMap: Map<number, RouteSelectorItem>): string {
  if (!Array.isArray(routeIds) || routeIds.length === 0) return '未授权群组';
  const names = routeIds
    .map((id) => routeMap.get(id))
    .filter(Boolean)
    .map((item) => routeTitle(item!));
  if (names.length === 0) return `${routeIds.length} 个群组`;
  if (names.length === 1) return names[0];
  return `${names[0]} +${names.length - 1}`;
}

function summarizeSiteWeightMultipliers(weights: Record<number, number> | undefined): string {
  const entries = Object.entries(weights || {});
  if (entries.length === 0) return '默认倍率';
  if (entries.length === 1) return `${entries[0][0]} => ${entries[0][1]}`;
  return `${entries[0][0]} => ${entries[0][1]} +${entries.length - 1}`;
}

function summarizeTags(tags: string[]): string {
  if (!Array.isArray(tags) || tags.length === 0) return '无标签';
  if (tags.length === 1) return tags[0];
  return `${tags[0]} +${tags.length - 1}`;
}

function SummaryMetric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div style={{ minWidth: 112, display: 'grid', gap: 4 }}>
      <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{label}</span>
      <strong style={{ fontSize: 14, color: 'var(--color-text-primary)', fontWeight: 700 }}>{value}</strong>
    </div>
  );
}

function InlineToggle({
  value,
  onChange,
}: {
  value: TagMatchMode;
  onChange: (value: TagMatchMode) => void;
}) {
  const options: Array<{ value: TagMatchMode; label: string }> = [
    { value: 'any', label: '匹配任一标签' },
    { value: 'all', label: '匹配全部标签' },
  ];

  const base: React.CSSProperties = {
    padding: '6px 12px',
    fontSize: 12,
    fontWeight: 600,
    border: '1px solid var(--color-border)',
    background: 'var(--color-bg-card)',
    color: 'var(--color-text-muted)',
    cursor: 'pointer',
  };

  const active: React.CSSProperties = {
    background: 'var(--color-primary)',
    color: '#fff',
    borderColor: 'var(--color-primary)',
  };

  return (
    <div style={{ display: 'inline-flex', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
      {options.map((option, index) => (
        <button
          key={option.value}
          type="button"
          onClick={() => onChange(option.value)}
          style={{
            ...base,
            ...(value === option.value ? active : {}),
            ...(index === 0
              ? { borderRight: 'none' }
              : { borderTopRightRadius: 'var(--radius-sm)', borderBottomRightRadius: 'var(--radius-sm)' }),
            ...(index === 0
              ? { borderTopLeftRadius: 'var(--radius-sm)', borderBottomLeftRadius: 'var(--radius-sm)' }
              : {}),
          }}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export default function DownstreamKeys() {
  const toast = useToast();
  const [range, setRange] = useState<Range>('24h');
  const [status, setStatus] = useState<Status>('all');
  const [searchInput, setSearchInput] = useState('');
  const deferredSearch = useDeferredValue(searchInput.trim());
  const [groupFilter, setGroupFilter] = useState('__all__');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [tagMatchMode, setTagMatchMode] = useState<TagMatchMode>('any');
  const [summaryItems, setSummaryItems] = useState<SummaryItem[]>([]);
  const [rawItems, setRawItems] = useState<DownstreamApiKeyItem[]>([]);
  const [routeOptions, setRouteOptions] = useState<RouteSelectorItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [batchActionLoading, setBatchActionLoading] = useState(false);
  const [rowLoading, setRowLoading] = useState<Record<string, boolean>>({});
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editorForm, setEditorForm] = useState<DownstreamKeyEditorForm>(() => buildEditorForm());
  const [createDefaultsPending, setCreateDefaultsPending] = useState(false);
  const [exclusionSourceLoading, setExclusionSourceLoading] = useState(false);
  const [exclusionSourceLoaded, setExclusionSourceLoaded] = useState(false);
  const [exclusionSiteOptions, setExclusionSiteOptions] = useState<DownstreamSiteOption[]>([]);
  const [exclusionCredentialOptions, setExclusionCredentialOptions] = useState<DownstreamCredentialOption[]>([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [showFilters, setShowFilters] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<DeleteConfirmState>(null);
  const [batchMetadataOpen, setBatchMetadataOpen] = useState(false);
  const [batchMetadataForm, setBatchMetadataForm] = useState<BatchMetadataForm>({
    groupOperation: 'keep',
    groupName: '',
    tagOperation: 'keep',
    tags: [],
  });
  const isMobile = useIsMobile();

  const load = async () => {
    setLoading(true);
    try {
      const [summaryRes, rawRes, routesRes] = await Promise.all([
        api.getDownstreamApiKeysSummary({ range }),
        api.getDownstreamApiKeys(),
        api.getRoutesLite(),
      ]);
      setSummaryItems(Array.isArray(summaryRes?.items) ? summaryRes.items : []);
      setRawItems(Array.isArray(rawRes?.items) ? rawRes.items : []);
      setRouteOptions((Array.isArray(routesRes) ? routesRes : []).map((row: any) => ({
        id: Number(row.id),
        modelPattern: String(row.modelPattern || ''),
        displayName: row.displayName,
        enabled: !!row.enabled,
      })));
    } catch (err: any) {
      toast.error(err?.message || '加载下游密钥列表失败');
    } finally {
      setLoading(false);
    }
  };

  const loadExclusionSources = async () => {
    if (exclusionSourceLoading || exclusionSourceLoaded) return;
    setExclusionSourceLoading(true);
    try {
      const [accountsRes, tokensRes] = await Promise.all([
        api.getAccounts(),
        api.getAccountTokens(),
      ]);

      const accountRows = Array.isArray(accountsRes) ? accountsRes : [];
      const tokenRows = Array.isArray(tokensRes) ? tokensRes : [];

      const siteMap = new Map<number, { siteId: number; siteName: string; accountIds: Set<number> }>();
      for (const account of accountRows) {
        const siteId = Number(account?.site?.id);
        const accountId = Number(account?.id);
        if (!Number.isFinite(siteId) || siteId <= 0 || !Number.isFinite(accountId) || accountId <= 0) continue;
        const siteName = String(account?.site?.name || `站点 ${siteId}`).trim() || `站点 ${siteId}`;
        if (!siteMap.has(siteId)) {
          siteMap.set(siteId, { siteId, siteName, accountIds: new Set<number>() });
        }
        siteMap.get(siteId)!.accountIds.add(accountId);
      }

      const siteOptions = Array.from(siteMap.values())
        .map((item) => ({
          siteId: item.siteId,
          siteName: item.siteName,
          accountCount: item.accountIds.size,
        }))
        .sort((left, right) => left.siteName.localeCompare(right.siteName));

      const credentialOptions: DownstreamCredentialOption[] = [];
      for (const account of accountRows) {
        const siteId = Number(account?.site?.id);
        const accountId = Number(account?.id);
        const apiToken = String(account?.apiToken || '').trim();
        if (!Number.isFinite(siteId) || siteId <= 0 || !Number.isFinite(accountId) || accountId <= 0 || !apiToken) continue;
        credentialOptions.push({
          key: `default_api_key:${siteId}:${accountId}`,
          ref: { kind: 'default_api_key', siteId: Math.trunc(siteId), accountId: Math.trunc(accountId) },
          siteName: String(account?.site?.name || `站点 ${siteId}`).trim() || `站点 ${siteId}`,
          accountName: String(account?.username || `账号 ${accountId}`).trim() || `账号 ${accountId}`,
          label: '默认 API Key',
          detail: `使用账号默认 API Key (${apiToken.slice(0, 6)}...)`,
        });
      }

      for (const token of tokenRows) {
        const siteId = Number(token?.site?.id);
        const accountId = Number(token?.account?.id ?? token?.accountId);
        const tokenId = Number(token?.id);
        if (!Number.isFinite(siteId) || siteId <= 0 || !Number.isFinite(accountId) || accountId <= 0 || !Number.isFinite(tokenId) || tokenId <= 0) continue;
        credentialOptions.push({
          key: `account_token:${siteId}:${accountId}:${tokenId}`,
          ref: { kind: 'account_token', siteId: Math.trunc(siteId), accountId: Math.trunc(accountId), tokenId: Math.trunc(tokenId) },
          siteName: String(token?.site?.name || `站点 ${siteId}`).trim() || `站点 ${siteId}`,
          accountName: String(token?.account?.username || `账号 ${accountId}`).trim() || `账号 ${accountId}`,
          label: String(token?.name || `token-${tokenId}`).trim() || `token-${tokenId}`,
          detail: String(token?.tokenGroup || 'default').trim() || 'default',
        });
      }

      setExclusionSiteOptions(siteOptions);
      setExclusionCredentialOptions(
        credentialOptions.sort((left, right) => (
          `${left.siteName}:${left.accountName}:${left.label}:${left.detail}`.localeCompare(
            `${right.siteName}:${right.accountName}:${right.label}:${right.detail}`,
          )
        )),
      );
      setExclusionSourceLoaded(true);
    } catch (err: any) {
      toast.error(err?.message || '加载可排除站点与令牌失败');
    } finally {
      setExclusionSourceLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [range]);

  useEffect(() => {
    if (!editorOpen) return;
    void loadExclusionSources();
  }, [editorOpen]);

  const rawItemMap = useMemo(() => new Map(rawItems.map((item) => [item.id, item])), [rawItems]);
  const routeMap = useMemo(() => new Map(routeOptions.map((item) => [item.id, item])), [routeOptions]);

  const managedItems = useMemo<ManagedItem[]>(() => (
    summaryItems.map((item) => {
      const raw = rawItemMap.get(item.id);
      return {
        ...item,
        key: raw?.key,
        keyMasked: raw?.keyMasked || item.keyMasked,
        description: raw?.description ?? item.description,
        groupName: raw?.groupName ?? item.groupName,
        tags: raw?.tags ?? item.tags,
        enabled: raw?.enabled ?? item.enabled,
        expiresAt: raw?.expiresAt ?? item.expiresAt,
        maxCost: raw?.maxCost ?? item.maxCost,
        usedCost: raw?.usedCost ?? item.usedCost,
        maxRequests: raw?.maxRequests ?? item.maxRequests,
        usedRequests: raw?.usedRequests ?? item.usedRequests,
        supportedModels: raw?.supportedModels ?? item.supportedModels,
        allowedRouteIds: raw?.allowedRouteIds ?? item.allowedRouteIds,
        siteWeightMultipliers: raw?.siteWeightMultipliers ?? item.siteWeightMultipliers,
        excludedSiteIds: raw?.excludedSiteIds ?? item.excludedSiteIds,
        excludedCredentialRefs: raw?.excludedCredentialRefs ?? item.excludedCredentialRefs,
        lastUsedAt: raw?.lastUsedAt ?? item.lastUsedAt,
      };
    })
  ), [rawItemMap, summaryItems]);

  const groupSuggestions = useMemo(
    () => uniqStrings(managedItems.map((item) => item.groupName || '')).sort((a, b) => a.localeCompare(b)),
    [managedItems],
  );

  const tagSuggestions = useMemo(
    () => uniqStrings(managedItems.flatMap((item) => item.tags || [])).sort((a, b) => a.localeCompare(b)),
    [managedItems],
  );

  const groupFilterOptions = useMemo(
    () => [
      { value: '__all__', label: '全部主分组' },
      { value: '__ungrouped__', label: '未分组' },
      ...groupSuggestions.map((group) => ({ value: group, label: group })),
    ],
    [groupSuggestions],
  );

  const parsedSearch = useMemo(() => splitSearchInput(deferredSearch), [deferredSearch]);
  const activeTagFilters = useMemo(
    () => normalizeTags([...selectedTags, ...parsedSearch.inlineTags]),
    [parsedSearch.inlineTags, selectedTags],
  );
  const searchMatcher = useMemo(() => buildSearchMatcher(parsedSearch.textSearch), [parsedSearch.textSearch]);

  const visibleItems = useMemo(() => managedItems.filter((item) => {
    if (status === 'enabled' && !item.enabled) return false;
    if (status === 'disabled' && item.enabled) return false;
    if (groupFilter === '__ungrouped__' && item.groupName) return false;
    if (groupFilter !== '__all__' && groupFilter !== '__ungrouped__' && item.groupName !== groupFilter) return false;
    if (activeTagFilters.length > 0) {
      const itemTags = new Set((item.tags || []).map((tag) => tag.toLowerCase()));
      const matches = tagMatchMode === 'all'
        ? activeTagFilters.every((tag) => itemTags.has(tag.toLowerCase()))
        : activeTagFilters.some((tag) => itemTags.has(tag.toLowerCase()));
      if (!matches) return false;
    }
    if (!searchMatcher) return true;
    const haystack = [
      item.name,
      item.description || '',
      item.keyMasked,
      item.groupName || '',
      ...(item.tags || []),
      ...(item.supportedModels || []),
      ...((item.allowedRouteIds || []).map((id) => routeTitle(routeMap.get(id) || { id, modelPattern: String(id), enabled: true } as RouteSelectorItem))),
    ].join(' ');
    return searchMatcher(haystack);
  }).sort((a, b) => {
    if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
    const lastA = a.lastUsedAt ? Date.parse(a.lastUsedAt) : 0;
    const lastB = b.lastUsedAt ? Date.parse(b.lastUsedAt) : 0;
    if (lastA !== lastB) return lastB - lastA;
    return a.name.localeCompare(b.name);
  }), [activeTagFilters, groupFilter, managedItems, routeMap, searchMatcher, status, tagMatchMode]);

  const visibleIds = useMemo(() => visibleItems.map((item) => item.id), [visibleItems]);
  const selectedVisibleCount = useMemo(() => selectedIds.filter((id) => visibleIds.includes(id)).length, [selectedIds, visibleIds]);
  const allVisibleSelected = visibleIds.length > 0 && selectedVisibleCount === visibleIds.length;

  useEffect(() => {
    setSelectedIds((current) => current.filter((id) => managedItems.some((item) => item.id == id)));
    setSelectedId((current) => (current && managedItems.some((item) => item.id === current) ? current : null));
  }, [managedItems]);

  const selectedItem = useMemo(
    () => managedItems.find((item) => item.id === selectedId) || null,
    [managedItems, selectedId],
  );

  const editingItem = useMemo(
    () => managedItems.find((item) => item.id === editingId) || null,
    [editingId, managedItems],
  );

  const statusOptions = useMemo(() => [
    { value: 'all', label: '全部状态' },
    { value: 'enabled', label: '仅启用' },
    { value: 'disabled', label: '仅禁用' },
  ], []);

  const totals = useMemo(() => visibleItems.reduce((acc, item) => {
    acc.tokens += Number(item.rangeUsage?.totalTokens || 0);
    acc.requests += Number(item.rangeUsage?.totalRequests || 0);
    acc.cost += Number(item.rangeUsage?.totalCost || 0);
    if (item.enabled) acc.enabled += 1;
    return acc;
  }, { tokens: 0, requests: 0, cost: 0, enabled: 0 }), [visibleItems]);

  useEffect(() => {
    if (!editorOpen || editingId !== null || !createDefaultsPending) {
      return;
    }

    const defaultSelections = buildDefaultRouteSelections(routeOptions);
    if (defaultSelections.selectedModels.length === 0 && defaultSelections.selectedGroupRouteIds.length === 0) {
      return;
    }

    setEditorForm((prev) => {
      if (prev.selectedModels.length > 0 || prev.selectedGroupRouteIds.length > 0) {
        return prev;
      }
      return {
        ...prev,
        selectedModels: defaultSelections.selectedModels,
        selectedGroupRouteIds: defaultSelections.selectedGroupRouteIds,
      };
    });
    setCreateDefaultsPending(false);
  }, [createDefaultsPending, editorOpen, editingId, routeOptions]);

  const openCreate = () => {
    setEditingId(null);
    setEditorForm(buildEditorForm(null, routeOptions, true));
    setCreateDefaultsPending(true);
    setEditorOpen(true);
  };

  const resetBatchMetadataForm = () => {
    setBatchMetadataForm({
      groupOperation: 'keep',
      groupName: '',
      tagOperation: 'keep',
      tags: [],
    });
  };

  const openEdit = (item: ManagedItem) => {
    setEditingId(item.id);
    setCreateDefaultsPending(false);
    setEditorForm(buildEditorForm(rawItemMap.get(item.id) || item));
    setEditorOpen(true);
  };

  const closeEditor = () => {
    setEditorOpen(false);
    setEditingId(null);
    setCreateDefaultsPending(false);
    setEditorForm(buildEditorForm());
  };

  const withRowLoading = async (key: string, action: () => Promise<void>) => {
    setRowLoading((prev) => ({ ...prev, [key]: true }));
    try {
      await action();
    } finally {
      setRowLoading((prev) => ({ ...prev, [key]: false }));
    }
  };

  const saveKey = async () => {
    const name = editorForm.name.trim();
    const key = editorForm.key.trim();
    if (!name) {
      toast.info('请填写密钥名称');
      return;
    }
    if (!key) {
      toast.info('请填写下游密钥');
      return;
    }
    if (!key.startsWith('sk-')) {
      toast.info('下游密钥必须以 sk- 开头');
      return;
    }

    let siteWeightMultipliers: Record<number, number> = {};
    const rawWeights = editorForm.siteWeightMultipliersText.trim();
    if (rawWeights && rawWeights !== '{}') {
      try {
        const parsed = JSON.parse(rawWeights);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          toast.info('站点倍率必须是 JSON 对象');
          return;
        }
        siteWeightMultipliers = Object.fromEntries(
          Object.entries(parsed)
            .map(([siteId, value]) => [Math.trunc(Number(siteId)), Number(value)])
            .filter(([siteId, value]) => Number.isFinite(siteId) && siteId > 0 && Number.isFinite(value) && value > 0),
        ) as Record<number, number>;
      } catch {
        toast.info('站点倍率 JSON 解析失败');
        return;
      }
    }

    setSaving(true);
    try {
      const payload = {
        name,
        key,
        description: editorForm.description.trim(),
        groupName: editorForm.groupName.trim() || null,
        tags: normalizeTags(editorForm.tags),
        enabled: editorForm.enabled,
        expiresAt: editorForm.expiresAt ? new Date(editorForm.expiresAt).toISOString() : null,
        maxCost: editorForm.maxCost.trim() ? Number(editorForm.maxCost.trim()) : null,
        maxRequests: editorForm.maxRequests.trim() ? Number(editorForm.maxRequests.trim()) : null,
        supportedModels: uniqStrings(editorForm.selectedModels),
        allowedRouteIds: uniqIds(editorForm.selectedGroupRouteIds).filter((id) => routeMap.has(id) && isGroupRouteOption(routeMap.get(id)!)),
        siteWeightMultipliers,
        excludedSiteIds: normalizeExcludedSiteIds(editorForm.excludedSiteIds),
        excludedCredentialRefs: normalizeExcludedCredentialRefs(editorForm.excludedCredentialRefs),
      };
      if (editingId) {
        await api.updateDownstreamApiKey(editingId, payload);
        toast.success('下游密钥已更新');
      } else {
        await api.createDownstreamApiKey(payload);
        toast.success('下游密钥已创建');
      }
      closeEditor();
      await load();
    } catch (err: any) {
      toast.error(err?.message || '保存下游密钥失败');
    } finally {
      setSaving(false);
    }
  };

  const toggleSelection = (id: number, checked: boolean) => {
    setSelectedIds((current) => checked ? uniqIds([...current, id]) : current.filter((item) => item !== id));
  };

  const toggleSelectAllVisible = (checked: boolean) => {
    if (!checked) {
      setSelectedIds((current) => current.filter((id) => !visibleIds.includes(id)));
      return;
    }
    setSelectedIds((current) => uniqIds([...current, ...visibleIds]));
  };

  const batchRun = async (label: string, ids: number[]) => {
    if (ids.length === 0) return;
    setBatchActionLoading(true);
    try {
      const action = label === '批量启用'
        ? 'enable'
        : label === '批量禁用'
          ? 'disable'
          : label === '批量删除'
            ? 'delete'
            : label === '批量清零用量'
              ? 'resetUsage'
              : 'updateMetadata';
      const payload = action === 'updateMetadata'
        ? {
          ids,
          action,
          groupOperation: batchMetadataForm.groupOperation,
          groupName: batchMetadataForm.groupOperation === 'set' ? batchMetadataForm.groupName.trim() : undefined,
          tagOperation: batchMetadataForm.tagOperation,
          tags: batchMetadataForm.tagOperation === 'append' ? normalizeTags(batchMetadataForm.tags) : undefined,
        }
        : { ids, action };
      const result = await api.batchDownstreamApiKeys(payload as any);
      const successIds = Array.isArray(result?.successIds) ? result.successIds.map((id: unknown) => Number(id)) : [];
      const failedItems = Array.isArray(result?.failedItems) ? result.failedItems : [];
      const failedIds = failedItems.map((item: any) => Number(item.id)).filter((id: number) => Number.isFinite(id) && id > 0);
      const successCount = successIds.length;
      if (failedIds.length > 0) {
        toast.info(`${label}完成：成功 ${successCount}，失败 ${failedIds.length}`);
      } else {
        toast.success(`${label}完成：成功 ${successCount}`);
      }
      setSelectedIds(failedIds);
      if (action === 'updateMetadata' && failedIds.length === 0) {
        setBatchMetadataOpen(false);
        resetBatchMetadataForm();
      }
      await load();
    } catch (err: any) {
      toast.error(err?.message || `${label}失败`);
    } finally {
      setBatchActionLoading(false);
    }
  };

  const toggleEnabled = async (item: ManagedItem) => {
    await withRowLoading(`toggle-${item.id}`, async () => {
      await api.updateDownstreamApiKey(item.id, { enabled: !item.enabled });
      await load();
      toast.success(item.enabled ? '已禁用该密钥' : '已启用该密钥');
    });
  };

  const resetUsage = async (item: ManagedItem) => {
    await withRowLoading(`reset-${item.id}`, async () => {
      await api.resetDownstreamApiKeyUsage(item.id);
      await load();
      toast.success('已清零该密钥用量');
    });
  };

  const confirmDelete = async () => {
    if (!deleteConfirm) return;
    const target = deleteConfirm;
    setDeleteConfirm(null);

    if (target.mode === 'single') {
      await withRowLoading(`delete-${target.item.id}`, async () => {
        await api.deleteDownstreamApiKey(target.item.id);
        toast.success('下游密钥已删除');
        await load();
      });
      return;
    }

    await batchRun('批量删除', target.ids);
  };

  const addTagFilter = (raw: string) => {
    const text = raw.trim();
    if (!text || parseInlineRegex(text)) return;
    const next = normalizeTags([...selectedTags, ...parseTagText(text)]);
    setSelectedTags(next);
  };

  const openBatchMetadata = () => {
    resetBatchMetadataForm();
    setBatchMetadataOpen(true);
  };

  const runBatchMetadata = async () => {
    if (batchMetadataForm.groupOperation === 'set' && !batchMetadataForm.groupName.trim()) {
      toast.info('请填写批量主分组');
      return;
    }
    if (batchMetadataForm.tagOperation === 'append' && normalizeTags(batchMetadataForm.tags).length === 0) {
      toast.info('请至少填写一个批量标签');
      return;
    }
    await batchRun('批量归类', selectedIds);
  };

  const filterControls = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="toolbar" style={{ marginBottom: 0, alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: '1 1 420px', minWidth: 280, flexWrap: 'wrap' }}>
          <div className="toolbar-search" style={{ maxWidth: 'unset', flex: '1 1 320px' }}>
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="搜索名称、备注、模型、主分组或标签"
            />
          </div>
          <InlineToggle value={tagMatchMode} onChange={setTagMatchMode} />
        </div>
        <div style={{ minWidth: 170 }}>
          <ModernSelect value={status} onChange={(value) => setStatus((value as Status) || 'all')} options={statusOptions} />
        </div>
        <div style={{ minWidth: 170 }}>
          <ModernSelect value={groupFilter} onChange={(value) => setGroupFilter(String(value || '__all__'))} options={groupFilterOptions} />
        </div>
        <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => { setSearchInput(''); setStatus('all'); setGroupFilter('__all__'); setSelectedTags([]); setTagMatchMode('any'); }}>
          重置筛选
        </button>
      </div>

      {(activeTagFilters.length > 0 || tagSuggestions.length > 0) ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {activeTagFilters.map((tag) => {
            const fromPinnedTags = selectedTags.some((item) => item.toLowerCase() === tag.toLowerCase());
            return (
              <button
                key={tag}
                className="btn btn-ghost"
                style={{ ...tagChipStyle('accent'), cursor: 'pointer', opacity: fromPinnedTags ? 1 : 0.82 }}
                onClick={() => {
                  if (fromPinnedTags) {
                    setSelectedTags((current) => current.filter((item) => item.toLowerCase() !== tag.toLowerCase()));
                    return;
                  }
                  setSearchInput((current) => current
                    .split(/[\r\n,，]+/g)
                    .map((item) => item.trim())
                    .filter(Boolean)
                    .filter((item) => item.toLowerCase() !== tag.toLowerCase())
                    .join(', '));
                }}
              >
                {tag} ×
              </button>
            );
          })}
          {tagSuggestions.filter((tag) => !activeTagFilters.some((current) => current.toLowerCase() === tag.toLowerCase())).slice(0, 8).map((tag) => (
            <button key={tag} className="btn btn-ghost" style={tagChipStyle()} onClick={() => addTagFilter(tag)}>
              {tag}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );

  const empty = !loading && visibleItems.length === 0;

  return (
    <div className="animate-fade-in" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="page-header" style={{ marginBottom: 0 }}>
        <div>
          <h2 className="page-title">下游密钥</h2>
          <div className="page-subtitle">统一管理分发给下游项目的密钥、主分组、标签、额度、模型白名单、群组范围与历史用量。</div>
        </div>
        <div className="page-actions">
          <RangeToggle range={range} onChange={setRange} />
          <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => void load()} disabled={loading}>
            {loading ? <><span className="spinner spinner-sm" /> 刷新中...</> : '刷新'}
          </button>
          <button className="btn btn-primary" onClick={openCreate}>+ 新增下游密钥</button>
        </div>
      </div>

      <div className="card" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>范围概览</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
              基于当前筛选范围查看密钥规模、使用量和成本概况。
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="kpi-chip">当前范围</span>
            <span className="kpi-chip kpi-chip-success">
              {range === '24h' ? '最近 24 小时' : range === '7d' ? '最近 7 天' : '全部历史'}
            </span>
            <span className="kpi-chip kpi-chip-warning">
              Tokens {formatCompactTokens(totals.tokens)}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px 18px', alignItems: 'center' }}>
          <SummaryMetric label="可见密钥" value={String(visibleItems.length)} />
          <SummaryMetric label="启用中" value={String(totals.enabled)} />
          <SummaryMetric label="已选中" value={String(selectedIds.length)} />
          <SummaryMetric label="请求数" value={totals.requests.toLocaleString()} />
          <SummaryMetric label="累计成本" value={formatMoney(totals.cost)} />
          <SummaryMetric label="筛选状态" value={statusOptions.find((item) => item.value === status)?.label || '全部状态'} />
        </div>
      </div>

      {selectedIds.length > 0 ? (
        <ResponsiveBatchActionBar
          isMobile={isMobile}
          info={`已选 ${selectedIds.length} 个密钥`}
          infoStyle={{ color: 'var(--color-text-primary)' }}
        >
          <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={openBatchMetadata} disabled={batchActionLoading}>{isMobile ? '归类/标签' : '批量归类/标签'}</button>
          <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => void batchRun('批量启用', selectedIds)} disabled={batchActionLoading}>{isMobile ? '启用' : '批量启用'}</button>
          <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => void batchRun('批量禁用', selectedIds)} disabled={batchActionLoading}>{isMobile ? '禁用' : '批量禁用'}</button>
          <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => void batchRun('批量清零用量', selectedIds)} disabled={batchActionLoading}>{isMobile ? '清零' : '批量清零用量'}</button>
          <button className="btn btn-link btn-link-danger" onClick={() => setDeleteConfirm({ mode: 'batch', ids: [...selectedIds] })} disabled={batchActionLoading}>{isMobile ? '删除' : '批量删除'}</button>
        </ResponsiveBatchActionBar>
      ) : null}

      <div className="card" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>筛选与列表</div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>按名称、状态、主分组和标签快速定位下游密钥。</div>
            </div>
            {isMobile && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => setShowFilters(true)}>
                  筛选
                </button>
                <button
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                  onClick={() => toggleSelectAllVisible(!allVisibleSelected)}
                >
                  {allVisibleSelected ? '取消全选' : '全选可见'}
                </button>
              </div>
            )}
          </div>
          <ResponsiveFilterPanel
            isMobile={isMobile}
            mobileOpen={showFilters}
            onMobileClose={() => setShowFilters(false)}
            mobileTitle="筛选下游密钥"
            mobileContent={filterControls}
            desktopContent={filterControls}
          />
        </div>

        {loading ? (
          <div className="skeleton" style={{ width: '100%', height: 280, borderRadius: 'var(--radius-sm)' }} />
        ) : empty ? (
          <div className="empty-state" style={{ padding: 40 }}>
            <div className="empty-state-title">暂无下游密钥</div>
            <div className="empty-state-desc">可以先新增一条密钥，或调整筛选条件查看已有数据。</div>
          </div>
        ) : isMobile ? (
          <div className="mobile-card-list">
            {visibleItems.map((row) => {
              const loadingToggle = !!rowLoading[`toggle-${row.id}`];
              const loadingReset = !!rowLoading[`reset-${row.id}`];
              const loadingDelete = !!rowLoading[`delete-${row.id}`];
              const checked = selectedIds.includes(row.id);
              return (
                <MobileCard
                  key={row.id}
                  title={row.name}
                  headerActions={(
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <StatusBadge enabled={row.enabled} />
                      <input
                        type="checkbox"
                        aria-label={`选择 ${row.name}`}
                        checked={checked}
                        onChange={(e) => toggleSelection(row.id, e.target.checked)}
                      />
                    </div>
                  )}
                  footerActions={(
                    <>
                      <button className="btn btn-link" onClick={() => { setSelectedId(row.id); setDrawerOpen(true); }}>查看</button>
                      <button className="btn btn-link" onClick={() => openEdit(row)}>编辑</button>
                      <button className="btn btn-link" onClick={() => void toggleEnabled(row)} disabled={loadingToggle}>{loadingToggle ? '处理中...' : (row.enabled ? '禁用' : '启用')}</button>
                      <button className="btn btn-link" onClick={() => void resetUsage(row)} disabled={loadingReset}>{loadingReset ? '处理中...' : '清零用量'}</button>
                      <button className="btn btn-link btn-link-danger" onClick={() => setDeleteConfirm({ mode: 'single', item: row })} disabled={loadingDelete}>{loadingDelete ? '处理中...' : '删除'}</button>
                    </>
                  )}
                >
                  <MobileField
                    label="密钥"
                    value={(
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-text-muted)' }}>{row.keyMasked}</span>
                        <DownstreamKeyCopyIconButton fullKey={row.key} />
                      </span>
                    )}
                    stacked
                  />
                  {row.description ? <MobileField label="备注" value={row.description} stacked /> : null}
                  <MobileField label="主分组" value={row.groupName || '未分组'} />
                  <MobileField label="标签" value={summarizeTags(row.tags || [])} stacked />
                  <MobileField label="模型" value={summarizeModelLimit(row.supportedModels || [])} stacked />
                  <MobileField label="群组" value={summarizeRouteLimit(row.allowedRouteIds || [], routeMap)} stacked />
                  <MobileField label="倍率" value={summarizeSiteWeightMultipliers(row.siteWeightMultipliers || {})} stacked />
                  <MobileField label="额度" value={`${row.maxRequests == null ? '不限' : row.maxRequests.toLocaleString()} / ${row.maxCost == null ? '成本不限' : formatMoney(row.maxCost)}`} stacked />
                  <MobileField label="用量" value={`${(row.rangeUsage?.totalRequests || 0).toLocaleString()} 请求 · ${formatCompactTokens(row.rangeUsage?.totalTokens || 0)}`} stacked />
                  <MobileField label="最近使用" value={formatIso(row.lastUsedAt)} stacked />
                </MobileCard>
              );
            })}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th style={{ width: 42 }}>
                    <input type="checkbox" checked={allVisibleSelected} onChange={(e) => toggleSelectAllVisible(e.target.checked)} />
                  </th>
                  <th>密钥信息</th>
                  <th>授权范围</th>
                  <th style={{ textAlign: 'right' }}>额度</th>
                  <th style={{ textAlign: 'right' }}>用量</th>
                  <th>最近使用</th>
                  <th style={{ textAlign: 'right' }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {visibleItems.map((row) => {
                  const loadingToggle = !!rowLoading[`toggle-${row.id}`];
                  const loadingReset = !!rowLoading[`reset-${row.id}`];
                  const loadingDelete = !!rowLoading[`delete-${row.id}`];
                  const checked = selectedIds.includes(row.id);
                  return (
                    <tr key={row.id} className={`row-selectable ${checked ? 'row-selected' : ''}`.trim()} onClick={() => { setSelectedId(row.id); setDrawerOpen(true); }}>
                      <td onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={checked} onChange={(e) => toggleSelection(row.id, e.target.checked)} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                          <strong style={{ color: 'var(--color-text-primary)' }}>{row.name}</strong>
                          <StatusBadge enabled={row.enabled} />
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--color-text-muted)' }}>{row.keyMasked}</span>
                          <DownstreamKeyCopyIconButton fullKey={row.key} />
                        </div>
                        {row.description ? <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', maxWidth: 320 }}>{row.description}</div> : null}
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
                          <span className={`badge ${row.groupName ? 'badge-info' : 'badge-muted'}`} style={{ fontSize: 11 }}>
                            {row.groupName ? `主分组 · ${row.groupName}` : '未分组'}
                          </span>
                          <TagChips tags={row.tags || []} maxVisible={3} />
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>模型：<span style={{ color: 'var(--color-text-primary)' }}>{summarizeModelLimit(row.supportedModels || [])}</span></div>
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>群组：<span style={{ color: 'var(--color-text-primary)' }}>{summarizeRouteLimit(row.allowedRouteIds || [], routeMap)}</span></div>
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>标签：<span style={{ color: 'var(--color-text-primary)' }}>{summarizeTags(row.tags || [])}</span></div>
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>倍率：<span style={{ color: 'var(--color-text-primary)' }}>{summarizeSiteWeightMultipliers(row.siteWeightMultipliers || {})}</span></div>
                        </div>
                      </td>
                      <td style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                        <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{row.maxRequests == null ? '不限' : row.maxRequests.toLocaleString()}</div>
                        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>{row.maxCost == null ? '成本不限' : `成本 ${formatMoney(row.maxCost)}`}</div>
                        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>{row.expiresAt ? `到期 ${formatIso(row.expiresAt)}` : '永久有效'}</div>
                      </td>
                      <td style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                        <div style={{ color: 'var(--color-text-primary)', fontWeight: 700 }}>{formatCompactTokens(row.rangeUsage?.totalTokens || 0)}</div>
                        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>{(row.rangeUsage?.totalRequests || 0).toLocaleString()} 请求</div>
                        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>{row.rangeUsage?.successRate == null ? '--' : `成功率 ${row.rangeUsage.successRate}%`}</div>
                      </td>
                      <td style={{ color: 'var(--color-text-muted)' }}>{formatIso(row.lastUsedAt)}</td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="accounts-row-actions" style={{ justifyContent: 'flex-end' }}>
                          <button className="btn btn-link" onClick={() => { setSelectedId(row.id); setDrawerOpen(true); }}>查看</button>
                          <button className="btn btn-link" onClick={() => openEdit(row)}>编辑</button>
                          <button className="btn btn-link" onClick={() => void toggleEnabled(row)} disabled={loadingToggle}>{loadingToggle ? '处理中...' : (row.enabled ? '禁用' : '启用')}</button>
                          <button className="btn btn-link" onClick={() => void resetUsage(row)} disabled={loadingReset}>{loadingReset ? '处理中...' : '清零用量'}</button>
                          <button className="btn btn-link btn-link-danger" onClick={() => setDeleteConfirm({ mode: 'single', item: row })} disabled={loadingDelete}>{loadingDelete ? '处理中...' : '删除'}</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <DownstreamKeyEditorModal
        open={editorOpen}
        editingItem={editingItem}
        form={editorForm}
        onChange={(updater) => setEditorForm((prev) => updater(prev))}
        onClose={closeEditor}
        onSave={() => void saveKey()}
        saving={saving}
        routeOptions={routeOptions}
        groupSuggestions={groupSuggestions}
        tagSuggestions={tagSuggestions}
        exclusionSourceLoading={exclusionSourceLoading}
        siteOptions={exclusionSiteOptions}
        credentialOptions={exclusionCredentialOptions}
      />

      <CenteredModal
        open={batchMetadataOpen}
        onClose={() => { setBatchMetadataOpen(false); resetBatchMetadataForm(); }}
        title="批量归类 / 标签"
        maxWidth={720}
        bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
        footer={(
          <>
            <button className="btn btn-ghost" onClick={() => { setBatchMetadataOpen(false); resetBatchMetadataForm(); }} disabled={batchActionLoading}>取消</button>
            <button className="btn btn-primary" onClick={() => void runBatchMetadata()} disabled={batchActionLoading}>
              {batchActionLoading ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '应用到所选密钥'}
            </button>
          </>
        )}
      >
        <div className="info-tip" style={{ marginBottom: 0 }}>
          本次会对已选中的 {selectedIds.length} 个密钥批量设置主分组，并追加标签。不会改动模型白名单、群组范围、额度和倍率。
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>主分组操作</div>
            <ModernSelect
              value={batchMetadataForm.groupOperation}
              onChange={(value) => setBatchMetadataForm((prev) => ({ ...prev, groupOperation: String(value) as BatchMetadataForm['groupOperation'] }))}
              options={[
                { value: 'keep', label: '不改动主分组' },
                { value: 'set', label: '统一设为主分组' },
                { value: 'clear', label: '清空主分组' },
              ]}
            />
            <input
              value={batchMetadataForm.groupName}
              onChange={(e) => setBatchMetadataForm((prev) => ({ ...prev, groupName: e.target.value }))}
              disabled={batchMetadataForm.groupOperation !== 'set'}
              placeholder="例如：VIP / 内部项目"
              list="downstream-group-suggestions"
              style={{ width: '100%', padding: '10px 12px', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg)', color: 'var(--color-text-primary)' }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>标签操作</div>
            <ModernSelect
              value={batchMetadataForm.tagOperation}
              onChange={(value) => setBatchMetadataForm((prev) => ({ ...prev, tagOperation: String(value) as BatchMetadataForm['tagOperation'] }))}
              options={[
                { value: 'keep', label: '不改动标签' },
                { value: 'append', label: '追加标签' },
              ]}
            />
            <div style={{ opacity: batchMetadataForm.tagOperation === 'append' ? 1 : 0.6, pointerEvents: batchMetadataForm.tagOperation === 'append' ? 'auto' : 'none' }}>
              <TagInput
                tags={batchMetadataForm.tags}
                onChange={(tags) => setBatchMetadataForm((prev) => ({ ...prev, tags }))}
                suggestions={tagSuggestions}
                placeholder="批量追加标签"
              />
            </div>
          </div>
        </div>
      </CenteredModal>

      <DeleteConfirmModal
        open={Boolean(deleteConfirm)}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={() => void confirmDelete()}
        title="确认删除下游密钥"
        confirmText="确认删除"
        loading={batchActionLoading || (deleteConfirm?.mode === 'single' && !!rowLoading[`delete-${deleteConfirm.item.id}`])}
        description={deleteConfirm?.mode === 'single'
          ? <>确定要删除密钥 <strong>{deleteConfirm.item.name}</strong> 吗？</>
          : <>确定要删除选中的 <strong>{deleteConfirm?.ids.length || 0}</strong> 个密钥吗？</>}
      />

      <DownstreamKeyDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        item={selectedItem}
        initialRange={range}
      />
    </div>
  );
}
