import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import CenteredModal from '../components/CenteredModal.js';
import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js';
import ResponsiveFormGrid from '../components/ResponsiveFormGrid.js';
import ResponsiveBatchActionBar from '../components/ResponsiveBatchActionBar.js';
import { useToast } from '../components/Toast.js';
import { formatDateTimeLocal } from './helpers/checkinLogTime.js';
import {
  isTruthyFlag,
  parsePositiveInt,
  resolveAccountCredentialMode,
} from './helpers/accountConnection.js';
import ModernSelect from '../components/ModernSelect.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import { useIsMobile } from '../components/useIsMobile.js';
import DeleteConfirmModal from '../components/DeleteConfirmModal.js';
import { clearFocusParams, readFocusTokenId } from './helpers/navigationFocus.js';
import { shouldIgnoreRowSelectionClick } from './helpers/rowSelection.js';
import { tr } from '../i18n.js';

type SyncStatus = 'success' | 'skipped' | 'failed';
type TokensPanelProps = {
  embedded?: boolean;
  onEmbeddedActionsChange?: (actions: React.ReactNode | null) => void;
};

type AccountTokenSyncResult = {
  status?: string;
  success?: boolean;
  synced?: boolean;
  message?: string;
  reason?: string;
  created?: number;
  updated?: number;
  maskedPending?: number;
  pendingTokenIds?: number[];
  accountId?: number;
  accountName?: string;
  account?: {
    id?: number;
    username?: string;
  };
};

type SyncableAccount = {
  id: number;
  username?: string | null;
  accessToken?: string | null;
  status?: string | null;
  credentialMode?: string | null;
  capabilities?: {
    proxyOnly?: boolean;
  } | null;
  site?: {
    status?: string | null;
    name?: string | null;
  } | null;
};

const ACCOUNT_SELECT_SEARCH_PLACEHOLDER = '筛选账号（名称 / 站点）';

const isAccountSyncable = (account: any) =>
  resolveAccountCredentialMode(account) === 'session'
  && account?.status === 'active'
  && account?.site?.status !== 'disabled';

const resolveSyncStatus = (result: AccountTokenSyncResult | null | undefined): SyncStatus => {
  const raw = String(result?.status || '').toLowerCase();
  if (raw === 'failed' || raw === 'error') return 'failed';
  if (raw === 'skipped' || raw === 'skip') return 'skipped';
  if (raw === 'success' || raw === 'ok' || raw === 'succeeded') return 'success';
  if (result?.success === false) return 'failed';
  if (result?.synced === false) return 'skipped';
  return 'success';
};

const resolveSyncMessage = (result: AccountTokenSyncResult | null | undefined, fallback: string) => {
  const message = typeof result?.message === 'string' ? result.message.trim() : '';
  return message || fallback;
};

const isMaskedPendingToken = (token: any): boolean => token?.valueStatus === 'masked_pending';

const isMaskedPendingSyncResult = (result: AccountTokenSyncResult | null | undefined) =>
  String(result?.reason || '').trim().toLowerCase() === 'upstream_masked_tokens'
  && Number(result?.maskedPending || 0) > 0;

const resolveAccountLabel = (result: AccountTokenSyncResult | null | undefined) => {
  const name = typeof result?.accountName === 'string' ? result.accountName.trim() : '';
  if (name) return name;
  const username = typeof result?.account?.username === 'string' ? result.account.username.trim() : '';
  if (username) return username;
  const accountId = result?.accountId ?? result?.account?.id;
  if (accountId) return `#${accountId}`;
  return '未知账号';
};

async function copyText(text: string) {
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

export function TokensPanel({ embedded = false, onEmbeddedActionsChange }: TokensPanelProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const initialCreateForm = {
    accountId: 0,
    name: '',
    group: 'default',
    unlimitedQuota: true,
    remainQuota: '',
    expiredTime: '',
    allowIps: '',
  };

  const [tokens, setTokens] = useState<any[]>([]);
  const [accounts, setAccounts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [syncingAccountId, setSyncingAccountId] = useState(0);
  const [syncing, setSyncing] = useState(false);
  const [syncingAll, setSyncingAll] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editingToken, setEditingToken] = useState<any | null>(null);
  const [editingTokenValueLoading, setEditingTokenValueLoading] = useState(false);
  const [editingTokenPendingMessage, setEditingTokenPendingMessage] = useState('');
  const [createHintModelName, setCreateHintModelName] = useState('');
  const [highlightTokenId, setHighlightTokenId] = useState<number | null>(null);
  const [pendingAutoOpenTokenId, setPendingAutoOpenTokenId] = useState<number | null>(null);
  const [rowLoading, setRowLoading] = useState<Record<string, boolean>>({});
  const [selectedTokenIds, setSelectedTokenIds] = useState<number[]>([]);
  const [expandedTokenIds, setExpandedTokenIds] = useState<number[]>([]);
  const [showMobileTools, setShowMobileTools] = useState(false);
  const [batchActionLoading, setBatchActionLoading] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<null | {
    mode: 'single' | 'batch';
    tokenId?: number;
    tokenName?: string;
    count?: number;
  }>(null);
  const [form, setForm] = useState(initialCreateForm);
  const [editForm, setEditForm] = useState({
    name: '',
    token: '',
    group: 'default',
    enabled: true,
    isDefault: false,
  });
  const [groupOptions, setGroupOptions] = useState<string[]>(['default']);
  const [groupLoading, setGroupLoading] = useState(false);
  const [editGroupOptions, setEditGroupOptions] = useState<string[]>(['default']);
  const [editGroupLoading, setEditGroupLoading] = useState(false);
  const rowRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const editingTokenIdRef = useRef<number | null>(null);
  const toast = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [tokenRows, accountRows] = await Promise.all([api.getAccountTokens(), api.getAccounts()]);
      const nextTokens = tokenRows || [];
      setTokens(nextTokens);
      setSelectedTokenIds((current) => current.filter((id) => nextTokens.some((token: any) => token.id === id)));
      const latestAccounts: SyncableAccount[] = Array.isArray(accountRows) ? accountRows : [];
      setAccounts(latestAccounts);

      const syncableAccounts = latestAccounts.filter(isAccountSyncable);
      const hasCurrentSelected = syncableAccounts.some((account: SyncableAccount) => account.id === syncingAccountId);
      if (!hasCurrentSelected) {
        setSyncingAccountId(syncableAccounts[0]?.id || 0);
      }
      return {
        tokens: nextTokens,
        accounts: latestAccounts,
      };
    } catch (e: any) {
      toast.error(e.message || '加载令牌失败');
      return {
        tokens: [] as any[],
        accounts: [] as any[],
      };
    } finally {
      setLoading(false);
    }
  }, [syncingAccountId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    return () => {
      if (highlightTimerRef.current) {
        clearTimeout(highlightTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!showAdd || !form.accountId) {
      setGroupLoading(false);
      setGroupOptions(['default']);
      return;
    }

    let cancelled = false;
    setGroupLoading(true);
    api.getAccountTokenGroups(form.accountId)
      .then((res: any) => {
        if (cancelled) return;
        const groups: string[] = Array.isArray(res?.groups)
          ? res.groups.map((item: any) => String(item || '').trim()).filter(Boolean)
          : [];
        const normalized = Array.from(new Set(groups));
        const nextOptions = normalized.length > 0 ? normalized : ['default'];
        setGroupOptions(nextOptions);
        setForm((prev) => {
          if (nextOptions.includes(prev.group)) return prev;
          return { ...prev, group: nextOptions[0] };
        });
      })
      .catch((error: any) => {
        if (cancelled) return;
        setGroupOptions(['default']);
        setForm((prev) => ({ ...prev, group: 'default' }));
        toast.error(error?.message || '拉取分组失败，已回退 default');
      })
      .finally(() => {
        if (cancelled) return;
        setGroupLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [showAdd, form.accountId]);

  useEffect(() => {
    if (!editingToken?.id || !editingToken?.accountId) {
      setEditGroupLoading(false);
      setEditGroupOptions(['default']);
      return;
    }

    const currentGroup = (editingToken?.tokenGroup || '').trim() || 'default';
    let cancelled = false;
    setEditGroupLoading(true);
    api.getAccountTokenGroups(editingToken.accountId)
      .then((res: any) => {
        if (cancelled) return;
        const groups = Array.isArray(res?.groups)
          ? res.groups.map((item: any) => String(item || '').trim()).filter(Boolean)
          : [];
        const normalized = Array.from(new Set(groups));
        setEditGroupOptions((current) => {
          const next = normalized.length > 0 ? normalized : ['default'];
          if (next.includes(currentGroup)) return next;
          return [...next, currentGroup];
        });
      })
      .catch((error: any) => {
        if (cancelled) return;
        setEditGroupOptions((current) => (current.includes(currentGroup) ? current : [...current, currentGroup]));
        toast.error(error?.message || '拉取分组失败，已保留当前分组');
      })
      .finally(() => {
        if (cancelled) return;
        setEditGroupLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [editingToken?.id, editingToken?.accountId]);

  const accountClusteredTokens = useMemo(() => {
    const accountLabel = (token: any) => String(token?.account?.username || `account-${token?.accountId || 0}`).toLowerCase();
    const siteLabel = (token: any) => String(token?.site?.name || '').toLowerCase();
    const tokenName = (token: any) => String(token?.name || '').toLowerCase();

    return [...tokens].sort((left, right) => {
      const accountCmp = accountLabel(left).localeCompare(accountLabel(right));
      if (accountCmp !== 0) return accountCmp;
      const siteCmp = siteLabel(left).localeCompare(siteLabel(right));
      if (siteCmp !== 0) return siteCmp;
      const nameCmp = tokenName(left).localeCompare(tokenName(right));
      if (nameCmp !== 0) return nameCmp;
      return Number(left?.id || 0) - Number(right?.id || 0);
    });
  }, [tokens]);
  const allVisibleTokensSelected = accountClusteredTokens.length > 0
    && accountClusteredTokens.every((token) => selectedTokenIds.includes(token.id));

  const activeAccounts = useMemo(() => accounts.filter(isAccountSyncable), [accounts]);
  const activeAccountSelectOptions = useMemo(() => (
    activeAccounts.map((account) => {
      const accountName = account.username || `account-${account.id}`;
      const siteName = account.site?.name || '-';
      return {
        value: String(account.id),
        label: `${accountName} @ ${siteName}`,
        description: siteName,
      };
    })
  ), [activeAccounts]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const shouldOpenCreate = isTruthyFlag(params.get('create'));
    const requestedAccountId = parsePositiveInt(params.get('accountId'));
    const requestedModel = (params.get('model') || '').trim();
    if (!shouldOpenCreate || !requestedAccountId) return;

    const preferredAccount = activeAccounts.find((account) => account.id === requestedAccountId);
    const fallbackAccount = preferredAccount || activeAccounts[0] || null;
    if (!fallbackAccount) return;

    setShowAdd(true);
    setCreateHintModelName(requestedModel);
    setSyncingAccountId(fallbackAccount.id);
    setForm((prev) => ({
      ...prev,
      accountId: fallbackAccount.id,
      group: 'default',
    }));

    if (!preferredAccount) {
      toast.info('指定账号不可用，已自动切换到首个可用账号');
    }

    params.delete('create');
    params.delete('accountId');
    params.delete('model');
    params.delete('from');
    const nextSearch = params.toString();
    navigate(
      {
        pathname: location.pathname,
        search: nextSearch ? `?${nextSearch}` : '',
      },
      { replace: true },
    );
  }, [activeAccounts, location.pathname, location.search, navigate, toast]);

  useEffect(() => {
    const focusTokenId = readFocusTokenId(location.search);
    if (!focusTokenId || loading) return;

    const row = rowRefs.current.get(focusTokenId);
    const cleanedSearch = clearFocusParams(location.search);
    if (!row) {
      navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
      return;
    }

    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setHighlightTokenId(focusTokenId);
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => {
      setHighlightTokenId((current) => (current === focusTokenId ? null : current));
    }, 2200);

    navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
  }, [loading, location.pathname, location.search, navigate, tokens]);

  const focusTokenRow = useCallback((tokenId: number) => {
    const row = rowRefs.current.get(tokenId);
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    setHighlightTokenId(tokenId);
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => {
      setHighlightTokenId((current) => (current === tokenId ? null : current));
    }, 2200);
  }, []);

  const withRowLoading = async (key: string, fn: () => Promise<void>) => {
    setRowLoading((prev) => ({ ...prev, [key]: true }));
    try {
      await fn();
    } finally {
      setRowLoading((prev) => ({ ...prev, [key]: false }));
    }
  };

  const toggleTokenSelection = (tokenId: number, checked: boolean) => {
    setSelectedTokenIds((current) => (
      checked
        ? Array.from(new Set([...current, tokenId]))
        : current.filter((id) => id !== tokenId)
    ));
  };

  const toggleSelectAllTokens = (checked: boolean) => {
    if (!checked) {
      setSelectedTokenIds((current) => current.filter((id) => !accountClusteredTokens.some((token) => token.id === id)));
      return;
    }
    setSelectedTokenIds((current) => Array.from(new Set([...current, ...accountClusteredTokens.map((token) => token.id)])));
  };

  const toggleTokenDetails = (tokenId: number) => {
    setExpandedTokenIds((current) => (
      current.includes(tokenId)
        ? current.filter((id) => id !== tokenId)
        : [...current, tokenId]
    ));
  };

  const runBatchTokenAction = async (action: 'enable' | 'disable' | 'delete', skipDeleteConfirm = false) => {
    if (selectedTokenIds.length === 0) return;
    if (action === 'delete' && !skipDeleteConfirm) {
      setDeleteConfirm({ mode: 'batch', count: selectedTokenIds.length });
      return;
    }

    setBatchActionLoading(true);
    try {
      const result = await api.batchUpdateAccountTokens({
        ids: selectedTokenIds,
        action,
      });
      const successIds = Array.isArray(result?.successIds) ? result.successIds.map((id: unknown) => Number(id)) : [];
      const failedItems = Array.isArray(result?.failedItems) ? result.failedItems : [];
      if (failedItems.length > 0) {
        toast.info(`批量操作完成：成功 ${successIds.length}，失败 ${failedItems.length}`);
      } else {
        toast.success(`批量操作完成：成功 ${successIds.length}`);
      }
      setSelectedTokenIds(failedItems.map((item: any) => Number(item.id)).filter((id: number) => Number.isFinite(id) && id > 0));
      await load();
    } catch (e: any) {
      toast.error(e.message || '批量操作失败');
    } finally {
      setBatchActionLoading(false);
    }
  };

  const confirmDelete = async () => {
    const target = deleteConfirm;
    if (!target) return;

    setDeleteConfirm(null);
    if (target.mode === 'single' && target.tokenId) {
      await withRowLoading(`token-${target.tokenId}-delete`, async () => {
        await api.deleteAccountToken(target.tokenId!);
        toast.success('令牌已删除');
        await load();
      });
      return;
    }

    await runBatchTokenAction('delete', true);
  };

  const openEditPanel = useCallback((token: any) => {
    setShowAdd(false);
    setCreateHintModelName('');
    setEditingToken(token);
    editingTokenIdRef.current = token.id;
    setEditingTokenPendingMessage(
      isMaskedPendingToken(token)
        ? '请粘贴完整明文 token；当前本地仅保存了上游返回的脱敏占位值。'
        : '',
    );
    setEditForm({
      name: token?.name || '',
      token: '',
      group: (token?.tokenGroup || '').trim() || 'default',
      enabled: isMaskedPendingToken(token) ? true : token?.enabled !== false,
      isDefault: !!token?.isDefault,
    });

    if (isMaskedPendingToken(token)) {
      setEditingTokenValueLoading(false);
      return;
    }

    setEditingTokenValueLoading(true);

    void api.getAccountTokenValue(token.id)
      .then((res: any) => {
        if (editingTokenIdRef.current !== token.id) return;
        setEditForm((prev) => ({
          ...prev,
          token: typeof res?.token === 'string' ? res.token : prev.token,
        }));
      })
      .catch((error: any) => {
        if (editingTokenIdRef.current !== token.id) return;
        toast.error(error?.message || '加载令牌详情失败');
      })
      .finally(() => {
        if (editingTokenIdRef.current !== token.id) return;
        setEditingTokenValueLoading(false);
      });
  }, [toast]);

  const closeEditPanel = useCallback(() => {
    editingTokenIdRef.current = null;
    setEditingToken(null);
    setSavingEdit(false);
    setEditingTokenValueLoading(false);
    setEditingTokenPendingMessage('');
    setEditForm({
      name: '',
      token: '',
      group: 'default',
      enabled: true,
      isDefault: false,
    });
  }, []);

  const saveEditPanel = async () => {
    if (!editingToken) return;
    if (isMaskedPendingToken(editingToken) && !editForm.token.trim()) {
      toast.error('请粘贴完整明文 token 后再保存');
      return;
    }
    setSavingEdit(true);
    try {
      await api.updateAccountToken(editingToken.id, {
        name: editForm.name.trim() || editingToken.name,
        token: editForm.token.trim() || undefined,
        group: editForm.group || 'default',
        enabled: editForm.enabled,
        isDefault: editForm.isDefault,
      });
      toast.success('令牌已更新');
      closeEditPanel();
      await load();
    } catch (e: any) {
      toast.error(e.message || '更新令牌失败');
    } finally {
      setSavingEdit(false);
    }
  };

  useEffect(() => {
    if (!pendingAutoOpenTokenId || loading) return;
    const token = tokens.find((item: any) => item.id === pendingAutoOpenTokenId);
    if (!token) return;
    focusTokenRow(token.id);
    openEditPanel(token);
    setPendingAutoOpenTokenId(null);
  }, [focusTokenRow, loading, openEditPanel, pendingAutoOpenTokenId, tokens]);

  const handleTokenRowClick = (tokenId: number, event: React.MouseEvent<HTMLTableRowElement>) => {
    if (shouldIgnoreRowSelectionClick(event.target)) return;
    const isSelected = selectedTokenIds.includes(tokenId);
    toggleTokenSelection(tokenId, !isSelected);
  };

  const handleCopyToken = async (tokenId: number, tokenName: string) => {
    try {
      await withRowLoading(`token-${tokenId}-copy`, async () => {
        const res = await api.getAccountTokenValue(tokenId);
        const tokenValue = (res?.token || '').trim();
        if (!tokenValue) {
          toast.error('令牌为空，无法复制');
          return;
        }

        await copyText(tokenValue);
        toast.success(`已复制令牌：${tokenName || `token-${tokenId}`}`);
      });
    } catch (error: any) {
      toast.error(error?.message || '复制令牌失败');
    }
  };

  const handleAddToken = async () => {
    if (!form.accountId) return;
    if (!form.unlimitedQuota) {
      const remainQuota = Number.parseInt(form.remainQuota, 10);
      if (!Number.isFinite(remainQuota) || remainQuota <= 0) {
        toast.error('有限额度令牌请填写正整数额度');
        return;
      }
    }
    setSaving(true);
    try {
      const remainQuota = form.unlimitedQuota
        ? undefined
        : Number.parseInt(form.remainQuota, 10);
      await api.addAccountToken({
        accountId: form.accountId,
        name: form.name,
        group: form.group || 'default',
        unlimitedQuota: form.unlimitedQuota,
        remainQuota,
        expiredTime: form.expiredTime || undefined,
        allowIps: form.allowIps,
      });
      toast.success('已在站点创建并同步令牌');
      setForm(initialCreateForm);
      setShowAdd(false);
      setCreateHintModelName('');
      await load();
    } catch (e: any) {
      toast.error(e.message || '创建令牌失败');
    } finally {
      setSaving(false);
    }
  };

  const handleSync = useCallback(async () => {
    if (!syncingAccountId) return;
    setSyncing(true);
    try {
      const res = await api.syncAccountTokens(syncingAccountId) as AccountTokenSyncResult;
      const status = resolveSyncStatus(res);
      if (status === 'failed') {
        toast.error(`同步失败：${resolveSyncMessage(res, '请检查账号令牌或站点状态')}`);
      } else if (isMaskedPendingSyncResult(res)) {
        toast.info(resolveSyncMessage(res, '上游返回了脱敏令牌，请补全明文 token'));
        const loaded = await load();
        const pendingIds = Array.isArray(res.pendingTokenIds)
          ? res.pendingTokenIds.map((id) => Number(id)).filter((id) => Number.isFinite(id) && id > 0)
          : [];
        const nextTokens = Array.isArray(loaded?.tokens) ? loaded.tokens : [];
        if (pendingIds.length === 1) {
          const pendingToken = nextTokens.find((token: any) => token.id === pendingIds[0]);
          if (pendingToken) {
            focusTokenRow(pendingToken.id);
            openEditPanel(pendingToken);
          } else {
            setPendingAutoOpenTokenId(pendingIds[0] || null);
          }
        } else if (pendingIds.length > 1) {
          focusTokenRow(pendingIds[0]!);
        }
        return;
      } else if (status === 'skipped') {
        toast.info(`同步已跳过：${resolveSyncMessage(res, '账号缺少可用 Session Cookie')}`);
      } else {
        toast.success(`同步完成：新增 ${res.created || 0}，更新 ${res.updated || 0}`);
      }
      await load();
    } catch (e: any) {
      toast.error(e.message || '同步令牌失败');
    } finally {
      setSyncing(false);
    }
  }, [focusTokenRow, load, openEditPanel, syncingAccountId, toast]);

  const handleSyncAll = useCallback(async () => {
    setSyncingAll(true);
    try {
      const res = await api.syncAllAccountTokens();
      if (res?.queued) {
        toast.info(res.message || '已开始同步令牌，请稍后查看日志');
        await load();
        return;
      }

      const syncResults = (
        Array.isArray(res?.results) ? res.results
          : Array.isArray(res?.items) ? res.items
            : Array.isArray(res?.accounts) ? res.accounts
              : []
      ) as AccountTokenSyncResult[];

      if (syncResults.length === 0) {
        const status = resolveSyncStatus(res as AccountTokenSyncResult);
        if (status === 'failed') {
          toast.error(`全部同步失败：${resolveSyncMessage(res, '请稍后重试')}`);
        } else if (status === 'skipped') {
          toast.info(`全部同步已跳过：${resolveSyncMessage(res, '没有可同步的账号')}`);
        } else {
          toast.success('全部账号同步完成');
        }
      } else {
        const failedRows = syncResults.filter((item) => resolveSyncStatus(item) === 'failed');
        const skippedRows = syncResults.filter((item) => resolveSyncStatus(item) === 'skipped');
        const successRows = syncResults.filter((item) => resolveSyncStatus(item) === 'success');
        const maskedRows = syncResults.filter((item) => isMaskedPendingSyncResult(item));

        toast.success(`全部同步完成：成功 ${successRows.length}，跳过 ${skippedRows.length}，失败 ${failedRows.length}`);

        failedRows.slice(0, 3).forEach((item) => {
          toast.error(`${resolveAccountLabel(item)} 同步失败：${resolveSyncMessage(item, '请检查账号配置')}`);
        });
        maskedRows.slice(0, 3).forEach((item) => {
          toast.info(`${resolveAccountLabel(item)} 需要补全明文 token：${resolveSyncMessage(item, '上游返回脱敏令牌')}`);
        });
        skippedRows.slice(0, 3).forEach((item) => {
          toast.info(`${resolveAccountLabel(item)} 已跳过：${resolveSyncMessage(item, '不满足同步条件')}`);
        });

        if (failedRows.length > 3) {
          toast.error(`另有 ${failedRows.length - 3} 个失败账号，请查看日志`);
        }
        if (skippedRows.length > 3) {
          toast.info(`另有 ${skippedRows.length - 3} 个跳过账号，请查看日志`);
        }
      }

      await load();
    } catch (e: any) {
      toast.error(e.message || '全部同步失败');
    } finally {
      setSyncingAll(false);
    }
  }, [load, toast]);

  const handleToggleAdd = useCallback(() => {
    setShowAdd((prev) => {
      const nextOpen = !prev;
      if (!nextOpen) setCreateHintModelName('');
      return nextOpen;
    });
  }, []);

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '10px 14px',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    fontSize: 13,
    outline: 'none',
    background: 'var(--color-bg)',
    color: 'var(--color-text-primary)',
  };

  const sectionCardStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
    padding: 14,
    border: '1px solid var(--color-border-light)',
    borderRadius: 'var(--radius-md)',
    background: 'var(--color-bg-card)',
  };

  const sectionLabelStyle: React.CSSProperties = {
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--color-text-secondary)',
    letterSpacing: '0.02em',
  };

  const toggleCardStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 10,
    padding: '12px 14px',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--color-bg)',
    color: 'var(--color-text-primary)',
  };

  const headerActions = useMemo(() => (
    <div className={`page-actions ${embedded ? 'accounts-page-actions' : ''}`.trim()}>
      {isMobile ? (
        <>
          <button
            type="button"
            onClick={() => setShowMobileTools(true)}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            同步与筛选
          </button>
          <button
            type="button"
            data-testid="tokens-mobile-select-all"
            onClick={() => toggleSelectAllTokens(!allVisibleTokensSelected)}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            {allVisibleTokensSelected ? '取消全选' : '全选可见项'}
          </button>
        </>
      ) : (
        <>
          <div style={{ minWidth: 220, position: 'relative', zIndex: 20 }}>
            <ModernSelect
              size="sm"
              value={String(syncingAccountId || 0)}
              onChange={(nextValue) => setSyncingAccountId(Number.parseInt(nextValue, 10) || 0)}
              options={[
                { value: '0', label: '选择账号后同步站点令牌' },
                ...activeAccountSelectOptions,
              ]}
              placeholder="选择账号后同步站点令牌"
              searchable
              searchPlaceholder={ACCOUNT_SELECT_SEARCH_PLACEHOLDER}
            />
          </div>
          <button
            onClick={handleSync}
            disabled={syncing || syncingAll || !syncingAccountId}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {syncing ? <><span className="spinner spinner-sm" /> 同步中...</> : '同步站点令牌'}
          </button>
          <button
            onClick={handleSyncAll}
            disabled={syncing || syncingAll || activeAccounts.length === 0}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {syncingAll ? <><span className="spinner spinner-sm" /> 同步中...</> : '同步全部账号'}
          </button>
        </>
      )}
      <button
        onClick={handleToggleAdd}
        className="btn btn-primary"
      >
        {showAdd ? '取消' : '+ 新增令牌'}
      </button>
    </div>
  ), [activeAccountSelectOptions, activeAccounts.length, allVisibleTokensSelected, embedded, handleSync, handleSyncAll, handleToggleAdd, isMobile, showAdd, syncing, syncingAccountId, syncingAll]);

  useEffect(() => {
    if (!embedded || !onEmbeddedActionsChange) return;
    onEmbeddedActionsChange(headerActions);
    return () => {
      onEmbeddedActionsChange(null);
    };
  }, [embedded, headerActions, onEmbeddedActionsChange]);

  return (
    <div className={embedded ? '' : 'animate-fade-in'}>
      {(!embedded || !onEmbeddedActionsChange) && (
        <div className="page-header">
          {!embedded ? <h2 className="page-title">{tr('账号令牌')}</h2> : <div />}
          {headerActions}
        </div>
      )}

      <ResponsiveFilterPanel
        isMobile={isMobile}
        mobileOpen={showMobileTools}
        onMobileClose={() => setShowMobileTools(false)}
        mobileTitle="令牌同步与筛选"
        mobileContent={(
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>同步账号</div>
              <ModernSelect
                value={String(syncingAccountId || 0)}
                onChange={(nextValue) => setSyncingAccountId(Number.parseInt(nextValue, 10) || 0)}
                options={[
                  { value: '0', label: '选择账号后同步站点令牌' },
                  ...activeAccountSelectOptions,
                ]}
                placeholder="选择账号后同步站点令牌"
                searchable
                searchPlaceholder={ACCOUNT_SELECT_SEARCH_PLACEHOLDER}
              />
            </div>
            <button
              onClick={handleSync}
              disabled={syncing || syncingAll || !syncingAccountId}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {syncing ? <><span className="spinner spinner-sm" /> 同步中...</> : '同步站点令牌'}
            </button>
            <button
              onClick={handleSyncAll}
              disabled={syncing || syncingAll || activeAccounts.length === 0}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {syncingAll ? <><span className="spinner spinner-sm" /> 同步中...</> : '同步全部账号'}
            </button>
          </div>
        )}
      />

      <div className="info-tip" style={{ marginBottom: 12 }}>
        新增令牌会调用站点 API 创建新密钥，再自动同步到本地。支持设置分组、额度、过期时间和 IP 白名单；已存在密钥可直接用“同步站点令牌”读取。
      </div>

      <DeleteConfirmModal
        open={Boolean(deleteConfirm)}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={confirmDelete}
        title="确认删除令牌"
        confirmText="确认删除"
        loading={batchActionLoading || (deleteConfirm?.mode === 'single' && !!rowLoading[`token-${deleteConfirm?.tokenId}-delete`])}
        description={deleteConfirm?.mode === 'single'
          ? <>确定要删除令牌 <strong>{deleteConfirm.tokenName || `#${deleteConfirm.tokenId}`}</strong> 吗？</>
          : <>确定要删除选中的 <strong>{deleteConfirm?.count || 0}</strong> 个令牌吗？</>}
      />

      <CenteredModal
        open={Boolean(editingToken)}
        onClose={closeEditPanel}
        title="编辑令牌"
        maxWidth={760}
        bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
        footer={(
          <>
            <button onClick={closeEditPanel} className="btn btn-ghost">取消</button>
            <button onClick={saveEditPanel} disabled={savingEdit || editingTokenValueLoading} className="btn btn-primary">
              {savingEdit ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存修改'}
            </button>
          </>
        )}
      >
        {editingToken ? (
          <>
            <div
              style={{
                fontSize: 12,
                color: 'var(--color-text-secondary)',
                background: 'color-mix(in srgb, var(--color-primary) 8%, var(--color-bg))',
                border: '1px solid color-mix(in srgb, var(--color-primary) 18%, transparent)',
                borderRadius: 'var(--radius-sm)',
                padding: '8px 10px',
              }}
            >
              账号: {editingToken.account?.username || `account-${editingToken.accountId}`} @ {editingToken.site?.name || '-'}
            </div>
            {editingTokenPendingMessage ? (
              <div
                style={{
                  fontSize: 12,
                  color: 'var(--color-text-secondary)',
                  background: 'color-mix(in srgb, var(--color-warning) 12%, var(--color-bg))',
                  border: '1px solid color-mix(in srgb, var(--color-warning) 28%, transparent)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '8px 10px',
                }}
              >
                {editingTokenPendingMessage}
              </div>
            ) : null}
            <div style={sectionCardStyle}>
              <div style={sectionLabelStyle}>基本信息</div>
              <ResponsiveFormGrid>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>令牌名称</div>
                  <input
                    placeholder="令牌名称"
                    value={editForm.name}
                    onChange={(e) => setEditForm((prev) => ({ ...prev, name: e.target.value }))}
                    style={inputStyle}
                  />
                </div>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>分组</div>
                  <ModernSelect
                    value={editForm.group || 'default'}
                    onChange={(nextValue) => setEditForm((prev) => ({ ...prev, group: nextValue || 'default' }))}
                    options={(editGroupOptions.length > 0 ? editGroupOptions : ['default']).map((group) => ({
                      value: group,
                      label: group,
                    }))}
                    placeholder={editGroupLoading ? '分组加载中...' : '选择分组'}
                    disabled={editGroupLoading}
                  />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>令牌值</div>
                  <textarea
                    placeholder={editingTokenValueLoading ? '令牌加载中...' : '令牌值'}
                    value={editForm.token}
                    onChange={(e) => setEditForm((prev) => ({ ...prev, token: e.target.value }))}
                    style={{
                      ...inputStyle,
                      minHeight: 96,
                      resize: 'vertical',
                      fontFamily: 'var(--font-mono)',
                      lineHeight: 1.5,
                    }}
                    disabled={editingTokenValueLoading}
                  />
                </div>
              </ResponsiveFormGrid>
            </div>
            <div style={sectionCardStyle}>
              <div style={sectionLabelStyle}>状态设置</div>
              <ResponsiveFormGrid>
                <label style={toggleCardStyle}>
                  <input
                    type="checkbox"
                    checked={editForm.enabled}
                    onChange={(e) => setEditForm((prev) => ({ ...prev, enabled: e.target.checked }))}
                    style={{ marginTop: 2 }}
                  />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>启用令牌</span>
                    <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>关闭后令牌不会参与分发</span>
                  </div>
                </label>
                <label style={toggleCardStyle}>
                  <input
                    type="checkbox"
                    checked={editForm.isDefault}
                    onChange={(e) => setEditForm((prev) => ({ ...prev, isDefault: e.target.checked }))}
                    style={{ marginTop: 2 }}
                  />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>设为默认令牌</span>
                    <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>优先作为该账号的默认转发令牌</span>
                  </div>
                </label>
              </ResponsiveFormGrid>
            </div>
          </>
        ) : null}
      </CenteredModal>

      {selectedTokenIds.length > 0 && (
        <ResponsiveBatchActionBar
          isMobile={isMobile}
          info={`已选 ${selectedTokenIds.length} 项`}
          desktopStyle={{ marginBottom: 12 }}
        >
          <button onClick={() => runBatchTokenAction('enable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量启用
          </button>
          <button onClick={() => runBatchTokenAction('disable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量禁用
          </button>
          <button data-testid="tokens-batch-delete" onClick={() => runBatchTokenAction('delete')} disabled={batchActionLoading} className="btn btn-link btn-link-danger">
            批量删除
          </button>
        </ResponsiveBatchActionBar>
      )}

      <CenteredModal
        open={showAdd}
        onClose={handleToggleAdd}
        title="新增令牌"
        maxWidth={820}
        bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      >
        <ResponsiveFormGrid>
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>所属账号</div>
            <ModernSelect
              value={String(form.accountId || 0)}
              onChange={(nextValue) => {
                setForm((prev) => ({
                  ...prev,
                  accountId: Number.parseInt(nextValue, 10) || 0,
                  group: '',
                }));
              }}
              options={[
                { value: '0', label: '选择账号' },
                ...activeAccountSelectOptions,
              ]}
              placeholder="选择账号"
              searchable
              searchPlaceholder={ACCOUNT_SELECT_SEARCH_PLACEHOLDER}
            />
          </div>
          {createHintModelName ? (
            <div
              style={{
                gridColumn: '1 / -1',
                fontSize: 12,
                color: 'var(--color-text-secondary)',
                background: 'color-mix(in srgb, var(--color-info) 10%, var(--color-bg))',
                border: '1px solid color-mix(in srgb, var(--color-info) 30%, transparent)',
                borderRadius: 'var(--radius-sm)',
                padding: '6px 8px',
              }}
            >
              来自路由提醒：为模型 <code style={{ fontSize: 11 }}>{createHintModelName}</code> 补充该账号令牌后，可自动生成对应通道。
            </div>
          ) : null}
          <div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>令牌名称（可选）</div>
            <input
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
              placeholder="例如 metapi"
              style={inputStyle}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>分组</div>
            <ModernSelect
              value={form.group || ''}
              onChange={(nextValue) => setForm((prev) => ({ ...prev, group: nextValue }))}
              options={(groupOptions.length > 0 ? groupOptions : ['default']).map((group) => ({
                value: group,
                label: group,
              }))}
              placeholder={groupLoading ? '分组加载中...' : '选择分组'}
              disabled={!form.accountId || groupLoading}
            />
          </div>
          <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={form.unlimitedQuota}
                onChange={(e) => setForm((prev) => ({ ...prev, unlimitedQuota: e.target.checked }))}
              />
              不限额度
            </label>
            {!form.unlimitedQuota && (
              <input
                value={form.remainQuota}
                onChange={(e) => setForm((prev) => ({ ...prev, remainQuota: e.target.value.replace(/[^\d]/g, '') }))}
                placeholder="额度（正整数）"
                style={{ ...inputStyle, maxWidth: 220 }}
              />
            )}
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>过期时间（可选）</div>
            <input
              type="datetime-local"
              value={form.expiredTime}
              onChange={(e) => setForm((prev) => ({ ...prev, expiredTime: e.target.value }))}
              style={inputStyle}
            />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>IP 白名单（可选）</div>
            <input
              value={form.allowIps}
              onChange={(e) => setForm((prev) => ({ ...prev, allowIps: e.target.value }))}
              placeholder="多个用英文逗号分隔"
              style={inputStyle}
            />
          </div>
          <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', fontSize: 12, color: 'var(--color-text-muted)' }}>
            将在选中账号所属站点直接创建新密钥
          </div>
        </ResponsiveFormGrid>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginTop: 8 }}>
          <button onClick={handleToggleAdd} className="btn btn-ghost">取消</button>
          <button
            onClick={handleAddToken}
            disabled={saving || !form.accountId}
            className="btn btn-primary"
          >
            {saving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 创建中...</> : '创建并同步令牌'}
          </button>
        </div>
      </CenteredModal>

      <div className="card" style={{ overflowX: 'auto' }}>
        {loading ? (
          <div style={{ padding: 20 }}>
            <div className="skeleton" style={{ width: '100%', height: 34, marginBottom: 8 }} />
            <div className="skeleton" style={{ width: '100%', height: 34, marginBottom: 8 }} />
            <div className="skeleton" style={{ width: '100%', height: 34 }} />
          </div>
        ) : tokens.length > 0 ? (
          isMobile ? (
            <div className="mobile-card-list">
              {accountClusteredTokens.map((token: any) => {
                const loadingPrefix = `token-${token.id}`;
                const isPending = isMaskedPendingToken(token);
                const isExpanded = expandedTokenIds.includes(token.id);
                return (
                  <MobileCard
                    key={token.id}
                    title={token.name || '-'}
                    headerActions={(
                      <input
                        type="checkbox"
                        aria-label={`选择令牌 ${token.name || token.id}`}
                        checked={selectedTokenIds.includes(token.id)}
                        onChange={(event) => toggleTokenSelection(token.id, event.target.checked)}
                      />
                    )}
                    footerActions={(
                      <>
                        <button
                          type="button"
                          onClick={() => toggleTokenDetails(token.id)}
                          className="btn btn-link"
                        >
                          {isExpanded ? '收起' : '详情'}
                        </button>
                        {!isPending ? (
                          <button
                            onClick={() => handleCopyToken(token.id, token.name || '')}
                            disabled={!!rowLoading[`${loadingPrefix}-copy`]}
                            className="btn btn-link btn-link-primary"
                            data-testid={`token-copy-${token.id}`}
                          >
                            {rowLoading[`${loadingPrefix}-copy`] ? <span className="spinner spinner-sm" /> : '复制'}
                          </button>
                        ) : null}
                        <button
                          onClick={() => openEditPanel(token)}
                          className="btn btn-link btn-link-info"
                        >
                          {isPending ? '编辑补全' : '编辑'}
                        </button>
                      </>
                    )}
                  >
                    <MobileField label="账号" value={token.account?.username || `account-${token.accountId}`} />
                    <MobileField label="分组" value={token.tokenGroup || 'default'} />
                    <MobileField
                      label="状态"
                      value={(
                        <span className={`badge ${isPending ? 'badge-warning' : (token.enabled ? 'badge-success' : 'badge-muted')}`} style={{ fontSize: 11 }}>
                          {isPending ? '待补全' : (token.enabled ? '启用' : '禁用')}
                        </span>
                      )}
                    />
                    {isExpanded ? (
                      <div className="mobile-card-extra">
                        <MobileField
                          label="令牌值"
                          stacked
                          value={<span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{token.tokenMasked || '***'}</span>}
                        />
                        <MobileField
                          label="来源站点"
                          value={token.site?.url ? (
                            <a
                              href={token.site.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="badge-link"
                            >
                              <span className="badge badge-muted" style={{ fontSize: 11 }}>
                                {token.site?.name || 'unknown'}
                              </span>
                            </a>
                          ) : (
                            <span className="badge badge-muted" style={{ fontSize: 11 }}>
                              {token.site?.name || 'unknown'}
                            </span>
                          )}
                        />
                        <MobileField
                          label="默认"
                          value={token.isDefault ? <span className="badge badge-warning" style={{ fontSize: 11 }}>默认</span> : '-'}
                        />
                        <MobileField label="更新时间" value={formatDateTimeLocal(token.updatedAt)} />
                        <div className="mobile-card-actions">
                          {!isPending && !token.isDefault && (
                            <button
                              onClick={() => withRowLoading(`${loadingPrefix}-default`, async () => {
                                await api.setDefaultAccountToken(token.id);
                                toast.success('默认令牌已更新');
                                await load();
                              })}
                              disabled={!!rowLoading[`${loadingPrefix}-default`]}
                              className="btn btn-link btn-link-info"
                            >
                              {rowLoading[`${loadingPrefix}-default`] ? <span className="spinner spinner-sm" /> : '设默认'}
                            </button>
                          )}
                          {!isPending ? (
                            <button
                              onClick={() => withRowLoading(`${loadingPrefix}-toggle`, async () => {
                                await api.updateAccountToken(token.id, { enabled: !token.enabled });
                                toast.success(token.enabled ? '令牌已禁用' : '令牌已启用');
                                await load();
                              })}
                              disabled={!!rowLoading[`${loadingPrefix}-toggle`]}
                              className={`btn btn-link ${token.enabled ? 'btn-link-warning' : 'btn-link-primary'}`}
                            >
                              {rowLoading[`${loadingPrefix}-toggle`] ? <span className="spinner spinner-sm" /> : (token.enabled ? '禁用' : '启用')}
                            </button>
                          ) : null}
                          <button
                            onClick={() => setDeleteConfirm({ mode: 'single', tokenId: token.id, tokenName: token.name || '' })}
                            disabled={!!rowLoading[`${loadingPrefix}-delete`]}
                            className="btn btn-link btn-link-danger"
                          >
                            {rowLoading[`${loadingPrefix}-delete`] ? <span className="spinner spinner-sm" /> : '删除'}
                          </button>
                        </div>
                      </div>
                    ) : null}
                  </MobileCard>
                );
              })}
            </div>
          ) : (
            <table className="data-table token-table">
            <thead>
              <tr>
                <th style={{ width: 44 }}>
                  <input
                    type="checkbox"
                    checked={allVisibleTokensSelected}
                    onChange={(e) => toggleSelectAllTokens(e.target.checked)}
                  />
                </th>
                <th>令牌名称</th>
                <th>令牌值</th>
                <th>来源站点</th>
                <th>账号</th>
                <th>分组</th>
                <th>状态</th>
                <th>默认</th>
                <th>更新时间</th>
                <th className="token-table-actions-col" style={{ textAlign: 'right' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {accountClusteredTokens.map((token: any, i: number) => {
                const loadingPrefix = `token-${token.id}`;
                const isPending = isMaskedPendingToken(token);
                return (
                  <tr
                    key={token.id}
                    data-testid={`token-row-${token.id}`}
                    ref={(node) => {
                      if (node) rowRefs.current.set(token.id, node);
                      else rowRefs.current.delete(token.id);
                    }}
                    onClick={(event) => handleTokenRowClick(token.id, event)}
                    className={`animate-slide-up stagger-${Math.min(i + 1, 5)} row-selectable ${selectedTokenIds.includes(token.id) ? 'row-selected' : ''} ${highlightTokenId === token.id ? 'row-focus-highlight' : ''}`.trim()}
                  >
                    <td>
                      <input
                        data-testid={`token-select-${token.id}`}
                        type="checkbox"
                        checked={selectedTokenIds.includes(token.id)}
                        onChange={(e) => toggleTokenSelection(token.id, e.target.checked)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </td>
                    <td style={{ fontWeight: 600 }}>{token.name || '-'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{token.tokenMasked || '***'}</td>
                    <td>
                      {token.site?.url ? (
                        <a
                          href={token.site.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="badge-link"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="badge badge-muted" style={{ fontSize: 11 }}>
                            {token.site?.name || 'unknown'}
                          </span>
                        </a>
                      ) : (
                        <span className="badge badge-muted" style={{ fontSize: 11 }}>
                          {token.site?.name || 'unknown'}
                        </span>
                      )}
                    </td>
                    <td>{token.account?.username || `account-${token.accountId}`}</td>
                    <td>{token.tokenGroup || 'default'}</td>
                    <td>
                      {isPending ? (
                        <span className="badge badge-warning" style={{ fontSize: 11 }}>待补全</span>
                      ) : (
                        <span className={`badge ${token.enabled ? 'badge-success' : 'badge-muted'}`} style={{ fontSize: 11 }}>
                          {token.enabled ? '启用' : '禁用'}
                        </span>
                      )}
                    </td>
                    <td>{token.isDefault ? <span className="badge badge-warning" style={{ fontSize: 11 }}>默认</span> : '-'}</td>
                    <td style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{formatDateTimeLocal(token.updatedAt)}</td>
                    <td className="token-actions-cell" style={{ textAlign: 'right' }}>
                      <div className="token-table-actions">
                        {!isPending && !token.isDefault && (
                          <button
                            onClick={() => withRowLoading(`${loadingPrefix}-default`, async () => {
                              await api.setDefaultAccountToken(token.id);
                              toast.success('默认令牌已更新');
                              await load();
                            })}
                            disabled={!!rowLoading[`${loadingPrefix}-default`]}
                            className="btn btn-link btn-link-info token-table-action-btn"
                          >
                            {rowLoading[`${loadingPrefix}-default`] ? <span className="spinner spinner-sm" /> : '设默认'}
                          </button>
                        )}
                        {!isPending ? (
                          <button
                            onClick={() => handleCopyToken(token.id, token.name || '')}
                            disabled={!!rowLoading[`${loadingPrefix}-copy`]}
                            className="btn btn-link btn-link-primary token-table-action-btn"
                            data-testid={`token-copy-${token.id}`}
                          >
                            {rowLoading[`${loadingPrefix}-copy`] ? <span className="spinner spinner-sm" /> : '复制'}
                          </button>
                        ) : null}
                        <button
                          onClick={() => openEditPanel(token)}
                          className="btn btn-link btn-link-info token-table-action-btn"
                        >
                          {isPending ? '编辑补全' : '编辑'}
                        </button>
                        {!isPending ? (
                          <button
                            onClick={() => withRowLoading(`${loadingPrefix}-toggle`, async () => {
                              await api.updateAccountToken(token.id, { enabled: !token.enabled });
                              toast.success(token.enabled ? '令牌已禁用' : '令牌已启用');
                              await load();
                            })}
                            disabled={!!rowLoading[`${loadingPrefix}-toggle`]}
                            className={`btn btn-link ${token.enabled ? 'btn-link-warning' : 'btn-link-primary'} token-table-action-btn`}
                          >
                            {rowLoading[`${loadingPrefix}-toggle`] ? <span className="spinner spinner-sm" /> : (token.enabled ? '禁用' : '启用')}
                          </button>
                        ) : null}
                        <button
                          onClick={() => setDeleteConfirm({ mode: 'single', tokenId: token.id, tokenName: token.name || '' })}
                          disabled={!!rowLoading[`${loadingPrefix}-delete`]}
                          className="btn btn-link btn-link-danger token-table-action-btn"
                        >
                          {rowLoading[`${loadingPrefix}-delete`] ? <span className="spinner spinner-sm" /> : '删除'}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          )
        ) : (
          <div className="empty-state">
            <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
            <div className="empty-state-title">暂无令牌</div>
            <div className="empty-state-desc">可先同步站点令牌，或直接在站点创建新令牌。</div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Tokens() {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  params.set('segment', 'tokens');
  const nextSearch = params.toString();
  return <Navigate to={`/accounts${nextSearch ? `?${nextSearch}` : ''}`} replace />;
}
