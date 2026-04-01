import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import CenteredModal from '../components/CenteredModal.js';
import ResponsiveFilterPanel from '../components/ResponsiveFilterPanel.js';
import ResponsiveFormGrid from '../components/ResponsiveFormGrid.js';
import ResponsiveBatchActionBar from '../components/ResponsiveBatchActionBar.js';
import { useToast } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import { useIsMobile } from '../components/useIsMobile.js';
import DeleteConfirmModal from '../components/DeleteConfirmModal.js';
import SiteBadgeLink from '../components/SiteBadgeLink.js';
import AccountModelsModal from './accounts/AccountModelsModal.js';
import {
  buildAddAccountPrereqHint,
  buildVerifyFailureHint,
  normalizeVerifyFailureMessage,
} from './helpers/accountVerifyFeedback.js';
import {
  isTruthyFlag,
  parsePositiveInt,
  resolveAccountCredentialMode,
} from './helpers/accountConnection.js';
import { clearFocusParams, readFocusAccountIntent } from './helpers/navigationFocus.js';
import { TokensPanel } from './Tokens.js';
import { tr } from '../i18n.js';
import { buildCustomReorderUpdates, sortItemsForDisplay, type SortMode } from './helpers/listSorting.js';
import { shouldIgnoreRowSelectionClick } from './helpers/rowSelection.js';
import { SITE_DOCS_URL } from '../docsLink.js';
import { getSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';

type ConnectionsSegment = 'session' | 'apikey' | 'tokens';

const ACCOUNT_SEGMENTS: Array<{
  value: ConnectionsSegment;
  label: string;
  tooltip: string;
  tooltipSide: 'top' | 'bottom';
  tooltipAlign: 'start' | 'center' | 'end';
}> = [
    { value: 'session', label: '账号管理', tooltip: '用于签到、余额、状态维护', tooltipSide: 'bottom', tooltipAlign: 'start' },
    { value: 'apikey', label: 'API Key管理', tooltip: '只有 Base URL + Key 时使用，只负责代理调用', tooltipSide: 'bottom', tooltipAlign: 'center' },
    { value: 'tokens', label: '账号令牌管理', tooltip: '从账号同步或手动维护，供路由实际调用', tooltipSide: 'bottom', tooltipAlign: 'end' },
  ];

const SITE_SELECT_SEARCH_PLACEHOLDER = '筛选站点（名称 / 平台 / URL）';

function createLoginForm() {
  return { siteId: 0, username: '', password: '' };
}

function createTokenForm(credentialMode: 'session' | 'apikey' = 'session') {
  return {
    siteId: 0,
    username: '',
    accessToken: '',
    platformUserId: '',
    refreshToken: '',
    tokenExpiresAt: '',
    credentialMode,
    skipModelFetch: false,
  };
}

function createRebindForm(platformUserId = '') {
  return { accessToken: '', platformUserId, refreshToken: '', tokenExpiresAt: '' };
}

function resolveConnectionsSegment(search: string): ConnectionsSegment {
  const rawSegment = new URLSearchParams(search).get('segment');
  if (rawSegment === 'apikey' || rawSegment === 'tokens') return rawSegment;
  return 'session';
}

export default function Accounts() {
  const location = useLocation();
  const navigate = useNavigate();
  const activeSegment = useMemo(() => resolveConnectionsSegment(location.search), [location.search]);
  const [accounts, setAccounts] = useState<any[]>([]);
  const [sites, setSites] = useState<any[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [sortMode, setSortMode] = useState<SortMode>('custom');
  const [highlightAccountId, setHighlightAccountId] = useState<number | null>(null);
  const [expandedAccountIds, setExpandedAccountIds] = useState<number[]>([]);
  const isMobile = useIsMobile();
  const [showMobileTools, setShowMobileTools] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [addMode, setAddMode] = useState<'token' | 'login'>('token');
  const [loginForm, setLoginForm] = useState(createLoginForm);
  const [tokenForm, setTokenForm] = useState(() => createTokenForm('session'));
  const [createIntentPresetId, setCreateIntentPresetId] = useState<string | null>(null);
  const [applyCreatePresetModels, setApplyCreatePresetModels] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [verifying, setVerifying] = useState(false);
  const [saving, setSaving] = useState(false);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [embeddedTokenActions, setEmbeddedTokenActions] = useState<React.ReactNode>(null);
  const [selectedAccountIds, setSelectedAccountIds] = useState<number[]>([]);
  const [batchActionLoading, setBatchActionLoading] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<null | {
    mode: 'single' | 'batch';
    accountId?: number;
    accountName?: string;
    count?: number;
  }>(null);
  const [editingAccount, setEditingAccount] = useState<any | null>(null);
  const [editForm, setEditForm] = useState({
    username: '',
    status: 'active',
    checkinEnabled: true,
    unitCost: '',
    accessToken: '',
    apiToken: '',
    isPinned: false,
    refreshToken: '',
    tokenExpiresAt: '',
    proxyUrl: '',
  });
  const [savingEdit, setSavingEdit] = useState(false);
  const [rebindTarget, setRebindTarget] = useState<any | null>(null);
  const [rebindForm, setRebindForm] = useState(() => createRebindForm());
  const [rebindVerifyResult, setRebindVerifyResult] = useState<any>(null);
  const [rebindVerifying, setRebindVerifying] = useState(false);
  const [rebindSaving, setRebindSaving] = useState(false);
  const [modelModal, setModelModal] = useState<{
    open: boolean;
    account: any | null;
    models: Array<{ name: string; latencyMs: number | null; disabled: boolean; isManual?: boolean }>;
    pendingDisabled: Set<string>;
    loading: boolean;
    saving: boolean;
    siteName: string;
    manualModelsInput: string;
    addingManualModels: boolean;
  }>({
    open: false,
    account: null,
    models: [],
    pendingDisabled: new Set(),
    loading: false,
    saving: false,
    siteName: '',
    manualModelsInput: '',
    addingManualModels: false,
  });
  const rowRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastRebindTargetRef = useRef<any | null>(null);
  const modelModalRequestSeqRef = useRef(0);
  const toast = useToast();
  if (rebindTarget) lastRebindTargetRef.current = rebindTarget;
  const activeRebindTarget = rebindTarget || lastRebindTargetRef.current;
  const isRebindSub2Api = ((activeRebindTarget?.site?.platform || '').toLowerCase() === 'sub2api');

  const load = async () => {
    const [accountsResult, sitesResult] = await Promise.allSettled([
      api.getAccounts(),
      api.getSites(),
    ]);
    if (accountsResult.status === 'fulfilled') {
      const nextAccounts = accountsResult.value || [];
      setAccounts(nextAccounts);
      setSelectedAccountIds((current) => current.filter((id) => nextAccounts.some((account: any) => account.id === id)));
    } else {
      const reason = (accountsResult as PromiseRejectedResult).reason as any;
      toast.error(reason?.message || '加载账号列表失败');
    }
    if (sitesResult.status === 'fulfilled') {
      setSites(sitesResult.value || []);
    }
    setLoaded(true);
  };
  useEffect(() => { void load(); }, []);

  const selectedTokenSite = useMemo(
    () => sites.find((item) => item.id === tokenForm.siteId) || null,
    [sites, tokenForm.siteId],
  );
  const siteSelectOptions = useMemo(
    () => [
      { value: '0', label: '选择站点' },
      ...sites.map((site: any) => ({
        value: String(site.id),
        label: `${site.name} (${site.platform})`,
        description: site.url || undefined,
      })),
    ],
    [sites],
  );
  const isSub2ApiSelected = (selectedTokenSite?.platform || '').toLowerCase() === 'sub2api';
  const activeAddCredentialMode = activeSegment === 'apikey' ? 'apikey' : 'session';
  const createIntentPreset = useMemo(
    () => getSiteInitializationPreset(createIntentPresetId),
    [createIntentPresetId],
  );

  const resetAddForms = (credentialMode: 'session' | 'apikey' = activeAddCredentialMode) => {
    setAddMode('token');
    setLoginForm(createLoginForm());
    setTokenForm(createTokenForm(credentialMode));
    setCreateIntentPresetId(null);
    setApplyCreatePresetModels(false);
    setVerifyResult(null);
  };

  const closeAddPanel = () => {
    setShowAdd(false);
    setVerifying(false);
    setSaving(false);
    resetAddForms();
  };

  const resolveAccountDisplayName = (account: any) => {
    const username = typeof account?.username === 'string' ? account.username.trim() : '';
    if (username) return username;
    return resolveAccountCredentialMode(account) === 'apikey' ? 'API Key 连接' : '未命名';
  };

  const sortedAccounts = useMemo(
    () => sortItemsForDisplay(accounts, sortMode, (account) => account.balance || 0),
    [accounts, sortMode],
  );
  const visibleAccounts = useMemo(() => {
    if (activeSegment === 'tokens') return [];
    return sortedAccounts.filter((account) => resolveAccountCredentialMode(account) === activeSegment);
  }, [activeSegment, sortedAccounts]);
  const allVisibleAccountsSelected = visibleAccounts.length > 0 && visibleAccounts.every((account) => selectedAccountIds.includes(account.id));
  const verifyFailureHint = buildVerifyFailureHint(verifyResult);
  const addAccountPrereqHint = buildAddAccountPrereqHint(verifyResult);

  const setSegment = (nextSegment: ConnectionsSegment) => {
    const params = new URLSearchParams(location.search);
    if (nextSegment === 'session') params.delete('segment');
    else params.set('segment', nextSegment);
    const nextSearch = params.toString();
    navigate(
      {
        pathname: location.pathname,
        search: nextSearch ? `?${nextSearch}` : '',
      },
      { replace: false },
    );
  };

  useEffect(() => {
    if (activeSegment !== 'tokens') return;
    closeAddPanel();
    if (rebindTarget) closeRebindPanel();
    setEditingAccount(null);
  }, [activeSegment]);

  useEffect(() => {
    if (activeSegment === 'tokens') return;
    setEmbeddedTokenActions(null);
  }, [activeSegment]);

  useEffect(() => {
    if (activeSegment === 'tokens' || !loaded) return;
    const params = new URLSearchParams(location.search);
    const shouldOpenCreate = isTruthyFlag(params.get('create'));
    const requestedSiteId = parsePositiveInt(params.get('siteId'));
    if (!shouldOpenCreate || !requestedSiteId) return;

    const credentialMode = activeSegment === 'apikey' ? 'apikey' : 'session';
    const initializationPreset = getSiteInitializationPreset(params.get('initPreset'));
    setShowAdd(true);
    setAddMode('token');
    setVerifyResult(null);
    setCreateIntentPresetId(initializationPreset?.id || null);
    setApplyCreatePresetModels(Boolean(initializationPreset?.recommendedModels?.length));
    setLoginForm(createLoginForm());
    setTokenForm({
      ...createTokenForm(credentialMode),
      siteId: requestedSiteId,
      skipModelFetch: credentialMode === 'apikey' && initializationPreset?.recommendedSkipModelFetch === true,
    });

    params.delete('create');
    params.delete('siteId');
    params.delete('from');
    params.delete('initPreset');
    const nextSearch = params.toString();
    navigate(
      {
        pathname: location.pathname,
        search: nextSearch ? `?${nextSearch}` : '',
      },
      { replace: true },
    );
  }, [activeSegment, loaded, location.pathname, location.search, navigate]);

  useEffect(() => {
    return () => {
      if (highlightTimerRef.current) {
        clearTimeout(highlightTimerRef.current);
      }
    };
  }, []);

  const handleLoginAdd = async () => {
    if (!loginForm.siteId || !loginForm.username || !loginForm.password) return;
    setSaving(true);
    try {
      const result = await api.loginAccount(loginForm);
      if (result.success) {
        closeAddPanel();
        const msg = result.apiTokenFound
          ? `账号 "${loginForm.username}" 已添加，API Key 已自动获取`
          : `账号 "${loginForm.username}" 已添加（未找到 API Key，请手动设置）`;
        toast.success(msg);
        load();
      } else {
        toast.error(result.message || '登录失败');
      }
    } catch (e: any) {
      toast.error(e.message || '登录请求失败');
    } finally {
      setSaving(false);
    }
  };

  const handleVerifyToken = async () => {
    if (!tokenForm.siteId || !tokenForm.accessToken) return;
    const credentialMode = activeSegment === 'apikey' ? 'apikey' : 'session';
    setVerifying(true);
    setVerifyResult(null);
    try {
      const result = await api.verifyToken({
        siteId: tokenForm.siteId,
        accessToken: tokenForm.accessToken,
        platformUserId: tokenForm.platformUserId ? parseInt(tokenForm.platformUserId) : undefined,
        credentialMode,
      });
      setVerifyResult(result);
      if (result.success) {
        if (result.tokenType === 'apikey') {
          toast.success(`API Key 验证成功（可用模型 ${result.modelCount || 0} 个）`);
        } else {
          toast.success(`Session 验证成功: ${result.userInfo?.username || '未知用户'}`);
        }
      } else {
        toast.error(normalizeVerifyFailureMessage(result.message || 'Token 无效'));
      }
    } catch (e: any) {
      toast.error(normalizeVerifyFailureMessage(e?.message));
      setVerifyResult({ success: false, message: e?.message });
    } finally {
      setVerifying(false);
    }
  };

  const handleTokenAdd = async () => {
    if (!tokenForm.siteId || !tokenForm.accessToken) return;
    if (!verifyResult?.success && !tokenForm.skipModelFetch) {
      toast.error('请先验证 Token 成功后再添加账号');
      return;
    }
    const credentialMode = activeSegment === 'apikey' ? 'apikey' : 'session';
    const initializationPreset = createIntentPreset;
    setSaving(true);
    try {
      const result = await api.addAccount({
        siteId: tokenForm.siteId,
        username: tokenForm.username.trim() || undefined,
        accessToken: tokenForm.accessToken,
        platformUserId: tokenForm.platformUserId ? parseInt(tokenForm.platformUserId) : undefined,
        refreshToken: isSub2ApiSelected && tokenForm.refreshToken.trim()
          ? tokenForm.refreshToken.trim()
          : undefined,
        tokenExpiresAt: isSub2ApiSelected && tokenForm.tokenExpiresAt.trim()
          ? Number.parseInt(tokenForm.tokenExpiresAt.trim(), 10)
          : undefined,
        credentialMode,
        skipModelFetch: tokenForm.skipModelFetch,
      });
      let seededRecommendedModels = false;
      const recommendedModels = initializationPreset?.recommendedModels || [];
      const createdAccountId = Number(result?.id) || 0;
      const shouldSeedRecommendedModels = (
        credentialMode === 'apikey'
        && tokenForm.skipModelFetch
        && applyCreatePresetModels
        && recommendedModels.length > 0
        && createdAccountId > 0
      );
      if (shouldSeedRecommendedModels) {
        try {
          await api.addAccountAvailableModels(createdAccountId, recommendedModels);
          seededRecommendedModels = true;
        } catch (seedErr: any) {
          toast.error(seedErr?.message || '连接已添加，但推荐模型补录失败');
        }
      }
      closeAddPanel();
      if (result.queued) {
        toast.info(result.message || '账号已添加，后台正在同步初始化信息。');
      } else if (result.tokenType === 'apikey') {
        toast.success('已添加为 API Key 账号（可用于代理转发）');
      } else {
        const parts: string[] = [];
        if (result.usernameDetected) parts.push('用户名已自动识别');
        if (result.apiTokenFound) parts.push('API Key 已自动获取');
        const extra = parts.length ? `（${parts.join('，')}）` : '';
        toast.success(`账号已添加${extra}`);
      }
      if (seededRecommendedModels) {
        toast.success(`已补入 ${recommendedModels.length} 个推荐模型并重建路由`);
      }
      load();
    } catch (e: any) {
      toast.error(e.message || '添加失败');
    } finally {
      setSaving(false);
    }
  };

  const withLoading = async (key: string, fn: () => Promise<any>, successMsg?: string) => {
    setActionLoading(s => ({ ...s, [key]: true }));
    try { await fn(); if (successMsg) toast.success(successMsg); }
    catch (e: any) { toast.error(e.message || '操作失败'); }
    finally {
      setActionLoading(s => ({ ...s, [key]: false }));
      void load();
    }
  };

  const formatModelSuccess = (refresh: any) => {
    const models = Array.isArray(refresh?.modelsPreview) ? refresh.modelsPreview : [];
    const count = Number.isFinite(refresh?.modelCount) ? refresh.modelCount : models.length;
    if (models.length === 0) return `已获取到模型（共 ${count} 个）`;
    const preview = models.slice(0, 6).join('、');
    const suffix = `（共 ${count} 个）`;
    return `已获取到模型：${preview}${suffix}`;
  };

  const formatModelFailure = (refresh: any, messageFallback?: string) => {
    const code = refresh?.errorCode;
    if (code === 'timeout') return '模型获取失败（请求超时）';
    if (code === 'unauthorized') return '模型获取失败，API Key 已无效';
    if (code === 'empty_models') return '模型获取失败：未获取到可用模型';
    return messageFallback || refresh?.errorMessage || '模型获取失败';
  };

  const handleCheckModels = async (accountId: number) => {
    const key = `models-${accountId}`;
    setActionLoading(s => ({ ...s, [key]: true }));
    try {
      const result = await api.checkModels(accountId);
      const refresh = result?.refresh;
      if (!refresh || refresh.status !== 'success') {
        toast.error(formatModelFailure(refresh, result?.message));
      } else {
        toast.success(formatModelSuccess(refresh));
      }
    } catch (e: any) {
      toast.error(e.message || '模型获取失败');
    } finally {
      setActionLoading(s => ({ ...s, [key]: false }));
      void load();
    }
  };

  const applyLoadedModelModal = (account: any, result: any) => {
    const models = Array.isArray(result?.models) ? result.models : [];
    const disabledSet = new Set<string>(models.filter((m: any) => m.disabled).map((m: any) => m.name as string));
    setModelModal(s => ({
      ...s,
      loading: false,
      models,
      pendingDisabled: disabledSet,
      siteName: result?.siteName || account.site?.name || s.siteName,
    }));
  };

  const loadModelModalModels = async (
    account: any,
    options: {
      refreshUpstream?: boolean;
      resetBeforeLoad?: boolean;
      closeOnError?: boolean;
      successMessage?: string | null;
      errorMessage?: string;
    } = {},
  ) => {
    const requestId = ++modelModalRequestSeqRef.current;
    setModelModal(s => ({
      ...s,
      open: true,
      account,
      loading: true,
      ...(options.resetBeforeLoad ? { models: [], pendingDisabled: new Set<string>(), siteName: '', manualModelsInput: '' } : {}),
    }));
    try {
      if (options.refreshUpstream) {
        await api.checkModels(account.id);
      }
      const result = await api.getAccountModels(account.id);
      if (modelModalRequestSeqRef.current !== requestId) return;
      applyLoadedModelModal(account, result);
      if (options.successMessage) {
        toast.success(options.successMessage);
      }
    } catch (e: any) {
      if (modelModalRequestSeqRef.current !== requestId) return;
      toast.error(e.message || options.errorMessage || '加载模型列表失败');
      setModelModal(s => (
        options.closeOnError
          ? { ...s, open: false, account: null, loading: false }
          : { ...s, loading: false }
      ));
    }
  };

  const openModelModal = async (account: any) => {
    await loadModelModalModels(account, {
      resetBeforeLoad: true,
      closeOnError: true,
      errorMessage: '加载模型列表失败',
    });
  };

  const closeModelModal = () => {
    modelModalRequestSeqRef.current += 1;
    setModelModal(s => ({ ...s, open: false, account: null, manualModelsInput: '', addingManualModels: false }));
  };

  const toggleModelDisabled = (modelName: string) => {
    setModelModal(s => {
      const next = new Set(s.pendingDisabled);
      if (next.has(modelName)) next.delete(modelName);
      else next.add(modelName);
      return { ...s, pendingDisabled: next };
    });
  };

  const saveModelDisabled = async () => {
    if (!modelModal.account) return;
    const siteId = modelModal.account.siteId;
    setModelModal(s => ({ ...s, saving: true }));
    try {
      await api.updateSiteDisabledModels(siteId, Array.from(modelModal.pendingDisabled));
      try {
        await api.rebuildRoutes(false, false);
        toast.success('模型禁用设置已保存，路由已重建');
      } catch {
        toast.error('模型禁用设置已保存，但路由重建失败，请手动刷新路由');
      }
      closeModelModal();
    } catch (e: any) {
      toast.error(e.message || '保存失败');
    } finally {
      setModelModal(s => ({ ...s, saving: false }));
    }
  };

  const handleAddManualModels = async () => {
    if (!modelModal.account || !modelModal.manualModelsInput.trim()) return;
    const modelsToAdd = modelModal.manualModelsInput.split(',').map((m) => m.trim()).filter(Boolean);
    if (modelsToAdd.length === 0) return;

    setModelModal(s => ({ ...s, addingManualModels: true }));
    try {
      const res = await api.addAccountAvailableModels(modelModal.account.id, modelsToAdd);
      if (res.success) {
        toast.success('模型已手动添加');
        setModelModal(s => ({ ...s, manualModelsInput: '' }));
        await loadModelModalModels(modelModal.account, { refreshUpstream: false });
      } else {
        toast.error(res.message || '手动添加模型失败');
      }
    } catch (e: any) {
      toast.error(e.message || '手动添加模型失败');
    } finally {
      setModelModal(s => ({ ...s, addingManualModels: false }));
    }
  };


  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '10px 14px', border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)', fontSize: 13, outline: 'none',
    background: 'var(--color-bg)', color: 'var(--color-text-primary)',
  };

  const runtimeHealthMap: Record<string, {
    label: string;
    cls: string;
    dotClass: string;
    pulse: boolean;
  }> = {
    healthy: { label: '健康', cls: 'badge-success', dotClass: 'status-dot-success', pulse: true },
    unhealthy: { label: '异常', cls: 'badge-error', dotClass: 'status-dot-error', pulse: true },
    degraded: { label: '降级', cls: 'badge-warning', dotClass: 'status-dot-pending', pulse: true },
    disabled: { label: '已禁用', cls: 'badge-muted', dotClass: 'status-dot-muted', pulse: false },
    unknown: { label: '未知', cls: 'badge-muted', dotClass: 'status-dot-pending', pulse: false },
  };

  const resolveRuntimeHealth = (account: any) => {
    const capabilities = resolveAccountCapabilities(account);
    const fallbackState = account.status === 'disabled' || account.site?.status === 'disabled'
      ? 'disabled'
      : (!capabilities.proxyOnly && account.status === 'expired' ? 'unhealthy' : 'unknown');
    const state = account.runtimeHealth?.state || fallbackState;
    const cfg = runtimeHealthMap[state] || runtimeHealthMap.unknown;
    const reason = account.runtimeHealth?.reason
      || (state === 'disabled'
        ? '账号或站点已禁用'
        : (state === 'unhealthy' ? '最近健康检查失败' : '尚未获取运行健康信息'));
    return { state, reason, ...cfg };
  };

  const resolveAccountCapabilities = (account: any) => {
    const fromServer = account?.capabilities;
    if (fromServer && typeof fromServer === 'object') {
      return {
        canCheckin: !!fromServer.canCheckin,
        canRefreshBalance: !!fromServer.canRefreshBalance,
        proxyOnly: !!fromServer.proxyOnly,
      };
    }
    const hasSession = typeof account?.accessToken === 'string' && account.accessToken.trim().length > 0;
    return {
      canCheckin: hasSession,
      canRefreshBalance: hasSession,
      proxyOnly: !hasSession,
    };
  };

  const handleRefreshRuntimeHealth = async () => {
    setActionLoading((s) => ({ ...s, 'health-refresh': true }));
    try {
      const res = await api.refreshAccountHealth();
      if (res?.queued) {
        toast.info(res.message || '账号状态刷新任务已提交，完成后会自动更新。');
      } else {
        toast.success(res?.message || '账号状态已刷新');
      }
      load();
    } catch (e: any) {
      toast.error(e.message || '刷新账号状态失败');
    } finally {
      setActionLoading((s) => ({ ...s, 'health-refresh': false }));
    }
  };

  const handleToggleCheckin = async (account: any) => {
    const key = `checkin-toggle-${account.id}`;
    const nextEnabled = !account.checkinEnabled;
    setActionLoading((s) => ({ ...s, [key]: true }));
    try {
      await api.updateAccount(account.id, { checkinEnabled: nextEnabled });
      toast.success(nextEnabled ? '已开启签到' : '已关闭签到（全部签到会忽略此账号）');
      load();
    } catch (e: any) {
      toast.error(e.message || '切换签到状态失败');
    } finally {
      setActionLoading((s) => ({ ...s, [key]: false }));
    }
  };

  const handleTogglePin = async (account: any) => {
    const key = `pin-toggle-${account.id}`;
    const nextPinned = !account.isPinned;
    setActionLoading((s) => ({ ...s, [key]: true }));
    try {
      await api.updateAccount(account.id, { isPinned: nextPinned });
      toast.success(nextPinned ? '账号已置顶' : '账号已取消置顶');
      load();
    } catch (e: any) {
      toast.error(e.message || '切换账号置顶失败');
    } finally {
      setActionLoading((s) => ({ ...s, [key]: false }));
    }
  };

  const handleMoveCustomOrder = async (account: any, direction: 'up' | 'down') => {
    const key = `reorder-${account.id}`;
    const updates = buildCustomReorderUpdates(accounts, account.id, direction);
    if (updates.length === 0) return;

    setActionLoading((s) => ({ ...s, [key]: true }));
    try {
      await Promise.all(updates.map((update) => api.updateAccount(update.id, { sortOrder: update.sortOrder })));
      load();
    } catch (e: any) {
      toast.error(e.message || '更新账号排序失败');
    } finally {
      setActionLoading((s) => ({ ...s, [key]: false }));
    }
  };

  const parseAccountExtraConfig = (account: any): Record<string, any> => {
    try { return JSON.parse(account?.extraConfig || '{}') || {}; }
    catch { return {}; }
  };

  const extractManagedSub2ApiAuth = (account: any) => {
    const parsed = parseAccountExtraConfig(account);
    const auth = parsed?.sub2apiAuth || {};
    return {
      refreshToken: typeof auth.refreshToken === 'string' ? auth.refreshToken : '',
      tokenExpiresAt: auth.tokenExpiresAt ? String(auth.tokenExpiresAt) : '',
    };
  };

  const openEditPanel = (account: any) => {
    const managedAuth = extractManagedSub2ApiAuth(account);
    const proxyUrl = parseAccountExtraConfig(account)?.proxyUrl || '';
    closeAddPanel();
    setRebindTarget(null);
    setEditingAccount(account);
    setEditForm({
      username: account?.username || '',
      status: account?.status || 'active',
      checkinEnabled: account?.checkinEnabled !== false,
      unitCost: account?.unitCost === null || account?.unitCost === undefined ? '' : String(account.unitCost),
      accessToken: account?.accessToken || '',
      apiToken: account?.apiToken || '',
      isPinned: !!account?.isPinned,
      refreshToken: managedAuth.refreshToken,
      tokenExpiresAt: managedAuth.tokenExpiresAt,
      proxyUrl,
    });
  };

  const closeEditPanel = () => {
    setEditingAccount(null);
    setSavingEdit(false);
  };

  const saveEditPanel = async () => {
    if (!editingAccount) return;
    setSavingEdit(true);
    try {
      await api.updateAccount(editingAccount.id, {
        username: editForm.username.trim() || undefined,
        status: editForm.status,
        checkinEnabled: editForm.checkinEnabled,
        unitCost: editForm.unitCost.trim() ? Number(editForm.unitCost.trim()) : null,
        accessToken: editForm.accessToken.trim(),
        apiToken: editForm.apiToken.trim() || null,
        isPinned: editForm.isPinned,
        refreshToken: editForm.refreshToken.trim() || null,
        tokenExpiresAt: editForm.tokenExpiresAt.trim() ? Number.parseInt(editForm.tokenExpiresAt.trim(), 10) : null,
        proxyUrl: editForm.proxyUrl.trim() || null,
      });
      toast.success('账号已更新');
      closeEditPanel();
      load();
    } catch (e: any) {
      toast.error(e.message || '更新账号失败');
    } finally {
      setSavingEdit(false);
    }
  };

  const toggleAccountSelection = (accountId: number, checked: boolean) => {
    setSelectedAccountIds((current) => (
      checked
        ? Array.from(new Set([...current, accountId]))
        : current.filter((id) => id !== accountId)
    ));
  };

  const toggleSelectAllVisibleAccounts = (checked: boolean) => {
    if (!checked) {
      setSelectedAccountIds((current) => current.filter((id) => !visibleAccounts.some((account) => account.id === id)));
      return;
    }
    setSelectedAccountIds((current) => Array.from(new Set([...current, ...visibleAccounts.map((account) => account.id)])));
  };

  const toggleAccountDetails = (accountId: number) => {
    setExpandedAccountIds((current) => (
      current.includes(accountId)
        ? current.filter((id) => id !== accountId)
        : [...current, accountId]
    ));
  };

  const runBatchAccountAction = async (action: 'enable' | 'disable' | 'delete' | 'refreshBalance', skipDeleteConfirm = false) => {
    if (selectedAccountIds.length === 0) return;
    if (action === 'delete' && !skipDeleteConfirm) {
      setDeleteConfirm({ mode: 'batch', count: selectedAccountIds.length });
      return;
    }

    setBatchActionLoading(true);
    try {
      const result = await api.batchUpdateAccounts({
        ids: selectedAccountIds,
        action,
      });
      const successIds = Array.isArray(result?.successIds) ? result.successIds.map((id: unknown) => Number(id)) : [];
      const failedItems = Array.isArray(result?.failedItems) ? result.failedItems : [];
      if (failedItems.length > 0) {
        toast.info(`批量操作完成：成功 ${successIds.length}，失败 ${failedItems.length}`);
      } else {
        toast.success(`批量操作完成：成功 ${successIds.length}`);
      }
      setSelectedAccountIds(failedItems.map((item: any) => Number(item.id)).filter((id: number) => Number.isFinite(id) && id > 0));
      load();
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
    if (target.mode === 'single' && target.accountId) {
      await withLoading(`delete-${target.accountId}`, () => api.deleteAccount(target.accountId!), '已删除');
      return;
    }

    await runBatchAccountAction('delete', true);
  };

  const handleAccountRowClick = (accountId: number, event: React.MouseEvent<HTMLTableRowElement>) => {
    if (shouldIgnoreRowSelectionClick(event.target)) return;
    const isSelected = selectedAccountIds.includes(accountId);
    toggleAccountSelection(accountId, !isSelected);
  };

  const extractPlatformUserId = (account: any): string => {
    const parsed = parseAccountExtraConfig(account);
    const raw = parsed?.platformUserId;
    const value = Number.parseInt(String(raw ?? ''), 10);
    if (Number.isFinite(value) && value > 0) return String(value);
    const guessed = Number.parseInt(String(account?.username || '').match(/(\d{3,8})$/)?.[1] || '', 10);
    return Number.isFinite(guessed) && guessed > 0 ? String(guessed) : '';
  };

  const openRebindPanel = (account: any) => {
    closeAddPanel();
    setEditingAccount(null);
    setRebindTarget(account);
    setRebindForm(createRebindForm(extractPlatformUserId(account)));
    setRebindVerifyResult(null);
  };

  const closeRebindPanel = () => {
    setRebindTarget(null);
    setRebindForm(createRebindForm());
    setRebindVerifyResult(null);
    setRebindVerifying(false);
    setRebindSaving(false);
  };

  const handleVerifyRebindToken = async () => {
    if (!rebindTarget || !rebindForm.accessToken.trim()) return;
    setRebindVerifying(true);
    setRebindVerifyResult(null);
    try {
      const result = await api.verifyToken({
        siteId: rebindTarget.siteId,
        accessToken: rebindForm.accessToken.trim(),
        platformUserId: rebindForm.platformUserId ? Number.parseInt(rebindForm.platformUserId, 10) : undefined,
        credentialMode: 'session',
      });
      setRebindVerifyResult(result);
      if (result.success && result.tokenType === 'session') {
        toast.success('Session Token 验证成功，可以重新绑定');
      } else if (result.success && result.tokenType !== 'session') {
        toast.error('当前是 API Key，不是 Session Token');
      } else {
        toast.error(normalizeVerifyFailureMessage(result.message || 'Token 无效'));
      }
    } catch (e: any) {
      toast.error(normalizeVerifyFailureMessage(e?.message));
      setRebindVerifyResult({ success: false, message: e?.message });
    } finally {
      setRebindVerifying(false);
    }
  };

  const handleSubmitRebind = async () => {
    if (!rebindTarget || !rebindForm.accessToken.trim()) return;
    if (!(rebindVerifyResult?.success && rebindVerifyResult?.tokenType === 'session')) {
      toast.error('请先验证新的 Session Token 成功');
      return;
    }
    const isSub2ApiRebindTarget = ((rebindTarget?.site?.platform || '').toLowerCase() === 'sub2api');
    setRebindSaving(true);
    try {
      await api.rebindAccountSession(rebindTarget.id, {
        accessToken: rebindForm.accessToken.trim(),
        platformUserId: rebindForm.platformUserId ? Number.parseInt(rebindForm.platformUserId, 10) : undefined,
        refreshToken: isSub2ApiRebindTarget && rebindForm.refreshToken.trim()
          ? rebindForm.refreshToken.trim()
          : undefined,
        tokenExpiresAt: isSub2ApiRebindTarget && rebindForm.tokenExpiresAt.trim()
          ? Number.parseInt(rebindForm.tokenExpiresAt, 10)
          : undefined,
      });
      toast.success('账号重新绑定成功，状态已恢复');
      closeRebindPanel();
      load();
    } catch (e: any) {
      toast.error(e.message || '重新绑定失败');
    } finally {
      setRebindSaving(false);
    }
  };

  useEffect(() => {
    const { accountId, openRebind } = readFocusAccountIntent(location.search);
    if (!accountId || !loaded || activeSegment === 'tokens') return;

    const target = visibleAccounts.find((account) => account.id === accountId);
    const row = rowRefs.current.get(accountId);
    const cleanedSearch = clearFocusParams(location.search);
    if (!target || !row) {
      navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
      return;
    }

    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setHighlightAccountId(accountId);
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => {
      setHighlightAccountId((current) => (current === accountId ? null : current));
    }, 2200);

    if (openRebind && target.status === 'expired' && !resolveAccountCapabilities(target).proxyOnly) {
      setShowAdd(false);
      if (!rebindTarget || rebindTarget.id !== target.id) {
        openRebindPanel(target);
      }
    }

    navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
  }, [activeSegment, loaded, location.pathname, location.search, navigate, openRebindPanel, rebindTarget, visibleAccounts]);

  const canAddVerifiedConnection = Boolean(
    verifyResult?.success
    && (
      (activeSegment === 'apikey' && verifyResult.tokenType === 'apikey')
      || (activeSegment === 'session' && verifyResult.tokenType === 'session')
    ),
  );

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">{tr('连接管理')}</h2>
        {activeSegment !== 'tokens' && (
          <div className="page-actions accounts-page-actions">
            {isMobile ? (
              <>
                <button
                  type="button"
                  onClick={() => setShowMobileTools(true)}
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                >
                  排序与操作
                </button>
                <button
                  type="button"
                  data-testid="accounts-mobile-select-all"
                  onClick={() => toggleSelectAllVisibleAccounts(!allVisibleAccountsSelected)}
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                >
                  {allVisibleAccountsSelected ? '取消全选' : '全选可见项'}
                </button>
              </>
            ) : (
              <>
                <div className="accounts-sort-select" style={{ minWidth: 156, position: 'relative', zIndex: 20 }}>
                  <ModernSelect
                    size="sm"
                    value={sortMode}
                    onChange={(nextValue) => setSortMode(nextValue as SortMode)}
                    options={[
                      { value: 'custom', label: '自定义排序' },
                      { value: 'balance-desc', label: '余额高到低' },
                      { value: 'balance-asc', label: '余额低到高' },
                    ]}
                    placeholder="自定义排序"
                  />
                </div>
                {activeSegment === 'session' && (
                  <button
                    onClick={() => withLoading('checkin-all', () => api.triggerCheckinAll(), '已触发全部签到')}
                    disabled={actionLoading['checkin-all']}
                    className="btn btn-soft-primary"
                  >
                    {actionLoading['checkin-all'] ? <><span className="spinner spinner-sm" />{tr('签到中...')}</> : tr('全部签到')}
                  </button>
                )}
                <button
                  onClick={handleRefreshRuntimeHealth}
                  disabled={actionLoading['health-refresh']}
                  className="btn btn-soft-primary"
                >
                  {actionLoading['health-refresh'] ? <><span className="spinner spinner-sm" />{tr('刷新状态中...')}</> : tr('刷新账户状态')}
                </button>
              </>
            )}
            <button
              onClick={() => {
                const nextOpen = !showAdd;
                if (!nextOpen) {
                  closeAddPanel();
                  return;
                }
                setEditingAccount(null);
                closeRebindPanel();
                setShowAdd(true);
                resetAddForms(activeAddCredentialMode);
              }}
              className="btn btn-primary"
            >
              {showAdd ? tr('取消') : tr('+ 添加连接')}
            </button>
          </div>
        )}
        {activeSegment === 'tokens' && embeddedTokenActions}
      </div>

      <ResponsiveFilterPanel
        isMobile={isMobile}
        mobileOpen={showMobileTools}
        onMobileClose={() => setShowMobileTools(false)}
        mobileTitle="连接排序与操作"
        mobileContent={(
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>排序方式</div>
              <ModernSelect
                value={sortMode}
                onChange={(nextValue) => setSortMode(nextValue as SortMode)}
                options={[
                  { value: 'custom', label: '自定义排序' },
                  { value: 'balance-desc', label: '余额高到低' },
                  { value: 'balance-asc', label: '余额低到高' },
                ]}
                placeholder="自定义排序"
              />
            </div>
            {activeSegment === 'session' && (
              <button
                onClick={async () => {
                  setShowMobileTools(false);
                  await withLoading('checkin-all', () => api.triggerCheckinAll(), '已触发全部签到');
                }}
                disabled={actionLoading['checkin-all']}
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)' }}
              >
                {actionLoading['checkin-all'] ? <><span className="spinner spinner-sm" />{tr('签到中...')}</> : tr('全部签到')}
              </button>
            )}
            <button
              onClick={async () => {
                setShowMobileTools(false);
                await handleRefreshRuntimeHealth();
              }}
              disabled={actionLoading['health-refresh']}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {actionLoading['health-refresh'] ? <><span className="spinner spinner-sm" />{tr('刷新状态中...')}</> : tr('刷新账户状态')}
            </button>
          </div>
        )}
      />

      <div
        style={{
          display: 'inline-flex',
          gap: 4,
          padding: 4,
          marginBottom: 16,
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border-light)',
          borderRadius: 'var(--radius-md)',
        }}
      >
        {ACCOUNT_SEGMENTS.map((segment) => (
          <button
            key={segment.value}
            type="button"
            onClick={() => setSegment(segment.value)}
            data-tooltip={segment.tooltip}
            data-tooltip-side={segment.tooltipSide}
            data-tooltip-align={segment.tooltipAlign}
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              border: 'none',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: activeSegment === segment.value ? 'var(--color-bg)' : 'transparent',
              color: activeSegment === segment.value ? 'var(--color-primary)' : 'var(--color-text-secondary)',
              boxShadow: activeSegment === segment.value ? 'var(--shadow-sm)' : 'none',
              transition: 'all 0.2s ease',
            }}
          >
            {segment.label}
          </button>
        ))}
      </div>

      <DeleteConfirmModal
        open={Boolean(deleteConfirm)}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={confirmDelete}
        title="确认删除连接"
        confirmText="确认删除"
        loading={batchActionLoading || (deleteConfirm?.mode === 'single' && !!actionLoading[`delete-${deleteConfirm?.accountId}`])}
        description={deleteConfirm?.mode === 'single'
          ? <>确定要删除连接 <strong>{deleteConfirm.accountName || `#${deleteConfirm.accountId}`}</strong> 吗？</>
          : <>确定要删除选中的 <strong>{deleteConfirm?.count || 0}</strong> 个连接吗？</>}
      />

      {activeSegment !== 'tokens' && selectedAccountIds.length > 0 && (
        <ResponsiveBatchActionBar
          isMobile={isMobile}
          info={`已选 ${selectedAccountIds.length} 项`}
          desktopStyle={{ marginBottom: 12 }}
        >
          <button data-testid="accounts-batch-refresh-balance" onClick={() => runBatchAccountAction('refreshBalance')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量刷新余额
          </button>
          <button onClick={() => runBatchAccountAction('enable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量启用
          </button>
          <button onClick={() => runBatchAccountAction('disable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量禁用
          </button>
          <button onClick={() => runBatchAccountAction('delete')} disabled={batchActionLoading} className="btn btn-link btn-link-danger">
            批量删除
          </button>
        </ResponsiveBatchActionBar>
      )}

      {activeSegment === 'tokens' ? (
        <TokensPanel embedded onEmbeddedActionsChange={setEmbeddedTokenActions} />
      ) : (
        <>
          <CenteredModal
            open={showAdd}
            onClose={closeAddPanel}
            title={activeSegment === 'apikey' ? '添加 API Key 连接' : (addMode === 'login' ? '账号密码登录' : '添加 Session 连接')}
            maxWidth={860}
            bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
            footer={<button onClick={closeAddPanel} className="btn btn-ghost">取消</button>}
          >
            {activeSegment === 'session' ? (
              <>
                <div style={{ display: 'flex', gap: 0, background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', padding: 3, marginBottom: 16 }}>
                  <button
                    onClick={() => { setAddMode('token'); setVerifyResult(null); }}
                    style={{
                      flex: 1,
                      padding: '8px 0',
                      borderRadius: 6,
                      fontSize: 13,
                      fontWeight: 500,
                      border: 'none',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      background: addMode === 'token' ? 'var(--color-bg-card)' : 'transparent',
                      color: addMode === 'token' ? 'var(--color-primary)' : 'var(--color-text-muted)',
                      boxShadow: addMode === 'token' ? 'var(--shadow-sm)' : 'none',
                    }}
                  >
                    Session Token / Cookie
                  </button>
                  <button
                    onClick={() => { setAddMode('login'); setVerifyResult(null); }}
                    style={{
                      flex: 1,
                      padding: '8px 0',
                      borderRadius: 6,
                      fontSize: 13,
                      fontWeight: 500,
                      border: 'none',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      background: addMode === 'login' ? 'var(--color-bg-card)' : 'transparent',
                      color: addMode === 'login' ? 'var(--color-primary)' : 'var(--color-text-muted)',
                      boxShadow: addMode === 'login' ? 'var(--shadow-sm)' : 'none',
                    }}
                  >
                    账号密码登录
                  </button>
                </div>

                {addMode === 'token' ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div className="info-tip">
                      <div>
                        <div style={{ fontWeight: 600, marginBottom: 4 }}>当前分段仅创建 Session 连接</div>
                        <div><strong>推荐</strong> 使用系统访问令牌（Access Token）；浏览器 Cookie 仅用于兼容场景。</div>
                        <div style={{ marginTop: 2 }}>以 NewAPI 为例：控制台 → 个人设置 → 安全设置 → 生成「系统访问令牌」</div>
                        <div style={{ opacity: 0.7, borderTop: '1px solid rgba(0,0,0,0.1)', paddingTop: 6, marginTop: 6 }}>
                          获取 Cookie: <kbd style={{ padding: '1px 5px', background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 3, fontSize: 11 }}>F12</kbd> → Application → Cookie
                        </div>
                        <div style={{ marginTop: 6 }}>
                          <a
                            href={SITE_DOCS_URL}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontSize: 12, color: 'var(--color-primary)', textDecoration: 'underline' }}
                          >
                            查看认证方式与特殊站点说明文档
                          </a>
                        </div>
                      </div>
                    </div>
                    <ModernSelect
                      value={String(tokenForm.siteId || 0)}
                      onChange={(nextValue) => {
                        const nextSiteId = Number.parseInt(nextValue, 10) || 0;
                        setTokenForm((f) => ({ ...f, siteId: nextSiteId }));
                        setVerifyResult(null);
                      }}
                      options={siteSelectOptions}
                      placeholder="选择站点"
                      searchable
                      searchPlaceholder={SITE_SELECT_SEARCH_PLACEHOLDER}
                    />
                    <input
                      placeholder="连接名称（可选）"
                      value={tokenForm.username}
                      onChange={(e) => setTokenForm((f) => ({ ...f, username: e.target.value }))}
                      style={inputStyle}
                    />
                    <textarea
                      placeholder="粘贴 Session Access Token 或浏览器 Cookie"
                      value={tokenForm.accessToken}
                      onChange={(e) => { setTokenForm((f) => ({ ...f, accessToken: e.target.value.trim() })); setVerifyResult(null); }}
                      style={{ ...inputStyle, fontFamily: 'var(--font-mono)', height: 72, resize: 'none' as const }}
                    />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <input
                        placeholder="用户 ID（可选）"
                        value={tokenForm.platformUserId}
                        onChange={(e) => { setTokenForm((f) => ({ ...f, platformUserId: e.target.value.replace(/\D/g, '') })); setVerifyResult(null); }}
                        style={inputStyle}
                      />
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                        若站点要求 New-Api-User / User-ID，请在这里提前填写。
                      </div>
                    </div>
                    {isSub2ApiSelected && (
                      <>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <input
                            placeholder="Sub2API refresh_token（可选，用于托管自动续期）"
                            value={tokenForm.refreshToken}
                            onChange={(e) => setTokenForm((f) => ({ ...f, refreshToken: e.target.value.trim() }))}
                            style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                          />
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                            可在浏览器控制台执行 <code style={{ fontFamily: 'var(--font-mono)' }}>localStorage.getItem('refresh_token')</code> 获取。
                          </div>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                          <input
                            placeholder="token_expires_at（可选，毫秒时间戳）"
                            value={tokenForm.tokenExpiresAt}
                            onChange={(e) => setTokenForm((f) => ({ ...f, tokenExpiresAt: e.target.value.replace(/\D/g, '') }))}
                            style={inputStyle}
                          />
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                            配置 refresh_token 后，metapi 会在 JWT 临近过期或 401 时自动续期并回写新 token。
                          </div>
                        </div>
                      </>
                    )}
                    {verifyResult && verifyResult.success && verifyResult.tokenType === 'session' && (
                      <div className="alert alert-success animate-scale-in">
                        <div className="alert-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                          Session 凭证有效（Access Token / Cookie）
                        </div>
                        <div style={{ fontSize: 12, lineHeight: 1.8 }}>
                          <div>用户名: <strong>{verifyResult.userInfo?.username || '未知'}</strong></div>
                          {verifyResult.balance && <div>余额: <strong>${(verifyResult.balance.balance || 0).toFixed(2)}</strong></div>}
                          <div>API Key: <span style={{ fontWeight: 500, color: verifyResult.apiToken ? 'var(--color-success)' : 'var(--color-text-muted)' }}>
                            {verifyResult.apiToken ? `已找到 (${verifyResult.apiToken.substring(0, 8)}...)` : '未找到'}
                          </span></div>
                        </div>
                      </div>
                    )}
                    {verifyResult && verifyResult.success && verifyResult.tokenType === 'apikey' && (
                      <div className="alert alert-warning animate-scale-in">
                        <div className="alert-title">当前分段仅接受 Session 凭证，请切到「API Key 连接」分段创建。</div>
                      </div>
                    )}
                    {verifyResult && !verifyResult.success && verifyResult.needsUserId && (
                      <div className="alert alert-warning animate-scale-in">
                        <div className="alert-title">此站点要求用户 ID，请补充后重新验证</div>
                      </div>
                    )}
                    {verifyResult && !verifyResult.success && !verifyResult.needsUserId && (
                      <div className="alert alert-error animate-scale-in">
                        <div className="alert-title">
                          {normalizeVerifyFailureMessage(verifyResult.message) || 'Token 无效或已过期'}
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                          {verifyFailureHint || '请检查 Token 是否正确'}
                        </div>
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button
                        onClick={handleVerifyToken}
                        disabled={verifying || !tokenForm.siteId || !tokenForm.accessToken}
                        className="btn btn-ghost"
                        style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
                      >
                        {verifying ? <><span className="spinner spinner-sm" />验证中...</> : '验证 Token'}
                      </button>
                      <button
                        onClick={handleTokenAdd}
                        disabled={saving || !tokenForm.siteId || !tokenForm.accessToken || !canAddVerifiedConnection}
                        className="btn btn-success"
                      >
                        {saving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} />添加中...</> : '添加连接'}
                      </button>
                    </div>
                    {!verifyResult?.success && (
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                        {addAccountPrereqHint}
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div className="info-tip">
                      输入目标站点的账号密码，将自动登录并获取访问令牌和 API Key
                    </div>
                    <ModernSelect
                      value={String(loginForm.siteId || 0)}
                      onChange={(nextValue) => {
                        const nextSiteId = Number.parseInt(nextValue, 10) || 0;
                        setLoginForm((f) => ({ ...f, siteId: nextSiteId }));
                      }}
                      options={siteSelectOptions}
                      placeholder="选择站点"
                      searchable
                      searchPlaceholder={SITE_SELECT_SEARCH_PLACEHOLDER}
                    />
                    <input placeholder="用户名" value={loginForm.username} onChange={(e) => setLoginForm((f) => ({ ...f, username: e.target.value }))} style={inputStyle} />
                    <input type="password" placeholder="密码" value={loginForm.password} onChange={(e) => setLoginForm((f) => ({ ...f, password: e.target.value }))} onKeyDown={(e) => e.key === 'Enter' && handleLoginAdd()} style={inputStyle} />
                    <button onClick={handleLoginAdd} disabled={saving || !loginForm.siteId || !loginForm.username || !loginForm.password} className="btn btn-success" style={{ alignSelf: 'flex-start' }}>
                      {saving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} />登录并添加...</> : '登录并添加'}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="info-tip">
                  API Key 连接只用于代理转发，不会自动派生账号令牌。系统会按站点平台能力自动引导到 Session 或 API Key 创建流程。
                </div>
                {createIntentPreset && (
                  <div className="alert alert-info animate-scale-in">
                    <div className="alert-title">{createIntentPreset.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4, lineHeight: 1.8 }}>
                      <div>{createIntentPreset.description}</div>
                      <div>推荐模型：{createIntentPreset.recommendedModels.join(' / ')}</div>
                      {createIntentPreset.recommendedSkipModelFetch && (
                        <div>建议直接跳过模型验证，先保存 Base URL + Key，再补入推荐模型完成初始化。</div>
                      )}
                    </div>
                    {createIntentPreset.recommendedModels.length > 0 && (
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer', marginTop: 8 }}>
                        <input
                          type="checkbox"
                          checked={applyCreatePresetModels}
                          onChange={(e) => setApplyCreatePresetModels(e.target.checked)}
                          style={{ width: 14, height: 14 }}
                        />
                        <span>添加后自动补入推荐模型并重建路由</span>
                      </label>
                    )}
                  </div>
                )}
                <ModernSelect
                  value={String(tokenForm.siteId || 0)}
                  onChange={(nextValue) => {
                    const nextSiteId = Number.parseInt(nextValue, 10) || 0;
                    setTokenForm((f) => ({ ...f, siteId: nextSiteId, credentialMode: 'apikey' }));
                    setVerifyResult(null);
                    if (createIntentPresetId && nextSiteId !== tokenForm.siteId) {
                      setCreateIntentPresetId(null);
                      setApplyCreatePresetModels(false);
                    }
                  }}
                  options={siteSelectOptions}
                  placeholder="选择站点"
                  searchable
                  searchPlaceholder={SITE_SELECT_SEARCH_PLACEHOLDER}
                />
                <input
                  placeholder="连接名称（可选）"
                  value={tokenForm.username}
                  onChange={(e) => setTokenForm((f) => ({ ...f, username: e.target.value, credentialMode: 'apikey' }))}
                  style={inputStyle}
                />
                <textarea
                  placeholder="粘贴 API Key"
                  value={tokenForm.accessToken}
                  onChange={(e) => { setTokenForm((f) => ({ ...f, accessToken: e.target.value.trim(), credentialMode: 'apikey' })); setVerifyResult(null); }}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)', height: 72, resize: 'none' as const }}
                />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <input
                    placeholder="用户 ID（可选）"
                    value={tokenForm.platformUserId}
                    onChange={(e) => { setTokenForm((f) => ({ ...f, platformUserId: e.target.value.replace(/\D/g, ''), credentialMode: 'apikey' })); setVerifyResult(null); }}
                    style={inputStyle}
                  />
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                    若站点要求 New-Api-User / User-ID，请在这里提前填写。
                  </div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer', alignSelf: 'flex-start' }}>
                  <input
                    type="checkbox"
                    checked={!!tokenForm.skipModelFetch}
                    onChange={(e) => setTokenForm((f) => ({ ...f, skipModelFetch: e.target.checked }))}
                    style={{ width: 14, height: 14 }}
                  />
                  <span>跳过模型验证（直接添加 API Key）</span>
                </label>
                {verifyResult && verifyResult.success && verifyResult.tokenType === 'apikey' && (
                  <div className="alert alert-info animate-scale-in">
                    <div className="alert-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
                      API Key 验证成功
                    </div>
                    <div style={{ fontSize: 12, lineHeight: 1.8 }}>
                      <div>可用模型: <strong>{verifyResult.modelCount} 个</strong></div>
                      {verifyResult.models && <div style={{ color: 'var(--color-text-muted)' }}>包含: {verifyResult.models.join(', ')}{verifyResult.modelCount > 10 ? ' ...' : ''}</div>}
                    </div>
                  </div>
                )}
                {verifyResult && verifyResult.success && verifyResult.tokenType === 'session' && (
                  <div className="alert alert-warning animate-scale-in">
                    <div className="alert-title">当前分段仅接受 API Key，请切到「Session 连接」分段创建。</div>
                  </div>
                )}
                {verifyResult && !verifyResult.success && verifyResult.needsUserId && (
                  <div className="alert alert-warning animate-scale-in">
                    <div className="alert-title">此站点要求用户 ID，请补充后重新验证</div>
                  </div>
                )}
                {verifyResult && !verifyResult.success && !verifyResult.needsUserId && (
                  <div className="alert alert-error animate-scale-in">
                    <div className="alert-title">
                      {normalizeVerifyFailureMessage(verifyResult.message) || 'Token 无效或已过期'}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                      {verifyFailureHint || '请检查 Token 是否正确'}
                    </div>
                  </div>
                )}
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    onClick={handleVerifyToken}
                    disabled={verifying || !tokenForm.siteId || !tokenForm.accessToken}
                    className="btn btn-ghost"
                    style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
                  >
                    {verifying ? <><span className="spinner spinner-sm" />验证中...</> : '验证 API Key'}
                  </button>
                  <button
                    onClick={handleTokenAdd}
                    disabled={saving || !tokenForm.siteId || !tokenForm.accessToken || (!canAddVerifiedConnection && !tokenForm.skipModelFetch)}
                    className="btn btn-success"
                  >
                    {saving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} />添加中...</> : '添加连接'}
                  </button>
                </div>
                {!verifyResult?.success && (
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                    {addAccountPrereqHint}
                  </div>
                )}
              </div>
            )}
          </CenteredModal>

          {activeSegment === 'session' && (
            <CenteredModal
              open={Boolean(rebindTarget)}
              onClose={closeRebindPanel}
              title="重新绑定 Session Token"
              maxWidth={820}
              bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
              footer={<button onClick={closeRebindPanel} className="btn btn-ghost">取消</button>}
            >
              {activeRebindTarget ? (
                <>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
                    连接: {resolveAccountDisplayName(activeRebindTarget)} @ {activeRebindTarget.site?.name || '-'}。请粘贴新的 Session Token，验证成功后再绑定。
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 220px', gap: 10, marginBottom: 10 }}>
                    <textarea
                      placeholder="粘贴新的 Session Token"
                      value={rebindForm.accessToken}
                      onChange={(e) => {
                        setRebindForm((prev) => ({ ...prev, accessToken: e.target.value.trim() }));
                        setRebindVerifyResult(null);
                      }}
                      style={{ ...inputStyle, fontFamily: 'var(--font-mono)', height: 74, resize: 'none' as const }}
                    />
                    <input
                      placeholder="用户 ID（可选）"
                      value={rebindForm.platformUserId}
                      onChange={(e) => {
                        setRebindForm((prev) => ({ ...prev, platformUserId: e.target.value.replace(/\D/g, '') }));
                        setRebindVerifyResult(null);
                      }}
                      style={inputStyle}
                    />
                  </div>
                  {isRebindSub2Api && (
                    <>
                      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 220px', gap: 10, marginBottom: 4 }}>
                        <input
                          placeholder="Sub2API refresh_token（可选）"
                          value={rebindForm.refreshToken}
                          onChange={(e) => setRebindForm((prev) => ({ ...prev, refreshToken: e.target.value.trim() }))}
                          style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                        />
                        <input
                          placeholder="token_expires_at（可选）"
                          value={rebindForm.tokenExpiresAt}
                          onChange={(e) => setRebindForm((prev) => ({ ...prev, tokenExpiresAt: e.target.value.replace(/\D/g, '') }))}
                          style={inputStyle}
                        />
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
                        留空将保持原有 refresh_token 不变。配置后可用于托管自动续期。
                      </div>
                    </>
                  )}

                  {rebindVerifyResult && rebindVerifyResult.success && rebindVerifyResult.tokenType === 'session' && (
                    <div className="alert alert-success animate-scale-in" style={{ marginBottom: 10 }}>
                      <div className="alert-title">Session Token 有效</div>
                      <div style={{ fontSize: 12, marginTop: 4 }}>
                        用户: {rebindVerifyResult.userInfo?.username || '未知'}
                        {rebindVerifyResult.apiToken ? `，已识别 API Key (${String(rebindVerifyResult.apiToken).slice(0, 8)}...)` : ''}
                      </div>
                    </div>
                  )}
                  {rebindVerifyResult && (!rebindVerifyResult.success || rebindVerifyResult.tokenType !== 'session') && (
                    <div className="alert alert-error animate-scale-in" style={{ marginBottom: 10 }}>
                      <div className="alert-title">
                        {rebindVerifyResult.message || 'Token 无效或类型不正确'}
                      </div>
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      onClick={handleVerifyRebindToken}
                      disabled={rebindVerifying || !rebindForm.accessToken.trim()}
                      className="btn btn-ghost"
                      style={{ border: '1px solid var(--color-border)' }}
                    >
                      {rebindVerifying ? <><span className="spinner spinner-sm" />验证中...</> : '验证 Token'}
                    </button>
                    <button
                      onClick={handleSubmitRebind}
                      disabled={rebindSaving || !(rebindVerifyResult?.success && rebindVerifyResult?.tokenType === 'session')}
                      className="btn btn-success"
                    >
                      {rebindSaving
                        ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} />绑定中...</>
                        : '确认重新绑定'}
                    </button>
                  </div>
                </>
              ) : null}
            </CenteredModal>
          )}

          <CenteredModal
            open={Boolean(editingAccount)}
            onClose={closeEditPanel}
            title="编辑账号"
            maxWidth={860}
            bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
            footer={(
              <>
                <button onClick={closeEditPanel} className="btn btn-ghost">取消</button>
                <button onClick={saveEditPanel} disabled={savingEdit} className="btn btn-primary">
                  {savingEdit ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存修改'}
                </button>
              </>
            )}
          >
            {editingAccount ? (
              <ResponsiveFormGrid>
                <input
                  placeholder="账号名称"
                  value={editForm.username}
                  onChange={(e) => setEditForm((prev) => ({ ...prev, username: e.target.value }))}
                  style={inputStyle}
                />
                <ModernSelect
                  value={editForm.status}
                  onChange={(value) => setEditForm((prev) => ({ ...prev, status: value }))}
                  options={[
                    { value: 'active', label: 'active' },
                    { value: 'disabled', label: 'disabled' },
                    { value: 'expired', label: 'expired' },
                  ]}
                  placeholder="状态"
                />
                <input
                  placeholder="单位成本（可选）"
                  value={editForm.unitCost}
                  onChange={(e) => setEditForm((prev) => ({ ...prev, unitCost: e.target.value }))}
                  style={inputStyle}
                />
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, ...inputStyle }}>
                  <input
                    type="checkbox"
                    checked={editForm.checkinEnabled}
                    onChange={(e) => setEditForm((prev) => ({ ...prev, checkinEnabled: e.target.checked }))}
                  />
                  启用签到
                </label>
                <input
                  placeholder="Access Token"
                  value={editForm.accessToken}
                  onChange={(e) => setEditForm((prev) => ({ ...prev, accessToken: e.target.value }))}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                />
                <input
                  placeholder="API Token（可选）"
                  value={editForm.apiToken}
                  onChange={(e) => setEditForm((prev) => ({ ...prev, apiToken: e.target.value }))}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                />
                <input
                  placeholder="代理地址（可选，如 http://127.0.0.1:7890）"
                  value={editForm.proxyUrl}
                  onChange={(e) => setEditForm((prev) => ({ ...prev, proxyUrl: e.target.value }))}
                  style={inputStyle}
                />
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: -4 }}>
                  覆盖站点和系统代理，留空则使用站点设置。支持 http/https/socks5 协议。
                </div>
                {((editingAccount?.site?.platform || '').toLowerCase() === 'sub2api') && (
                  <>
                    <input
                      placeholder="Sub2API refresh_token（可选）"
                      value={editForm.refreshToken}
                      onChange={(e) => setEditForm((prev) => ({ ...prev, refreshToken: e.target.value }))}
                      style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                    />
                    <input
                      placeholder="token_expires_at（可选）"
                      value={editForm.tokenExpiresAt}
                      onChange={(e) => setEditForm((prev) => ({ ...prev, tokenExpiresAt: e.target.value.replace(/\D/g, '') }))}
                      style={inputStyle}
                    />
                  </>
                )}
              </ResponsiveFormGrid>
            ) : null}
          </CenteredModal>

          <div className="card">
            {visibleAccounts.length > 0 ? (
              isMobile ? (
                <div className="mobile-card-list">
                  {visibleAccounts.map((a: any) => {
                    const capabilities = resolveAccountCapabilities(a);
                    const connectionMode = resolveAccountCredentialMode(a);
                    const health = resolveRuntimeHealth(a);
                    const isExpanded = expandedAccountIds.includes(a.id);
                    const hintMessage = (a.status === 'expired' && !capabilities.proxyOnly)
                      ? '账号已过期，请重新绑定'
                      : (health.reason || '-');
                    return (
                      <MobileCard
                        key={a.id}
                        title={resolveAccountDisplayName(a)}
                        headerActions={(
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <input
                              type="checkbox"
                              aria-label={`选择账号 ${resolveAccountDisplayName(a)}`}
                              checked={selectedAccountIds.includes(a.id)}
                              onChange={(event) => toggleAccountSelection(a.id, event.target.checked)}
                            />
                            <span className={`badge ${connectionMode === 'apikey' ? 'badge-warning' : 'badge-info'}`} style={{ fontSize: 10 }}>
                              {connectionMode === 'apikey' ? 'API Key' : 'Session'}
                            </span>
                            {parseAccountExtraConfig(a)?.proxyUrl && (
                              <span className="badge badge-purple" style={{ fontSize: 10 }}>代理</span>
                            )}
                          </div>
                        )}
                        footerActions={(
                          <>
                            <button
                              type="button"
                              onClick={() => toggleAccountDetails(a.id)}
                              className="btn btn-link"
                            >
                              {isExpanded ? '收起' : '详情'}
                            </button>
                            <button onClick={() => openEditPanel(a)} className="btn btn-link btn-link-info">
                              编辑
                            </button>
                            <button
                              onClick={() => openModelModal(a)}
                              disabled={actionLoading[`models-${a.id}`]}
                              className="btn btn-link btn-link-info"
                            >
                              模型
                            </button>
                          </>
                        )}
                      >
                        <MobileField
                          label="运行健康状态"
                          value={(
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                              <span className={`badge ${health.cls}`} style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4, width: 'fit-content' }}>
                                <span className={`status-dot ${health.dotClass} ${health.pulse ? 'animate-pulse-dot' : ''}`} style={{ marginRight: 0 }} />
                                {health.label}
                              </span>
                              <span
                                style={{
                                  fontSize: 11,
                                  color: 'var(--color-text-muted)',
                                  maxWidth: 240,
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap',
                                }}
                                data-tooltip={health.reason}
                              >
                                {health.reason}
                              </span>
                            </div>
                          )}
                        />
                        <MobileField
                          label="余额"
                          value={(
                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>${(a.balance || 0).toFixed(2)}</div>
                              <div style={{ fontSize: 11, color: (a.todayReward || 0) > 0 ? 'var(--color-success)' : 'var(--color-text-muted)', fontWeight: 500 }}>
                                +{(a.todayReward || 0).toFixed(2)}
                              </div>
                            </div>
                          )}
                        />
                        <MobileField
                          label="已用"
                          value={(
                            <div>
                              <div>${(a.balanceUsed || 0).toFixed(2)}</div>
                              <div style={{ fontSize: 11, color: (a.todaySpend || 0) > 0 ? 'var(--color-danger)' : 'var(--color-text-muted)', fontWeight: 500 }}>
                                -{(a.todaySpend || 0).toFixed(2)}
                              </div>
                            </div>
                          )}
                        />
                        {isExpanded ? (
                          <div className="mobile-card-extra">
                            <MobileField
                              label="站点"
                              value={(
                                <SiteBadgeLink
                                  siteId={a.site?.id}
                                  siteName={a.site?.name}
                                  badgeStyle={{ fontSize: 11 }}
                                />
                              )}
                            />
                            <MobileField
                              label="签到"
                              value={capabilities.canCheckin ? (
                                <button
                                  type="button"
                                  className={`checkin-toggle-badge ${a.checkinEnabled ? 'is-on' : 'is-off'}`}
                                  onClick={() => handleToggleCheckin(a)}
                                  disabled={!!actionLoading[`checkin-toggle-${a.id}`]}
                                  data-tooltip={a.checkinEnabled ? '点击关闭签到，全部签到会忽略此账号' : '点击开启签到'}
                                  aria-label={a.checkinEnabled ? '点击关闭签到，全部签到会忽略此账号' : '点击开启签到'}
                                >
                                  {actionLoading[`checkin-toggle-${a.id}`]
                                    ? <span className="spinner spinner-sm" />
                                    : (a.checkinEnabled ? '开启' : '关闭')}
                                </button>
                              ) : (
                                <span className="badge badge-muted" style={{ fontSize: 11 }}>
                                  不支持
                                </span>
                              )}
                            />
                            <MobileField
                              label="账号状态"
                              value={a.status === 'expired' ? '已过期' : (a.status || '-')}
                            />
                            <MobileField
                              label="提示"
                              stacked
                              value={hintMessage}
                            />
                            <div className="mobile-card-actions">
                              <button
                                onClick={() => handleTogglePin(a)}
                                disabled={!!actionLoading[`pin-toggle-${a.id}`]}
                                className={`btn btn-link ${a.isPinned ? 'btn-link-warning' : 'btn-link-primary'}`}
                              >
                                {actionLoading[`pin-toggle-${a.id}`] ? <span className="spinner spinner-sm" /> : (a.isPinned ? '取消置顶' : '置顶')}
                              </button>
                              {sortMode === 'custom' && (
                                <>
                                  <button
                                    onClick={() => handleMoveCustomOrder(a, 'up')}
                                    disabled={!!actionLoading[`reorder-${a.id}`]}
                                    className="btn btn-link btn-link-muted"
                                  >
                                    ↑ 上移
                                  </button>
                                  <button
                                    onClick={() => handleMoveCustomOrder(a, 'down')}
                                    disabled={!!actionLoading[`reorder-${a.id}`]}
                                    className="btn btn-link btn-link-muted"
                                  >
                                    ↓ 下移
                                  </button>
                                </>
                              )}
                              {capabilities.canRefreshBalance && (
                                <button onClick={() => withLoading(`refresh-${a.id}`, () => api.refreshBalance(a.id), '余额已刷新')} disabled={actionLoading[`refresh-${a.id}`]} className="btn btn-link btn-link-primary">
                                  {actionLoading[`refresh-${a.id}`] ? <span className="spinner spinner-sm" /> : '刷新'}
                                </button>
                              )}
                              {capabilities.canCheckin && (
                                <button onClick={() => withLoading(`checkin-${a.id}`, () => api.triggerCheckin(a.id), '签到完成')} disabled={actionLoading[`checkin-${a.id}`]} className="btn btn-link btn-link-warning">
                                  {actionLoading[`checkin-${a.id}`] ? <span className="spinner spinner-sm" /> : '签到'}
                                </button>
                              )}
                              {a.status === 'expired' && !capabilities.proxyOnly && (
                                <button
                                  onClick={() => openRebindPanel(a)}
                                  className="btn btn-link btn-link-warning"
                                >
                                  重新绑定
                                </button>
                              )}
                              <button onClick={() => setDeleteConfirm({ mode: 'single', accountId: a.id, accountName: resolveAccountDisplayName(a) })} disabled={actionLoading[`delete-${a.id}`]} className="btn btn-link btn-link-danger">
                                {actionLoading[`delete-${a.id}`] ? <span className="spinner spinner-sm" /> : '删除'}
                              </button>
                            </div>
                          </div>
                        ) : null}
                      </MobileCard>
                    );
                  })}
                </div>
              ) : (
                <table className="data-table accounts-table">
                <thead>
                  <tr>
                    <th style={{ width: 44 }}>
                      <input
                        type="checkbox"
                        checked={allVisibleAccountsSelected}
                        onChange={(e) => toggleSelectAllVisibleAccounts(e.target.checked)}
                      />
                    </th>
                    <th>连接名称</th>
                    <th>站点</th>
                    <th>运行健康状态</th>
                    <th>余额</th>
                    <th>已用</th>
                    <th>签到</th>
                    <th className="accounts-actions-col" style={{ textAlign: 'right' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleAccounts.map((a: any, i: number) => {
                    const capabilities = resolveAccountCapabilities(a);
                    const connectionMode = resolveAccountCredentialMode(a);
                    return (
                      <tr
                        key={a.id}
                        data-testid={`account-row-${a.id}`}
                        ref={(node) => {
                          if (node) rowRefs.current.set(a.id, node);
                          else rowRefs.current.delete(a.id);
                        }}
                        onClick={(event) => handleAccountRowClick(a.id, event)}
                        className={`animate-slide-up stagger-${Math.min(i + 1, 5)} row-selectable ${selectedAccountIds.includes(a.id) ? 'row-selected' : ''} ${highlightAccountId === a.id ? 'row-focus-highlight' : ''}`.trim()}
                      >
                        <td>
                          <input
                            data-testid={`account-select-${a.id}`}
                            type="checkbox"
                            checked={selectedAccountIds.includes(a.id)}
                            onChange={(e) => toggleAccountSelection(a.id, e.target.checked)}
                          />
                        </td>
                        <td style={{ color: 'var(--color-text-primary)' }}>
                          <div style={{ fontWeight: 600 }}>{resolveAccountDisplayName(a)}</div>
                          <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                            <span className={`badge ${connectionMode === 'apikey' ? 'badge-warning' : 'badge-info'}`} style={{ fontSize: 10 }}>
                              {connectionMode === 'apikey' ? 'API Key' : 'Session'}
                            </span>
                            {parseAccountExtraConfig(a)?.proxyUrl && (
                              <span className="badge badge-purple" style={{ fontSize: 10 }}>代理</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <SiteBadgeLink
                            siteId={a.site?.id}
                            siteName={a.site?.name}
                            badgeStyle={{ fontSize: 11 }}
                          />
                        </td>
                        <td>
                          {(() => {
                            const health = resolveRuntimeHealth(a);
                            return (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <span className={`badge ${health.cls}`} style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 4, width: 'fit-content' }}>
                                  <span className={`status-dot ${health.dotClass} ${health.pulse ? 'animate-pulse-dot' : ''}`} style={{ marginRight: 0 }} />
                                  {health.label}
                                </span>
                                <span
                                  style={{
                                    fontSize: 11,
                                    color: 'var(--color-text-muted)',
                                    maxWidth: 200,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                  data-tooltip={health.reason}
                                >
                                  {health.reason}
                                </span>
                              </div>
                            );
                          })()}
                        </td>
                        <td style={{ fontVariantNumeric: 'tabular-nums' }}>
                          <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>${(a.balance || 0).toFixed(2)}</div>
                          <div style={{ fontSize: 11, color: (a.todayReward || 0) > 0 ? 'var(--color-success)' : 'var(--color-text-muted)', fontWeight: 500 }}>
                            +{(a.todayReward || 0).toFixed(2)}
                          </div>
                        </td>
                        <td style={{ fontVariantNumeric: 'tabular-nums', fontSize: 12 }}>
                          <div>${(a.balanceUsed || 0).toFixed(2)}</div>
                          <div style={{ fontSize: 11, color: (a.todaySpend || 0) > 0 ? 'var(--color-danger)' : 'var(--color-text-muted)', fontWeight: 500 }}>
                            -{(a.todaySpend || 0).toFixed(2)}
                          </div>
                        </td>
                        <td>
                          {capabilities.canCheckin ? (
                            <button
                              type="button"
                              className={`checkin-toggle-badge ${a.checkinEnabled ? 'is-on' : 'is-off'}`}
                              onClick={() => handleToggleCheckin(a)}
                              disabled={!!actionLoading[`checkin-toggle-${a.id}`]}
                              data-tooltip={a.checkinEnabled ? '点击关闭签到，全部签到会忽略此账号' : '点击开启签到'}
                              aria-label={a.checkinEnabled ? '点击关闭签到，全部签到会忽略此账号' : '点击开启签到'}
                            >
                              {actionLoading[`checkin-toggle-${a.id}`]
                                ? <span className="spinner spinner-sm" />
                                : (a.checkinEnabled ? '开启' : '关闭')}
                            </button>
                          ) : (
                            <span className="badge badge-muted" style={{ fontSize: 11 }}>
                              不支持
                            </span>
                          )}
                        </td>
                        <td className="accounts-actions-cell" style={{ textAlign: 'right' }}>
                          <div className="accounts-row-actions">
                            <button
                              onClick={() => handleTogglePin(a)}
                              disabled={!!actionLoading[`pin-toggle-${a.id}`]}
                              className={`btn btn-link ${a.isPinned ? 'btn-link-warning' : 'btn-link-primary'}`}
                            >
                              {actionLoading[`pin-toggle-${a.id}`] ? <span className="spinner spinner-sm" /> : (a.isPinned ? '取消置顶' : '置顶')}
                            </button>
                            {sortMode === 'custom' && (
                              <>
                                <button
                                  onClick={() => handleMoveCustomOrder(a, 'up')}
                                  disabled={!!actionLoading[`reorder-${a.id}`]}
                                  className="btn btn-link btn-link-muted"
                                >
                                  ↑
                                </button>
                                <button
                                  onClick={() => handleMoveCustomOrder(a, 'down')}
                                  disabled={!!actionLoading[`reorder-${a.id}`]}
                                  className="btn btn-link btn-link-muted"
                                >
                                  ↓
                                </button>
                              </>
                            )}
                            {capabilities.canRefreshBalance && (
                              <button onClick={() => withLoading(`refresh-${a.id}`, () => api.refreshBalance(a.id), '余额已刷新')} disabled={actionLoading[`refresh-${a.id}`]} className="btn btn-link btn-link-primary">
                                {actionLoading[`refresh-${a.id}`] ? <span className="spinner spinner-sm" /> : '刷新'}
                              </button>
                            )}
                            <button
                              onClick={() => openModelModal(a)}
                              disabled={actionLoading[`models-${a.id}`]}
                              className="btn btn-link btn-link-info"
                            >
                              模型
                            </button>
                            {capabilities.canCheckin && (
                              <button onClick={() => withLoading(`checkin-${a.id}`, () => api.triggerCheckin(a.id), '签到完成')} disabled={actionLoading[`checkin-${a.id}`]} className="btn btn-link btn-link-warning">
                                {actionLoading[`checkin-${a.id}`] ? <span className="spinner spinner-sm" /> : '签到'}
                              </button>
                            )}
                            {a.status === 'expired' && !capabilities.proxyOnly && (
                              <button
                                onClick={() => openRebindPanel(a)}
                                className="btn btn-link btn-link-warning"
                              >
                                重新绑定
                              </button>
                            )}
                            <button onClick={() => openEditPanel(a)} className="btn btn-link btn-link-info">
                              编辑
                            </button>
                            <button onClick={() => setDeleteConfirm({ mode: 'single', accountId: a.id, accountName: resolveAccountDisplayName(a) })} disabled={actionLoading[`delete-${a.id}`]} className="btn btn-link btn-link-danger">
                              {actionLoading[`delete-${a.id}`] ? <span className="spinner spinner-sm" /> : '删除'}
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
                <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                <div className="empty-state-title">{activeSegment === 'apikey' ? '暂无 API Key 连接' : '暂无 Session 连接'}</div>
                <div className="empty-state-desc">
                  {activeSegment === 'apikey'
                    ? (sites.length > 0 ? '请为现有站点补充 API Key 连接' : '请先添加站点，然后为站点补充 API Key 连接')
                    : (sites.length > 0 ? '请为现有站点添加 Session 连接' : '请先添加站点，然后添加 Session 连接')}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      <AccountModelsModal
        modelModal={modelModal}
        inputStyle={inputStyle}
        onClose={closeModelModal}
        onSave={saveModelDisabled}
        onRefresh={async () => {
          if (!modelModal.account) return;
          await loadModelModalModels(modelModal.account, {
            refreshUpstream: true,
            successMessage: '模型列表已刷新',
            errorMessage: '刷新失败',
          });
        }}
        onToggleModelDisabled={toggleModelDisabled}
        onSetPendingDisabled={(pendingDisabled) => setModelModal((state) => ({ ...state, pendingDisabled }))}
        onManualInputChange={(value) => setModelModal((state) => ({ ...state, manualModelsInput: value }))}
        onAddManualModels={handleAddManualModels}
      />
    </div>
  );
}
