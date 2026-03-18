import React, { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import { useToast } from '../components/Toast.js';
import ChangeKeyModal from '../components/ChangeKeyModal.js';
import { useAnimatedVisibility } from '../components/useAnimatedVisibility.js';
import { BrandGlyph, InlineBrandIcon, getBrand, normalizeBrandIconKey } from '../components/BrandIcon.js';
import ModernSelect from '../components/ModernSelect.js';
import {
  applyRoutingProfilePreset,
  resolveRoutingProfilePreset,
  type RoutingWeights,
} from './helpers/routingProfiles.js';
import { fuzzyMatch } from './helpers/fuzzySearch.js';
import { clearAuthSession } from '../authSession.js';
import { clearAppInstallationState } from '../appLocalState.js';
import { tr } from '../i18n.js';
import { ROUTE_ICON_NONE_VALUE } from './token-routes/utils.js';

const PROXY_TOKEN_PREFIX = 'sk-';
const ROUTE_BRAND_ICON_PREFIX = 'brand:';
const FACTORY_RESET_ADMIN_TOKEN = 'change-me-admin-token';
const FACTORY_RESET_CONFIRM_SECONDS = 3;
type DbDialect = 'sqlite' | 'mysql' | 'postgres';

type RuntimeSettings = {
  checkinCron: string;
  balanceRefreshCron: string;
  logCleanupCron: string;
  logCleanupUsageLogsEnabled: boolean;
  logCleanupProgramLogsEnabled: boolean;
  logCleanupRetentionDays: number;
  routingFallbackUnitCost: number;
  routingWeights: RoutingWeights;
  systemProxyUrl: string;
  proxyErrorKeywords: string[];
  proxyEmptyContentFailEnabled: boolean;
  proxyTokenMasked?: string;
  adminIpAllowlist?: string[];
  currentAdminIp?: string;
};

type DownstreamApiKeyItem = {
  id: number;
  name: string;
  key: string;
  keyMasked: string;
  description: string | null;
  enabled: boolean;
  expiresAt: string | null;
  maxCost: number | null;
  usedCost: number;
  maxRequests: number | null;
  usedRequests: number;
  supportedModels: string[];
  allowedRouteIds: number[];
  lastUsedAt: string | null;
};

type DownstreamCreateForm = {
  name: string;
  key: string;
  description: string;
  maxCost: string;
  maxRequests: string;
  expiresAt: string;
  selectedModels: string[];
  selectedGroupRouteIds: number[];
};

type RouteSelectorItem = {
  id: number;
  modelPattern: string;
  displayName?: string | null;
  displayIcon?: string | null;
  enabled: boolean;
};

type DatabaseMigrationSummary = {
  dialect: DbDialect;
  connection: string;
  overwrite: boolean;
  version: string;
  timestamp: number;
  rows: {
    sites: number;
    accounts: number;
    accountTokens: number;
    tokenRoutes: number;
    routeChannels: number;
    settings: number;
  };
};

type RuntimeDatabaseState = {
  active: {
    dialect: DbDialect;
    connection: string;
    ssl: boolean;
  };
  saved: {
    dialect: DbDialect;
    connection: string;
    ssl: boolean;
  } | null;
  restartRequired: boolean;
};

type ShorthandConnection = {
  host: string;
  user: string;
  password: string;
  port: string;
  database: string;
};

const defaultWeights: RoutingWeights = {
  baseWeightFactor: 0.5,
  valueScoreFactor: 0.5,
  costWeight: 0.4,
  balanceWeight: 0.3,
  usageWeight: 0.3,
};

function getDialectDefaults(dialect: DbDialect) {
  if (dialect === 'mysql') {
    return { port: '3306', database: 'mysql' };
  }
  if (dialect === 'postgres') {
    return { port: '5432', database: 'postgres' };
  }
  return { port: '', database: '' };
}

function buildShorthandConnectionString(dialect: DbDialect, input: ShorthandConnection): string {
  if (dialect === 'sqlite') return '';
  const host = input.host.trim();
  const user = input.user.trim();
  const password = input.password;
  if (!host || !user || !password) return '';
  const defaults = getDialectDefaults(dialect);
  const port = (input.port || defaults.port).trim() || defaults.port;
  const database = (input.database || defaults.database).trim() || defaults.database;
  const protocol = dialect === 'mysql' ? 'mysql' : 'postgres';
  return `${protocol}://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${encodeURIComponent(database)}`;
}

function inferUrlDialect(connectionString: string): 'mysql' | 'postgres' | null {
  const normalized = (connectionString || '').trim().toLowerCase();
  if (!normalized) return null;
  if (normalized.startsWith('mysql://')) return 'mysql';
  if (normalized.startsWith('postgres://') || normalized.startsWith('postgresql://')) return 'postgres';
  return null;
}

function isRegexModelPattern(pattern: string): boolean {
  return pattern.trim().toLowerCase().startsWith('re:');
}

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (isRegexModelPattern(normalized)) return false;
  return !/[\*\?]/.test(normalized);
}

function routeTitle(route: RouteSelectorItem): string {
  const displayName = (route.displayName || '').trim();
  return displayName || route.modelPattern;
}

function parseBrandIconValue(raw: string | null | undefined): string | null {
  const normalized = (raw || '').trim();
  if (!normalized.startsWith(ROUTE_BRAND_ICON_PREFIX)) return null;
  const icon = normalized.slice(ROUTE_BRAND_ICON_PREFIX.length).trim();
  return normalizeBrandIconKey(icon);
}

function resolveRouteBrandSource(route: RouteSelectorItem): string {
  const title = routeTitle(route);
  if (getBrand(title)) return title;
  return route.modelPattern;
}

export default function Settings() {
  const navigate = useNavigate();
  const [runtime, setRuntime] = useState<RuntimeSettings>({
    checkinCron: '0 8 * * *',
    balanceRefreshCron: '0 * * * *',
    logCleanupCron: '0 6 * * *',
    logCleanupUsageLogsEnabled: false,
    logCleanupProgramLogsEnabled: false,
    logCleanupRetentionDays: 30,
    routingFallbackUnitCost: 1,
    routingWeights: defaultWeights,
    systemProxyUrl: '',
    proxyErrorKeywords: [],
    proxyEmptyContentFailEnabled: false,
  });
  const [proxyTokenSuffix, setProxyTokenSuffix] = useState('');
  const [proxyErrorKeywordsText, setProxyErrorKeywordsText] = useState('');
  const [maskedToken, setMaskedToken] = useState('');
  const [loading, setLoading] = useState(true);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [savingToken, setSavingToken] = useState(false);
  const [savingSystemProxy, setSavingSystemProxy] = useState(false);
  const [savingProxyFailureRules, setSavingProxyFailureRules] = useState(false);
  const [savingRouting, setSavingRouting] = useState(false);
  const [showAdvancedRouting, setShowAdvancedRouting] = useState(false);
  const [savingSecurity, setSavingSecurity] = useState(false);
  const [adminIpAllowlistText, setAdminIpAllowlistText] = useState('');
  const [clearingCache, setClearingCache] = useState(false);
  const [clearingUsage, setClearingUsage] = useState(false);
  const [migrationDialect, setMigrationDialect] = useState<DbDialect>('postgres');
  const [migrationConnectionString, setMigrationConnectionString] = useState('');
  const [connectionMode, setConnectionMode] = useState<'shorthand' | 'advanced'>('shorthand');
  const [showShorthandOptional, setShowShorthandOptional] = useState(false);
  const [shorthandConnection, setShorthandConnection] = useState<ShorthandConnection>({
    host: '',
    user: '',
    password: '',
    port: '5432',
    database: 'postgres',
  });
  const [migrationOverwrite, setMigrationOverwrite] = useState(true);
  const [migrationSsl, setMigrationSsl] = useState(false);
  const [testingMigrationConnection, setTestingMigrationConnection] = useState(false);
  const [migratingDatabase, setMigratingDatabase] = useState(false);
  const [savingRuntimeDatabase, setSavingRuntimeDatabase] = useState(false);
  const [migrationSummary, setMigrationSummary] = useState<DatabaseMigrationSummary | null>(null);
  const [runtimeDatabaseState, setRuntimeDatabaseState] = useState<RuntimeDatabaseState | null>(null);
  const [showChangeKey, setShowChangeKey] = useState(false);
  const [downstreamKeys, setDownstreamKeys] = useState<DownstreamApiKeyItem[]>([]);
  const [downstreamLoading, setDownstreamLoading] = useState(false);
  const [downstreamSaving, setDownstreamSaving] = useState(false);
  const [downstreamOps, setDownstreamOps] = useState<Record<number, boolean>>({});
  const [editingDownstreamId, setEditingDownstreamId] = useState<number | null>(null);
  const [downstreamModalOpen, setDownstreamModalOpen] = useState(false);
  const downstreamModalPresence = useAnimatedVisibility(downstreamModalOpen, 220);
  const [selectorOpen, setSelectorOpen] = useState(false);
  const selectorModalPresence = useAnimatedVisibility(selectorOpen, 220);
  const [factoryResetOpen, setFactoryResetOpen] = useState(false);
  const factoryResetPresence = useAnimatedVisibility(factoryResetOpen, 220);
  const [factoryResetting, setFactoryResetting] = useState(false);
  const [factoryResetSecondsLeft, setFactoryResetSecondsLeft] = useState(FACTORY_RESET_CONFIRM_SECONDS);
  const [selectorLoading, setSelectorLoading] = useState(false);
  const [selectorRoutes, setSelectorRoutes] = useState<RouteSelectorItem[]>([]);
  const [selectorModelSearch, setSelectorModelSearch] = useState('');
  const [selectorGroupSearch, setSelectorGroupSearch] = useState('');
  const [downstreamCreate, setDownstreamCreate] = useState<DownstreamCreateForm>({
    name: '',
    key: '',
    description: '',
    maxCost: '',
    maxRequests: '',
    expiresAt: '',
    selectedModels: [],
    selectedGroupRouteIds: [],
  });
  const toast = useToast();

  const activeRoutingProfile = useMemo(
    () => resolveRoutingProfilePreset(runtime.routingWeights),
    [runtime.routingWeights],
  );

  const exactModelOptions = useMemo(() => (
    selectorRoutes
      .filter((route) => isExactModelPattern(route.modelPattern))
      .map((route) => route.modelPattern.trim())
      .filter((item, index, arr) => item.length > 0 && arr.indexOf(item) === index)
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
  ), [selectorRoutes]);

  const groupRouteOptions = useMemo(() => (
    selectorRoutes
      .filter((route) => !isExactModelPattern(route.modelPattern))
      .sort((a, b) => routeTitle(a).localeCompare(routeTitle(b), undefined, { sensitivity: 'base' }))
  ), [selectorRoutes]);

  const filteredExactModelOptions = useMemo(() => {
    const query = selectorModelSearch.trim();
    if (!query) return exactModelOptions;
    return exactModelOptions.filter((modelName) => fuzzyMatch(modelName, query));
  }, [exactModelOptions, selectorModelSearch]);

  const filteredGroupRouteOptions = useMemo(() => {
    const query = selectorGroupSearch.trim();
    if (!query) return groupRouteOptions;
    return groupRouteOptions.filter((route) => {
      const matchText = `${routeTitle(route)} ${route.modelPattern} ${route.displayName || ''}`;
      return fuzzyMatch(matchText, query);
    });
  }, [groupRouteOptions, selectorGroupSearch]);

  const generatedConnectionString = useMemo(() => (
    buildShorthandConnectionString(migrationDialect, shorthandConnection)
  ), [migrationDialect, shorthandConnection]);

  const effectiveMigrationConnectionString = useMemo(() => {
    if (migrationDialect === 'sqlite') return migrationConnectionString.trim();
    if (connectionMode === 'advanced') return migrationConnectionString.trim();
    return generatedConnectionString.trim();
  }, [connectionMode, generatedConnectionString, migrationConnectionString, migrationDialect]);

  useEffect(() => {
    const defaults = getDialectDefaults(migrationDialect);
    if (migrationDialect === 'sqlite') {
      setConnectionMode('advanced');
      return;
    }
    setShorthandConnection((prev) => ({
      ...prev,
      port: defaults.port,
      database: defaults.database,
    }));
  }, [migrationDialect]);

  useEffect(() => {
    if (!factoryResetOpen) {
      setFactoryResetSecondsLeft(FACTORY_RESET_CONFIRM_SECONDS);
      return;
    }
    setFactoryResetSecondsLeft(FACTORY_RESET_CONFIRM_SECONDS);
    const timer = globalThis.setInterval(() => {
      setFactoryResetSecondsLeft((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => globalThis.clearInterval(timer);
  }, [factoryResetOpen]);

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

  const toDateTimeLocal = (isoString: string | null | undefined): string => {
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
  };

  const loadDownstreamKeys = async () => {
    setDownstreamLoading(true);
    try {
      const res = await api.getDownstreamApiKeys();
      const items = Array.isArray(res?.items) ? res.items : [];
      setDownstreamKeys(items);
    } catch (err: any) {
      toast.error(err?.message || '加载下游 API Key 失败');
    } finally {
      setDownstreamLoading(false);
    }
  };

  const loadRouteSelectorRoutes = async () => {
    setSelectorLoading(true);
    try {
      const rows = await api.getRoutesLite();
      setSelectorRoutes((Array.isArray(rows) ? rows : []).map((row: any) => ({
        id: row.id,
        modelPattern: row.modelPattern,
        displayName: row.displayName,
        displayIcon: row.displayIcon,
        enabled: !!row.enabled,
      })));
    } catch (err: any) {
      toast.error(err?.message || '加载路由列表失败');
    } finally {
      setSelectorLoading(false);
    }
  };

  const loadSettings = async () => {
    setLoading(true);
    try {
      const [authInfo, runtimeInfo, downstreamInfo, routeRows, runtimeDatabaseInfo] = await Promise.all([
        api.getAuthInfo(),
        api.getRuntimeSettings(),
        api.getDownstreamApiKeys(),
        api.getRoutesLite(),
        api.getRuntimeDatabaseConfig(),
      ]);
      setMaskedToken(authInfo.masked || '****');
      setRuntime({
        checkinCron: runtimeInfo.checkinCron || '0 8 * * *',
        balanceRefreshCron: runtimeInfo.balanceRefreshCron || '0 * * * *',
        logCleanupCron: runtimeInfo.logCleanupCron || '0 6 * * *',
        logCleanupUsageLogsEnabled: !!runtimeInfo.logCleanupUsageLogsEnabled,
        logCleanupProgramLogsEnabled: !!runtimeInfo.logCleanupProgramLogsEnabled,
        logCleanupRetentionDays: Number(runtimeInfo.logCleanupRetentionDays) >= 1
          ? Math.trunc(Number(runtimeInfo.logCleanupRetentionDays))
          : 30,
        routingFallbackUnitCost: Number(runtimeInfo.routingFallbackUnitCost) > 0
          ? Number(runtimeInfo.routingFallbackUnitCost)
          : 1,
        routingWeights: {
          ...defaultWeights,
          ...(runtimeInfo.routingWeights || {}),
        },
        systemProxyUrl: typeof runtimeInfo.systemProxyUrl === 'string' ? runtimeInfo.systemProxyUrl : '',
        proxyErrorKeywords: Array.isArray(runtimeInfo.proxyErrorKeywords)
          ? runtimeInfo.proxyErrorKeywords.filter((item: unknown) => typeof item === 'string')
          : [],
        proxyEmptyContentFailEnabled: !!runtimeInfo.proxyEmptyContentFailEnabled,
        proxyTokenMasked: runtimeInfo.proxyTokenMasked || '',
        adminIpAllowlist: Array.isArray(runtimeInfo.adminIpAllowlist)
          ? runtimeInfo.adminIpAllowlist.filter((item: unknown) => typeof item === 'string')
          : [],
        currentAdminIp: typeof runtimeInfo.currentAdminIp === 'string' ? runtimeInfo.currentAdminIp : '',
      });
      setProxyErrorKeywordsText(
        Array.isArray(runtimeInfo.proxyErrorKeywords)
          ? runtimeInfo.proxyErrorKeywords.filter((item: unknown) => typeof item === 'string').join('\n')
          : '',
      );
      setAdminIpAllowlistText(
        Array.isArray(runtimeInfo.adminIpAllowlist)
          ? runtimeInfo.adminIpAllowlist.join('\n')
          : '',
      );
      setDownstreamKeys(Array.isArray(downstreamInfo?.items) ? downstreamInfo.items : []);
      setSelectorRoutes((Array.isArray(routeRows) ? routeRows : []).map((row: any) => ({
        id: row.id,
        modelPattern: row.modelPattern,
        displayName: row.displayName,
        displayIcon: row.displayIcon,
        enabled: !!row.enabled,
      })));
      if (runtimeDatabaseInfo?.active?.dialect) {
        const preferredDialect = (runtimeDatabaseInfo?.saved?.dialect || runtimeDatabaseInfo.active.dialect) as DbDialect;
        setMigrationDialect(preferredDialect);
      }
      setRuntimeDatabaseState({
        active: {
          dialect: (runtimeDatabaseInfo?.active?.dialect || 'sqlite') as DbDialect,
          connection: String(runtimeDatabaseInfo?.active?.connection || ''),
          ssl: !!runtimeDatabaseInfo?.active?.ssl,
        },
        saved: runtimeDatabaseInfo?.saved
          ? {
            dialect: runtimeDatabaseInfo.saved.dialect as DbDialect,
            connection: String(runtimeDatabaseInfo.saved.connection || ''),
            ssl: !!runtimeDatabaseInfo.saved.ssl,
          }
          : null,
        restartRequired: !!runtimeDatabaseInfo?.restartRequired,
      });
    } catch (err: any) {
      toast.error(err?.message || '加载设置失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const normalizeProxyTokenSuffix = (raw: string) => {
    const compact = raw.replace(/\s+/g, '');
    if (compact.toLowerCase().startsWith(PROXY_TOKEN_PREFIX)) {
      return compact.slice(PROXY_TOKEN_PREFIX.length);
    }
    return compact;
  };

  const parseProxyErrorKeywords = (raw: string) => raw
    .split(/\r?\n|,/g)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  const saveSchedule = async () => {
    setSavingSchedule(true);
    try {
      await api.updateRuntimeSettings({
        checkinCron: runtime.checkinCron,
        balanceRefreshCron: runtime.balanceRefreshCron,
        logCleanupCron: runtime.logCleanupCron,
        logCleanupUsageLogsEnabled: runtime.logCleanupUsageLogsEnabled,
        logCleanupProgramLogsEnabled: runtime.logCleanupProgramLogsEnabled,
        logCleanupRetentionDays: runtime.logCleanupRetentionDays,
      });
      toast.success('定时任务设置已保存');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingSchedule(false);
    }
  };

  const saveProxyToken = async () => {
    const suffix = proxyTokenSuffix.trim();
    if (!suffix) {
      toast.info('请输入 sk- 后的令牌内容');
      return;
    }
    setSavingToken(true);
    try {
      const res = await api.updateRuntimeSettings({ proxyToken: `${PROXY_TOKEN_PREFIX}${suffix}` });
      setRuntime((prev) => ({ ...prev, proxyTokenMasked: res.proxyTokenMasked || prev.proxyTokenMasked }));
      setProxyTokenSuffix('');
      toast.success('Proxy token updated');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingToken(false);
    }
  };

  const saveSystemProxy = async () => {
    setSavingSystemProxy(true);
    try {
      const res = await api.updateRuntimeSettings({
        systemProxyUrl: runtime.systemProxyUrl.trim(),
      });
      setRuntime((prev) => ({
        ...prev,
        systemProxyUrl: typeof res?.systemProxyUrl === 'string'
          ? res.systemProxyUrl
          : prev.systemProxyUrl,
      }));
      toast.success('系统代理已保存');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingSystemProxy(false);
    }
  };

  const saveProxyFailureRules = async () => {
    setSavingProxyFailureRules(true);
    try {
      const keywords = parseProxyErrorKeywords(proxyErrorKeywordsText);
      const res = await api.updateRuntimeSettings({
        proxyErrorKeywords: keywords,
        proxyEmptyContentFailEnabled: runtime.proxyEmptyContentFailEnabled,
      });
      const nextKeywords = Array.isArray(res?.proxyErrorKeywords)
        ? res.proxyErrorKeywords
        : keywords;
      setRuntime((prev) => ({
        ...prev,
        proxyErrorKeywords: nextKeywords,
        proxyEmptyContentFailEnabled: typeof res?.proxyEmptyContentFailEnabled === 'boolean'
          ? res.proxyEmptyContentFailEnabled
          : prev.proxyEmptyContentFailEnabled,
      }));
      setProxyErrorKeywordsText(nextKeywords.join('\n'));
      toast.success('代理失败规则已保存');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingProxyFailureRules(false);
    }
  };

  const resetDownstreamForm = () => {
    setEditingDownstreamId(null);
    setDownstreamCreate({
      name: '',
      key: '',
      description: '',
      maxCost: '',
      maxRequests: '',
      expiresAt: '',
      selectedModels: [],
      selectedGroupRouteIds: [],
    });
  };

  const openCreateDownstreamModal = () => {
    resetDownstreamForm();
    setDownstreamModalOpen(true);
  };

  const closeDownstreamModal = () => {
    setDownstreamModalOpen(false);
    resetDownstreamForm();
  };

  const closeSelectorModal = () => {
    setSelectorOpen(false);
    setSelectorModelSearch('');
    setSelectorGroupSearch('');
  };

  const beginEditDownstream = (item: DownstreamApiKeyItem) => {
    setEditingDownstreamId(item.id);
    setDownstreamCreate({
      name: item.name || '',
      key: item.key || '',
      description: item.description || '',
      maxCost: item.maxCost === null || item.maxCost === undefined ? '' : String(item.maxCost),
      maxRequests: item.maxRequests === null || item.maxRequests === undefined ? '' : String(item.maxRequests),
      expiresAt: toDateTimeLocal(item.expiresAt),
      selectedModels: Array.isArray(item.supportedModels)
        ? [...new Set(item.supportedModels.map((model) => String(model).trim()).filter((model) => model.length > 0))]
        : [],
      selectedGroupRouteIds: Array.isArray(item.allowedRouteIds)
        ? [...new Set(item.allowedRouteIds.map((id) => Number(id)).filter((id) => Number.isFinite(id) && id > 0).map((id) => Math.trunc(id)))]
        : [],
    });
    setDownstreamModalOpen(true);
  };

  const saveDownstreamKey = async () => {
    const name = downstreamCreate.name.trim();
    const rawKey = downstreamCreate.key.trim();
    if (!name) {
      toast.info('Please enter a name');
      return;
    }
    if (!rawKey) {
      toast.info('请填写 API Key');
      return;
    }
    if (!rawKey.startsWith(PROXY_TOKEN_PREFIX)) {
      toast.info('API Key must start with sk-');
      return;
    }

    setDownstreamSaving(true);
    try {
      const payload = {
        name,
        key: rawKey,
        description: downstreamCreate.description.trim(),
        expiresAt: downstreamCreate.expiresAt ? new Date(downstreamCreate.expiresAt).toISOString() : null,
        maxCost: downstreamCreate.maxCost.trim() ? Number(downstreamCreate.maxCost.trim()) : null,
        maxRequests: downstreamCreate.maxRequests.trim() ? Number(downstreamCreate.maxRequests.trim()) : null,
        supportedModels: downstreamCreate.selectedModels,
        allowedRouteIds: downstreamCreate.selectedGroupRouteIds,
      };

      if (editingDownstreamId) {
        await api.updateDownstreamApiKey(editingDownstreamId, payload);
        toast.success('Downstream API Key updated');
      } else {
        await api.createDownstreamApiKey(payload);
        toast.success('Downstream API Key created');
      }
      setDownstreamModalOpen(false);
      resetDownstreamForm();
      await loadDownstreamKeys();
    } catch (err: any) {
      toast.error(err?.message || '保存下游 API Key 失败');
    } finally {
      setDownstreamSaving(false);
    }
  };

  const toggleModelSelection = (modelName: string) => {
    setDownstreamCreate((prev) => {
      const exists = prev.selectedModels.includes(modelName);
      return {
        ...prev,
        selectedModels: exists
          ? prev.selectedModels.filter((item) => item !== modelName)
          : [...prev.selectedModels, modelName],
      };
    });
  };

  const toggleGroupRouteSelection = (routeId: number) => {
    setDownstreamCreate((prev) => {
      const exists = prev.selectedGroupRouteIds.includes(routeId);
      return {
        ...prev,
        selectedGroupRouteIds: exists
          ? prev.selectedGroupRouteIds.filter((item) => item !== routeId)
          : [...prev.selectedGroupRouteIds, routeId],
      };
    });
  };

  const runDownstreamOp = async (id: number, action: () => Promise<void>) => {
    setDownstreamOps((prev) => ({ ...prev, [id]: true }));
    try {
      await action();
    } finally {
      setDownstreamOps((prev) => ({ ...prev, [id]: false }));
    }
  };

  const toggleDownstreamEnabled = async (item: DownstreamApiKeyItem) => {
    await runDownstreamOp(item.id, async () => {
      await api.updateDownstreamApiKey(item.id, { enabled: !item.enabled });
      await loadDownstreamKeys();
      toast.success(item.enabled ? 'Disabled' : 'Enabled');
    });
  };

  const resetDownstreamUsage = async (item: DownstreamApiKeyItem) => {
    await runDownstreamOp(item.id, async () => {
      await api.resetDownstreamApiKeyUsage(item.id);
      await loadDownstreamKeys();
      toast.success('Usage reset');
    });
  };

  const deleteDownstreamKey = async (item: DownstreamApiKeyItem) => {
    if (!window.confirm('Confirm delete API Key?')) return;
    await runDownstreamOp(item.id, async () => {
      await api.deleteDownstreamApiKey(item.id);
      if (editingDownstreamId === item.id) {
        setDownstreamModalOpen(false);
        resetDownstreamForm();
      }
      await loadDownstreamKeys();
      toast.success('Deleted');
    });
  };

  const saveRouting = async () => {
    setSavingRouting(true);
    try {
      await api.updateRuntimeSettings({
        routingWeights: runtime.routingWeights,
        routingFallbackUnitCost: runtime.routingFallbackUnitCost,
      });
      toast.success('Routing weights saved');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingRouting(false);
    }
  };

  const applyRoutingPreset = (preset: 'balanced' | 'stable' | 'cost') => {
    setRuntime((prev) => ({
      ...prev,
      routingWeights: applyRoutingProfilePreset(preset),
    }));
  };

  const saveSecuritySettings = async () => {
    setSavingSecurity(true);
    try {
      const allowlist = adminIpAllowlistText
        .split(/\r?\n|,/g)
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
      const res = await api.updateRuntimeSettings({
        adminIpAllowlist: allowlist,
      });
      setRuntime((prev) => ({
        ...prev,
        adminIpAllowlist: allowlist,
        currentAdminIp: typeof res?.currentAdminIp === 'string'
          ? res.currentAdminIp
          : prev.currentAdminIp,
      }));
      toast.success('Security settings saved');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingSecurity(false);
    }
  };


  const handleClearCache = async () => {
    if (!window.confirm('确认清理模型缓存并重建路由？')) return;
    setClearingCache(true);
    try {
      const res = await api.clearRuntimeCache();
      toast.success(`缓存已清理（模型缓存 ${res.deletedModelAvailability || 0} 条）`);
    } catch (err: any) {
      toast.error(err?.message || '清理缓存失败');
    } finally {
      setClearingCache(false);
    }
  };

  const handleClearUsage = async () => {
    if (!window.confirm('确认清理占用统计与使用日志？')) return;
    setClearingUsage(true);
    try {
      const res = await api.clearUsageData();
      toast.success(`占用统计已清理（日志 ${res.deletedProxyLogs || 0} 条）`);
    } catch (err: any) {
      toast.error(err?.message || '清理占用失败');
    } finally {
      setClearingUsage(false);
    }
  };

  const closeFactoryResetModal = () => {
    if (factoryResetting) return;
    setFactoryResetOpen(false);
  };

  const handleFactoryReset = async () => {
    if (factoryResetSecondsLeft > 0 || factoryResetting) return;
    setFactoryResetting(true);
    try {
      await api.factoryReset();
      clearAppInstallationState(localStorage);
      window.location.reload();
    } catch (err: any) {
      toast.error(err?.message || '重新初始化系统失败');
      setFactoryResetting(false);
    }
  };

  const handleTestExternalDatabaseConnection = async () => {
    if (!effectiveMigrationConnectionString) {
      toast.info('Please fill target database connection first');
      return;
    }

    const inferredDialect = inferUrlDialect(effectiveMigrationConnectionString);
    if (migrationDialect === 'sqlite' && inferredDialect) {
      toast.error(`当前选择 SQLite，但连接串是 ${inferredDialect.toUpperCase()} URL，请先切换方言`);
      return;
    }

    setTestingMigrationConnection(true);
    try {
      const res = await api.testExternalDatabaseConnection({
        dialect: migrationDialect,
        connectionString: effectiveMigrationConnectionString,
        ssl: migrationSsl,
      });
      toast.success(`Connection success: ${res.connection || migrationDialect}`);
    } catch (err: any) {
      toast.error(err?.message || 'Target database connection failed');
    } finally {
      setTestingMigrationConnection(false);
    }
  };

  const handleMigrateToExternalDatabase = async () => {
    if (!effectiveMigrationConnectionString) {
      toast.info('Please fill target database connection first');
      return;
    }

    const inferredDialect = inferUrlDialect(effectiveMigrationConnectionString);
    if (migrationDialect === 'sqlite' && inferredDialect) {
      toast.error(`当前选择 SQLite，但连接串是 ${inferredDialect.toUpperCase()} URL，请先切换方言`);
      return;
    }

    const warning = migrationOverwrite
      ? 'Confirm migration and overwrite existing data in target database?'
      : 'Confirm migration to target database? If target has data, migration may fail.';
    if (!window.confirm(warning)) return;

    setMigratingDatabase(true);
    try {
      const res = await api.migrateExternalDatabase({
        dialect: migrationDialect,
        connectionString: effectiveMigrationConnectionString,
        overwrite: migrationOverwrite,
        ssl: migrationSsl,
      });
      setMigrationSummary(res);
      toast.success(res?.message || 'Database migration completed');
    } catch (err: any) {
      toast.error(err?.message || 'Database migration failed');
    } finally {
      setMigratingDatabase(false);
    }
  };

  const handleSaveRuntimeDatabaseConfig = async () => {
    if (!effectiveMigrationConnectionString) {
      toast.info('Please fill target database connection first');
      return;
    }

    const inferredDialect = inferUrlDialect(effectiveMigrationConnectionString);
    if (migrationDialect === 'sqlite' && inferredDialect) {
      toast.error(`当前选择 SQLite，但连接串是 ${inferredDialect.toUpperCase()} URL，请先切换方言`);
      return;
    }

    setSavingRuntimeDatabase(true);
    try {
      const res = await api.updateRuntimeDatabaseConfig({
        dialect: migrationDialect,
        connectionString: effectiveMigrationConnectionString,
        ssl: migrationSsl,
      });
      setRuntimeDatabaseState({
        active: {
          dialect: (res?.active?.dialect || 'sqlite') as DbDialect,
          connection: String(res?.active?.connection || ''),
          ssl: !!res?.active?.ssl,
        },
        saved: res?.saved
          ? {
            dialect: res.saved.dialect as DbDialect,
            connection: String(res.saved.connection || ''),
            ssl: !!res.saved.ssl,
          }
          : null,
        restartRequired: !!res?.restartRequired,
      });
      toast.success(res?.message || 'Runtime database config saved');
    } catch (err: any) {
      toast.error(err?.message || 'Runtime database config save failed');
    } finally {
      setSavingRuntimeDatabase(false);
    }
  };

  if (loading) {
    return (
      <div className="animate-fade-in">
        <div className="skeleton" style={{ width: 220, height: 28, marginBottom: 20 }} />
        <div className="skeleton" style={{ width: '100%', height: 320, borderRadius: 'var(--radius-sm)' }} />
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">系统设置</h2>
      </div>

      <div style={{ maxWidth: 720, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="card animate-slide-up stagger-1" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>管理员登录令牌</div>
          <code style={{ display: 'block', padding: '10px 14px', background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border-light)', marginBottom: 12 }}>
            {maskedToken || '****'}
          </code>
          <button onClick={() => setShowChangeKey(true)} className="btn btn-primary">修改登录令牌</button>
          <ChangeKeyModal
            open={showChangeKey}
            onClose={() => {
              setShowChangeKey(false);
              api.getAuthInfo().then((r: any) => setMaskedToken(r.masked || '****')).catch(() => { });
            }}
          />
        </div>

        <div className="card animate-slide-up stagger-2" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>定时任务</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>签到 Cron</div>
              <input
                value={runtime.checkinCron}
                onChange={(e) => setRuntime((prev) => ({ ...prev, checkinCron: e.target.value }))}
                style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>余额刷新 Cron</div>
              <input
                value={runtime.balanceRefreshCron}
                onChange={(e) => setRuntime((prev) => ({ ...prev, balanceRefreshCron: e.target.value }))}
                style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              />
            </div>
          </div>
          <div
            style={{
              marginTop: 16,
              paddingTop: 16,
              borderTop: '1px solid var(--color-border-light)',
              display: 'grid',
              gap: 12,
            }}
          >
            <div style={{ fontWeight: 600, fontSize: 13 }}>自动清理日志</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px', gap: 12 }}>
              <div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>清理 Cron</div>
                <input
                  value={runtime.logCleanupCron}
                  onChange={(e) => setRuntime((prev) => ({ ...prev, logCleanupCron: e.target.value }))}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                />
              </div>
              <div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>保留天数</div>
                <input
                  type="number"
                  min={1}
                  value={runtime.logCleanupRetentionDays}
                  onChange={(e) => setRuntime((prev) => {
                    const nextValue = Number(e.target.value);
                    return {
                      ...prev,
                      logCleanupRetentionDays: Number.isFinite(nextValue) && nextValue >= 1
                        ? Math.trunc(nextValue)
                        : prev.logCleanupRetentionDays,
                    };
                  })}
                  style={inputStyle}
                />
              </div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)' }}>
                <input
                  type="checkbox"
                  checked={runtime.logCleanupUsageLogsEnabled}
                  onChange={(e) => setRuntime((prev) => ({ ...prev, logCleanupUsageLogsEnabled: e.target.checked }))}
                />
                清理使用日志
              </label>
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)' }}>
                <input
                  type="checkbox"
                  checked={runtime.logCleanupProgramLogsEnabled}
                  onChange={(e) => setRuntime((prev) => ({ ...prev, logCleanupProgramLogsEnabled: e.target.checked }))}
                />
                清理程序日志
              </label>
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.6 }}>
              默认每天早上 6 点执行。按每次定时任务执行时间，清理早于“保留天数”的日志；两个选项都不勾选时不会实际删除日志。
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <button onClick={saveSchedule} disabled={savingSchedule} className="btn btn-primary">
              {savingSchedule ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存定时任务'}
            </button>
          </div>
        </div>

        <div className="card animate-slide-up stagger-3" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>系统代理</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            配置一个全局出站代理地址，站点页可按站点决定是否启用系统代理。
          </div>
          <input
            value={runtime.systemProxyUrl}
            onChange={(e) => setRuntime((prev) => ({ ...prev, systemProxyUrl: e.target.value }))}
            placeholder="系统代理 URL（可选，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080）"
            style={{ ...inputStyle, fontFamily: 'var(--font-mono)', marginBottom: 10 }}
          />
          <button onClick={saveSystemProxy} disabled={savingSystemProxy} className="btn btn-primary">
            {savingSystemProxy ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存系统代理'}
          </button>
        </div>

        <div className="card animate-slide-up stagger-4" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>代理失败判定</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            命中任一关键词或空内容时判定失败，可触发重试。
          </div>
          <textarea
            value={proxyErrorKeywordsText}
            onChange={(e) => setProxyErrorKeywordsText(e.target.value)}
            placeholder="一行一个关键词，或逗号分隔"
            style={{
              ...inputStyle,
              fontFamily: 'var(--font-mono)',
              minHeight: 96,
              resize: 'vertical',
              marginBottom: 12,
            }}
          />
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 12 }}>
            <input
              type="checkbox"
              checked={runtime.proxyEmptyContentFailEnabled}
              onChange={(e) => setRuntime((prev) => ({ ...prev, proxyEmptyContentFailEnabled: e.target.checked }))}
            />
            空内容（completion=0，即使 prompt 有 token 也算）判定失败
          </label>
          <div>
            <button onClick={saveProxyFailureRules} disabled={savingProxyFailureRules} className="btn btn-primary">
              {savingProxyFailureRules ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存失败规则'}
            </button>
          </div>
        </div>

        <div className="card animate-slide-up stagger-4" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>下游访问令牌（PROXY_TOKEN）</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            用于下游站点或客户端访问本服务代理接口。前缀 sk- 固定不可修改，只需填写后缀。
          </div>
          <code style={{ display: 'block', padding: '10px 14px', background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border-light)', marginBottom: 10 }}>
            当前：{runtime.proxyTokenMasked || '未设置'}
          </code>
          <div
            style={{
              ...inputStyle,
              marginBottom: 10,
              padding: 0,
              display: 'flex',
              alignItems: 'center',
              overflow: 'hidden',
            }}
          >
            <span
              style={{
                padding: '10px 12px',
                borderRight: '1px solid var(--color-border-light)',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                color: 'var(--color-text-secondary)',
                userSelect: 'none',
              }}
            >
              {PROXY_TOKEN_PREFIX}
            </span>
            <input
              type="password"
              value={proxyTokenSuffix}
              onChange={(e) => setProxyTokenSuffix(normalizeProxyTokenSuffix(e.target.value))}
              placeholder="请输入 sk- 后的令牌内容"
              style={{
                flex: 1,
                border: 'none',
                outline: 'none',
                background: 'transparent',
                color: 'var(--color-text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                padding: '10px 12px',
              }}
            />
          </div>
          <button onClick={saveProxyToken} disabled={savingToken} className="btn btn-primary">
            {savingToken ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '更新下游访问令牌'}
          </button>
        </div>

        <div className="card animate-slide-up stagger-5" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>下游密钥管理入口已迁移</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.8 }}>
            下游 API Key 的新增、编辑、模型白名单、群组限制、趋势与用量分析，现统一收口到「控制台 / 下游密钥」页面，设置页不再保留重复管理入口。
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button onClick={() => navigate('/downstream-keys')} className="btn btn-primary">
              打开下游密钥管理页
            </button>
          </div>
        </div>

        <div className="card animate-slide-up stagger-5" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10 }}>路由策略</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            先选择预设策略，只有需要精调时再展开高级参数。
          </div>
          <div style={{ marginBottom: 12, maxWidth: 280 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>
                无实测/配置/目录价时默认单价
            </div>
            <input
              type="number"
              min={0.000001}
              step={0.000001}
              value={runtime.routingFallbackUnitCost}
              onChange={(e) => {
                const nextValue = Number(e.target.value);
                setRuntime((prev) => ({
                  ...prev,
                  routingFallbackUnitCost: Number.isFinite(nextValue) && nextValue > 0 ? nextValue : prev.routingFallbackUnitCost,
                }));
              }}
              style={inputStyle}
            />
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
            <button
              onClick={() => applyRoutingPreset('balanced')}
              className="btn btn-ghost"
              style={{
                border: activeRoutingProfile === 'balanced' ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                color: activeRoutingProfile === 'balanced' ? 'var(--color-primary)' : undefined,
              }}
            >
              均衡
            </button>
            <button
              onClick={() => applyRoutingPreset('stable')}
              className="btn btn-ghost"
              style={{
                border: activeRoutingProfile === 'stable' ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                color: activeRoutingProfile === 'stable' ? 'var(--color-primary)' : undefined,
              }}
            >
              稳定优先
            </button>
            <button
              onClick={() => applyRoutingPreset('cost')}
              className="btn btn-ghost"
              style={{
                border: activeRoutingProfile === 'cost' ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                color: activeRoutingProfile === 'cost' ? 'var(--color-primary)' : undefined,
              }}
            >
              成本优先
            </button>
            <button
              onClick={() => setShowAdvancedRouting((prev) => !prev)}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {showAdvancedRouting ? '收起高级参数' : '展开高级参数'}
            </button>
          </div>

          <div className={`anim-collapse ${showAdvancedRouting ? 'is-open' : ''}`.trim()}>
            <div className="anim-collapse-inner" style={{ paddingTop: 2 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {([
                ['baseWeightFactor', '基础权重因子'],
                ['valueScoreFactor', '价值分因子'],
                ['costWeight', '成本权重'],
                ['balanceWeight', '余额权重'],
                ['usageWeight', '使用频次权重'],
              ] as Array<[keyof RoutingWeights, string]>).map(([key, label]) => (
                <div key={key}>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>{label}</div>
                  <input
                    type="number"
                    min={0}
                    step={0.1}
                    value={runtime.routingWeights[key]}
                    onChange={(e) => {
                      const v = Number(e.target.value);
                      setRuntime((prev) => ({
                        ...prev,
                        routingWeights: {
                          ...prev.routingWeights,
                          [key]: Number.isFinite(v) ? v : 0,
                        },
                      }));
                    }}
                    style={inputStyle}
                  />
                </div>
              ))}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 12 }}>
            <button onClick={saveRouting} disabled={savingRouting} className="btn btn-primary">
              {savingRouting ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存路由策略'}
            </button>
          </div>
        </div>

        <div className="card animate-slide-up stagger-6" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10 }}>数据库迁移（SQLite / MySQL / PostgreSQL）</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            可先测试连接，再迁移数据；迁移完成后可保存为运行数据库配置（重启容器后生效）。
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 10, marginBottom: 10, alignItems: 'center' }}>
            <ModernSelect
              value={migrationDialect}
              onChange={(value) => setMigrationDialect(value as DbDialect)}
              options={[
                { value: 'postgres', label: 'PostgreSQL' },
                { value: 'mysql', label: 'MySQL' },
                { value: 'sqlite', label: 'SQLite' },
              ]}
            />
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8 }}>
              {migrationDialect !== 'sqlite' && (
                <button
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                  onClick={() => setConnectionMode((prev) => (prev === 'shorthand' ? 'advanced' : 'shorthand'))}
                >
                  {connectionMode === 'shorthand' ? '高级输入连接串' : '使用半自动简写'}
                </button>
              )}
            </div>
          </div>

          {migrationDialect === 'sqlite' ? (
            <input
              value={migrationConnectionString}
              onChange={(e) => setMigrationConnectionString(e.target.value)}
              placeholder="./data/target.db or file:///abs/path.db"
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)', marginBottom: 10 }}
            />
          ) : connectionMode === 'advanced' ? (
            <input
              value={migrationConnectionString}
              onChange={(e) => setMigrationConnectionString(e.target.value)}
              placeholder={migrationDialect === 'mysql'
                ? 'mysql://user:pass@host:3306/db'
                : 'postgres://user:pass@host:5432/db'}
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)', marginBottom: 10 }}
            />
          ) : (
            <div style={{ marginBottom: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 8 }}>
                <input
                  value={shorthandConnection.host}
                  onChange={(e) => setShorthandConnection((prev) => ({ ...prev, host: e.target.value }))}
                  placeholder="Host (required)"
                  style={inputStyle}
                />
                <input
                  value={shorthandConnection.user}
                  onChange={(e) => setShorthandConnection((prev) => ({ ...prev, user: e.target.value }))}
                  placeholder="User (required)"
                  style={inputStyle}
                />
                <input
                  value={shorthandConnection.password}
                  onChange={(e) => setShorthandConnection((prev) => ({ ...prev, password: e.target.value }))}
                  placeholder="Password (required)"
                  type="password"
                  style={inputStyle}
                />
              </div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <button
                  className="btn btn-ghost"
                  style={{ border: '1px solid var(--color-border)' }}
                  onClick={() => setShowShorthandOptional((prev) => !prev)}
                >
                  {showShorthandOptional ? '收起端口/库名' : '展开端口/库名'}
                </button>
              </div>
              {showShorthandOptional && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 8 }}>
                  <input
                    value={shorthandConnection.port}
                    onChange={(e) => setShorthandConnection((prev) => ({ ...prev, port: e.target.value }))}
                    placeholder={getDialectDefaults(migrationDialect).port}
                    style={inputStyle}
                  />
                  <input
                    value={shorthandConnection.database}
                    onChange={(e) => setShorthandConnection((prev) => ({ ...prev, database: e.target.value }))}
                    placeholder={getDialectDefaults(migrationDialect).database}
                    style={inputStyle}
                  />
                </div>
              )}
              <code style={{ display: 'block', padding: '10px 14px', background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border-light)' }}>
                {generatedConnectionString || 'Fill host/user/password to generate connection string'}
              </code>
            </div>
          )}

          {migrationDialect !== 'sqlite' && (
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 12, fontSize: 12, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={migrationSsl}
                onChange={(e) => setMigrationSsl(e.target.checked)}
                style={{ width: 14, height: 14, accentColor: 'var(--color-primary)' }}
              />
              启用 SSL/TLS 加密连接
            </label>
          )}

          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 12, fontSize: 12, color: 'var(--color-text-secondary)' }}>
            <input
              type="checkbox"
              checked={migrationOverwrite}
              onChange={(e) => setMigrationOverwrite(e.target.checked)}
              style={{ width: 14, height: 14, accentColor: 'var(--color-primary)' }}
            />
            允许覆盖目标数据库现有数据
          </label>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
            <button
              onClick={handleTestExternalDatabaseConnection}
              disabled={testingMigrationConnection || migratingDatabase || savingRuntimeDatabase}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {testingMigrationConnection ? <><span className="spinner spinner-sm" /> 测试中...</> : '测试连接'}
            </button>
            <button
              onClick={handleMigrateToExternalDatabase}
              disabled={migratingDatabase || testingMigrationConnection || savingRuntimeDatabase}
              className="btn btn-primary"
            >
              {migratingDatabase ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 迁移中...</> : '开始迁移'}
            </button>
            <button
              onClick={handleSaveRuntimeDatabaseConfig}
              disabled={savingRuntimeDatabase || migratingDatabase || testingMigrationConnection}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {savingRuntimeDatabase ? <><span className="spinner spinner-sm" /> 保存中...</> : '保存为运行数据库（重启后生效）'}
            </button>
          </div>

          {runtimeDatabaseState && (
            <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10, fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.8, marginBottom: migrationSummary ? 12 : 0 }}>
              <div>当前运行：{runtimeDatabaseState.active.dialect}（{runtimeDatabaseState.active.connection || '(empty)' }）{runtimeDatabaseState.active.ssl && ' [SSL]'}</div>
              <div>
                已保存待生效：
                {runtimeDatabaseState.saved
                  ? ` ${runtimeDatabaseState.saved.dialect}（${runtimeDatabaseState.saved.connection}）${runtimeDatabaseState.saved.ssl ? ' [SSL]' : ''}`
                  : ' 未保存'}
              </div>
              {runtimeDatabaseState.restartRequired && (
                <div style={{ color: 'var(--color-warning)' }}>检测到待生效数据库配置，请重启容器使其生效。</div>
              )}
            </div>
          )}

          {migrationSummary && (
            <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10, fontSize: 12, color: 'var(--color-text-secondary)', lineHeight: 1.8 }}>
              <div>目标：{migrationSummary.dialect}（{migrationSummary.connection}）</div>
              <div>版本：{migrationSummary.version}，时间：{new Date(migrationSummary.timestamp).toLocaleString()}</div>
              <div>迁移结果：站点 {migrationSummary.rows.sites} / 账号 {migrationSummary.rows.accounts} / 令牌 {migrationSummary.rows.accountTokens} / 路由 {migrationSummary.rows.tokenRoutes} / 通道 {migrationSummary.rows.routeChannels} / 设置 {migrationSummary.rows.settings}</div>
            </div>
          )}
        </div>

        <div className="card animate-slide-up stagger-6" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 12 }}>维护工具</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button onClick={handleClearCache} disabled={clearingCache} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
              {clearingCache ? <><span className="spinner spinner-sm" /> 清理中...</> : '清除缓存并重建路由'}
            </button>
            <button onClick={handleClearUsage} disabled={clearingUsage} className="btn btn-link btn-link-warning">
              {clearingUsage ? <><span className="spinner spinner-sm" /> 清理中...</> : '清除占用与使用日志'}
            </button>
          </div>
        </div>

        <div className="card animate-slide-up stagger-7" style={{ padding: 20, border: '1px solid color-mix(in srgb, var(--color-danger) 30%, var(--color-border))' }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10, color: 'var(--color-danger)' }}>危险操作</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.8, marginBottom: 12 }}>
            重新初始化系统会清空当前 metapi 使用中的全部数据库内容；若当前运行在外部 MySQL/Postgres，也会先清空该外部库中的 metapi 数据，然后切回默认 SQLite。
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.8, marginBottom: 14 }}>
            完成后管理员 Token 会重置为 <code style={{ fontFamily: 'var(--font-mono)' }}>{FACTORY_RESET_ADMIN_TOKEN}</code>，当前会话会立即退出并刷新页面。
          </div>
          <button onClick={() => setFactoryResetOpen(true)} className="btn btn-danger">
            重新初始化系统
          </button>
        </div>

        <div className="card animate-slide-up stagger-7" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10 }}>会话与安全</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            登录会话默认 12 小时自动过期。可选配置管理端 IP 白名单（每行一个 IP）。
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>
            当前识别到的管理端 IP（由服务端判定）：
          </div>
          <code style={{ display: 'block', padding: '10px 14px', background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border-light)', marginBottom: 10 }}>
            {runtime.currentAdminIp || '未知'}
          </code>
          <textarea
            value={adminIpAllowlistText}
            onChange={(e) => setAdminIpAllowlistText(e.target.value)}
            placeholder={'例如：\n127.0.0.1\n192.168.1.10'}
            rows={4}
            style={{ ...inputStyle, fontFamily: 'var(--font-mono)', resize: 'vertical', marginBottom: 10 }}
          />
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button onClick={saveSecuritySettings} disabled={savingSecurity} className="btn btn-primary">
              {savingSecurity ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存安全设置'}
            </button>
            <button
              onClick={() => {
                clearAuthSession(localStorage);
                window.location.reload();
              }}
              className="btn btn-danger"
            >
              退出登录
            </button>
          </div>
        </div>
      </div>
      {downstreamModalPresence.shouldRender && (() => {
        const modal = (
          <div className={`modal-backdrop ${downstreamModalPresence.isVisible ? '' : 'is-closing'}`.trim()} onClick={closeDownstreamModal}>
            <div
              className={`modal-content ${downstreamModalPresence.isVisible ? '' : 'is-closing'}`.trim()}
              style={{ maxWidth: 860 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                {editingDownstreamId ? '编辑下游 API Key' : '新增下游 API Key'}
              </div>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
                  <input
                    value={downstreamCreate.name}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, name: e.target.value }))}
                    placeholder="Name (e.g. cc-project)"
                    style={inputStyle}
                  />
                  <input
                    value={downstreamCreate.key}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, key: e.target.value.trim() }))}
                    placeholder="sk-xxxx"
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  />
                  <input
                    value={downstreamCreate.maxCost}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, maxCost: e.target.value }))}
                    placeholder="最大费用（可选）"
                    type="number"
                    min={0}
                    step={0.000001}
                    style={inputStyle}
                  />
                  <input
                    value={downstreamCreate.maxRequests}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, maxRequests: e.target.value }))}
                    placeholder="最大请求数（可选）"
                    type="number"
                    min={0}
                    step={1}
                    style={inputStyle}
                  />
                  <input
                    value={downstreamCreate.expiresAt}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, expiresAt: e.target.value }))}
                    type="datetime-local"
                    placeholder="过期时间（可选）"
                    style={inputStyle}
                  />
                  <input
                    value={downstreamCreate.description}
                    onChange={(e) => setDownstreamCreate((prev) => ({ ...prev, description: e.target.value }))}
                    placeholder="备注（可选）"
                    style={inputStyle}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                    已选模型 {downstreamCreate.selectedModels.length} 个，已选群组 {downstreamCreate.selectedGroupRouteIds.length} 个
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button
                      onClick={async () => {
                        if (selectorRoutes.length === 0) await loadRouteSelectorRoutes();
                        setSelectorModelSearch('');
                        setSelectorGroupSearch('');
                        setSelectorOpen(true);
                      }}
                      className="btn btn-ghost"
                      style={{ border: '1px solid var(--color-border)' }}
                    >
                      勾选模型和群组
                    </button>
                    {(downstreamCreate.selectedModels.length > 0 || downstreamCreate.selectedGroupRouteIds.length > 0) && (
                      <button
                        onClick={() => setDownstreamCreate((prev) => ({ ...prev, selectedModels: [], selectedGroupRouteIds: [] }))}
                        className="btn btn-link btn-link-warning"
                      >
                        清空选择
                      </button>
                    )}
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button onClick={closeDownstreamModal} className="btn btn-ghost">取消</button>
                <button onClick={saveDownstreamKey} disabled={downstreamSaving} className="btn btn-primary">
                  {downstreamSaving
                    ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</>
                    : (editingDownstreamId ? '更新 API Key' : '新增 API Key')}
                </button>
              </div>
            </div>
          </div>
        );
        return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
      })()}
      {factoryResetPresence.shouldRender && (() => {
        const confirmLabel = factoryResetting
          ? '重新初始化中...'
          : (factoryResetSecondsLeft > 0
            ? `确认重新初始化系统（${factoryResetSecondsLeft}s）`
            : '确认重新初始化系统');
        const modal = (
          <div className={`modal-backdrop ${factoryResetPresence.isVisible ? '' : 'is-closing'}`.trim()} onClick={closeFactoryResetModal}>
            <div
              className={`modal-content ${factoryResetPresence.isVisible ? '' : 'is-closing'}`.trim()}
              style={{ maxWidth: 720, border: '1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border))' }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header" style={{ color: 'var(--color-danger)' }}>确认重新初始化系统</div>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', background: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: 12, lineHeight: 1.8 }}>
                  这是不可逆操作。系统会清空当前 metapi 使用中的全部数据库内容，并在成功后立即退出当前登录状态。
                </div>
                <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.9 }}>
                  <div>• 当前若使用外部 MySQL/Postgres，也会先清空该外部库中的 metapi 数据。</div>
                  <div>• 系统随后会强制切回默认 SQLite。</div>
                  <div>• 管理员 Token 将重置为 <code style={{ fontFamily: 'var(--font-mono)' }}>{FACTORY_RESET_ADMIN_TOKEN}</code>。</div>
                  <div>• 完成后会立即退出登录并刷新页面，回到当前首装初始状态。</div>
                </div>
              </div>
              <div className="modal-footer">
                <button onClick={closeFactoryResetModal} disabled={factoryResetting} className="btn btn-ghost">取消</button>
                <button onClick={handleFactoryReset} disabled={factoryResetting || factoryResetSecondsLeft > 0} className="btn btn-danger">
                  {factoryResetting
                    ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> {confirmLabel}</>
                    : confirmLabel}
                </button>
              </div>
            </div>
          </div>
        );
        return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
      })()}
      {selectorModalPresence.shouldRender && (() => {
        const modal = (
          <div className={`modal-backdrop ${selectorModalPresence.isVisible ? '' : 'is-closing'}`.trim()} onClick={closeSelectorModal}>
            <div
              className={`modal-content ${selectorModalPresence.isVisible ? '' : 'is-closing'}`.trim()}
              style={{ maxWidth: 860 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">勾选模型和群组</div>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                  选择结果会保存到当前下游 API Key：精确模型用于模型白名单，群组用于路由范围限制。
                </div>
                {selectorLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-muted)' }}>
                    <span className="spinner spinner-sm" />
                    加载路由中...
                  </div>
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
                    <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                        精确模型 ({selectorModelSearch.trim()
                          ? `${filteredExactModelOptions.length}/${exactModelOptions.length}`
                          : exactModelOptions.length})
                      </div>
                      <input
                        value={selectorModelSearch}
                        onChange={(e) => setSelectorModelSearch(e.target.value)}
                        placeholder="搜索精确模型（支持模糊匹配）"
                        style={{ ...inputStyle, padding: '8px 10px', fontSize: 12, marginBottom: 8 }}
                      />
                      <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {exactModelOptions.length === 0 ? (
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可选精确模型</div>
                        ) : filteredExactModelOptions.length === 0 ? (
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>没有匹配的精确模型</div>
                        ) : filteredExactModelOptions.map((modelName) => {
                          const checked = downstreamCreate.selectedModels.includes(modelName);
                          const brand = getBrand(modelName);
                          return (
                            <label
                              key={modelName}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 10,
                                cursor: 'pointer',
                                border: `1px solid ${checked ? 'color-mix(in srgb, var(--color-primary) 45%, transparent)' : 'var(--color-border-light)'}`,
                                borderRadius: 10,
                                padding: '8px 10px',
                                background: checked
                                  ? 'color-mix(in srgb, var(--color-primary) 9%, var(--color-bg-card))'
                                  : 'var(--color-bg-card)',
                                transition: 'all 0.15s ease',
                              }}
                            >
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleModelSelection(modelName)}
                                style={{ width: 18, height: 18, accentColor: 'var(--color-primary)', flexShrink: 0 }}
                              />
                              <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <code
                                  style={{
                                    fontWeight: 600,
                                    fontSize: 12,
                                    background: 'var(--color-bg)',
                                    padding: '4px 10px',
                                    borderRadius: 8,
                                    color: 'var(--color-text-primary)',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: 6,
                                    maxWidth: '100%',
                                  }}
                                >
                                  {brand ? (
                                    <InlineBrandIcon model={modelName} size={18} />
                                  ) : (
                                    <span
                                      style={{
                                        width: 18,
                                        height: 18,
                                        borderRadius: 6,
                                        background: 'var(--color-bg-card)',
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        fontSize: 10,
                                        color: 'var(--color-text-muted)',
                                        flexShrink: 0,
                                      }}
                                    >
                                      {modelName.slice(0, 1).toUpperCase()}
                                    </span>
                                  )}
                                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {modelName}
                                  </span>
                                </code>
                                {brand && (
                                  <div style={{ fontSize: 11, color: 'var(--color-text-muted)', paddingLeft: 6 }}>
                                    {brand.name}
                                  </div>
                                )}
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>

                    <div style={{ border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', padding: 10 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                        群组 ({selectorGroupSearch.trim()
                          ? `${filteredGroupRouteOptions.length}/${groupRouteOptions.length}`
                          : groupRouteOptions.length})
                      </div>
                      <input
                        value={selectorGroupSearch}
                        onChange={(e) => setSelectorGroupSearch(e.target.value)}
                        placeholder="Search groups (name / pattern)"
                        style={{ ...inputStyle, padding: '8px 10px', fontSize: 12, marginBottom: 8 }}
                      />
                      <div style={{ maxHeight: 280, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {groupRouteOptions.length === 0 ? (
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可选群组</div>
                        ) : filteredGroupRouteOptions.length === 0 ? (
                          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>没有匹配的群组</div>
                        ) : filteredGroupRouteOptions.map((route) => {
                          const checked = downstreamCreate.selectedGroupRouteIds.includes(route.id);
                          const explicitBrandIcon = parseBrandIconValue(route.displayIcon);
                          const explicitNoIcon = (route.displayIcon || '').trim() === ROUTE_ICON_NONE_VALUE;
                          const textIcon = explicitBrandIcon || explicitNoIcon ? '' : (route.displayIcon || '').trim();
                          return (
                            <label
                              key={route.id}
                              style={{
                                display: 'flex',
                                alignItems: 'flex-start',
                                gap: 10,
                                cursor: 'pointer',
                                border: `1px solid ${checked ? 'color-mix(in srgb, var(--color-primary) 45%, transparent)' : 'var(--color-border-light)'}`,
                                borderRadius: 10,
                                padding: '8px 10px',
                                background: checked
                                  ? 'color-mix(in srgb, var(--color-primary) 9%, var(--color-bg-card))'
                                  : 'var(--color-bg-card)',
                                transition: 'all 0.15s ease',
                              }}
                            >
                              <input
                                type="checkbox"
                                style={{ marginTop: 4, width: 18, height: 18, accentColor: 'var(--color-primary)', flexShrink: 0 }}
                                checked={checked}
                                onChange={() => toggleGroupRouteSelection(route.id)}
                              />
                              <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <code
                                  style={{
                                    fontWeight: 600,
                                    fontSize: 12,
                                    background: 'var(--color-bg)',
                                    padding: '4px 10px',
                                    borderRadius: 8,
                                    color: 'var(--color-text-primary)',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: 6,
                                    maxWidth: '100%',
                                  }}
                                >
                                  <span
                                    style={{
                                      width: 18,
                                      height: 18,
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      justifyContent: 'center',
                                      borderRadius: 6,
                                      background: 'var(--color-bg-card)',
                                      flexShrink: 0,
                                      overflow: 'hidden',
                                      fontSize: 12,
                                      lineHeight: 1,
                                    }}
                                  >
                                    {explicitBrandIcon ? (
                                      <BrandGlyph
                                        icon={explicitBrandIcon}
                                        alt={routeTitle(route)}
                                        size={18}
                                        fallbackText={routeTitle(route)}
                                      />
                                    ) : textIcon ? (
                                      textIcon
                                    ) : explicitNoIcon ? null : (
                                      <InlineBrandIcon model={resolveRouteBrandSource(route)} size={18} />
                                    )}
                                  </span>
                                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {routeTitle(route)}
                                  </span>
                                  {!route.enabled && (
                                    <span
                                      style={{
                                        fontSize: 10,
                                        padding: '1px 6px',
                                        borderRadius: 999,
                                        background: 'var(--color-danger-bg)',
                                        color: 'var(--color-danger)',
                                      }}
                                    >
                                      已禁用
                                    </span>
                                  )}
                                </code>
                                <code style={{ fontSize: 11, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', paddingLeft: 6 }}>
                                  {route.modelPattern}
                                </code>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}
              </div>
              <div className="modal-footer">
                <button onClick={closeSelectorModal} className="btn btn-ghost">关闭</button>
              </div>
            </div>
          </div>
        );
        return typeof document !== 'undefined' ? createPortal(modal, document.body) : modal;
      })()}
    </div>
  );
}
