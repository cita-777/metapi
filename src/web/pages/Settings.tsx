import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import { useToast } from '../components/Toast.js';
import { useIsMobile } from '../components/useIsMobile.js';
import ChangeKeyModal from '../components/ChangeKeyModal.js';
import { useAnimatedVisibility } from '../components/useAnimatedVisibility.js';
import ModernSelect from '../components/ModernSelect.js';
import DownstreamApiKeyModal from './settings/DownstreamApiKeyModal.js';
import FactoryResetModal from './settings/FactoryResetModal.js';
import RouteSelectorModal from './settings/RouteSelectorModal.js';
import UpdateCenterSection from './settings/UpdateCenterSection.js';
import {
  applyRoutingProfilePreset,
  resolveRoutingProfilePreset,
  type RoutingWeights,
} from './helpers/routingProfiles.js';
import { fuzzyMatch } from './helpers/fuzzySearch.js';
import { clearAuthSession } from '../authSession.js';
import { clearAppInstallationState } from '../appLocalState.js';
import { tr } from '../i18n.js';
import {
  isExactModelPattern,
  resolveRouteTitle,
} from './token-routes/utils.js';
import { generateDownstreamSkKey } from './helpers/generateDownstreamSkKey.js';

const PROXY_TOKEN_PREFIX = 'sk-';
const FACTORY_RESET_ADMIN_TOKEN = 'change-me-admin-token';
const FACTORY_RESET_CONFIRM_SECONDS = 3;
const SECONDS_PER_DAY = 24 * 60 * 60;
const ROUTE_COOLDOWN_UNIT_OPTIONS = [
  { value: 'second', label: '秒', multiplierSec: 1 },
  { value: 'minute', label: '分钟', multiplierSec: 60 },
  { value: 'hour', label: '小时', multiplierSec: 60 * 60 },
  { value: 'day', label: '天', multiplierSec: SECONDS_PER_DAY },
] as const;
const CHECKIN_SCHEDULE_MODE_OPTIONS = [
  { value: 'cron', label: 'Cron' },
  { value: 'interval', label: '间隔签到' },
] as const;
const CHECKIN_INTERVAL_OPTIONS = Array.from({ length: 24 }, (_, index) => {
  const hour = index + 1;
  return {
    value: String(hour),
    label: `${hour} 小时`,
  };
});
type DbDialect = 'sqlite' | 'mysql' | 'postgres';
type RouteCooldownUnit = typeof ROUTE_COOLDOWN_UNIT_OPTIONS[number]['value'];

type RuntimeSettings = {
  checkinCron: string;
  checkinScheduleMode: 'cron' | 'interval';
  checkinIntervalHours: number;
  balanceRefreshCron: string;
  logCleanupCron: string;
  logCleanupUsageLogsEnabled: boolean;
  logCleanupProgramLogsEnabled: boolean;
  logCleanupRetentionDays: number;
  codexUpstreamWebsocketEnabled: boolean;
  disableCrossProtocolFallback: boolean;
  proxySessionChannelConcurrencyLimit: number;
  proxySessionChannelQueueWaitMs: number;
  routingFallbackUnitCost: number;
  routeFailureCooldownMaxValue: number;
  routeFailureCooldownMaxUnit: RouteCooldownUnit;
  routingWeights: RoutingWeights;
  systemProxyUrl: string;
  proxyErrorKeywords: string[];
  proxyEmptyContentFailEnabled: boolean;
  proxyTokenMasked?: string;
  adminIpAllowlist?: string[];
  currentAdminIp?: string;
  globalBlockedBrands?: string[];
  globalAllowedModels?: string[];
};

type SystemProxyTestState =
  | { kind: 'success'; text: string }
  | { kind: 'error'; text: string }
  | null;

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

function resolveRouteCooldownInput(seconds: number | null | undefined): {
  value: number;
  unit: RouteCooldownUnit;
} {
  const normalizedSeconds = Number.isFinite(Number(seconds)) && Number(seconds) > 0
    ? Math.max(1, Math.trunc(Number(seconds)))
    : 30 * SECONDS_PER_DAY;

  for (const option of [...ROUTE_COOLDOWN_UNIT_OPTIONS].reverse()) {
    if (normalizedSeconds % option.multiplierSec === 0) {
      return {
        value: normalizedSeconds / option.multiplierSec,
        unit: option.value,
      };
    }
  }

  return {
    value: normalizedSeconds,
    unit: 'second',
  };
}

function toRouteCooldownSeconds(value: number, unit: RouteCooldownUnit): number {
  const normalizedValue = Number.isFinite(value) && value > 0 ? Math.max(1, Math.trunc(value)) : 1;
  const unitConfig = ROUTE_COOLDOWN_UNIT_OPTIONS.find((option) => option.value === unit) || ROUTE_COOLDOWN_UNIT_OPTIONS[0];
  return normalizedValue * unitConfig.multiplierSec;
}

export default function Settings() {
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const [runtime, setRuntime] = useState<RuntimeSettings>({
    checkinCron: '0 8 * * *',
    checkinScheduleMode: 'cron',
    checkinIntervalHours: 6,
    balanceRefreshCron: '0 * * * *',
    logCleanupCron: '0 6 * * *',
    logCleanupUsageLogsEnabled: false,
    logCleanupProgramLogsEnabled: false,
    logCleanupRetentionDays: 30,
    codexUpstreamWebsocketEnabled: false,
    disableCrossProtocolFallback: false,
    proxySessionChannelConcurrencyLimit: 2,
    proxySessionChannelQueueWaitMs: 1500,
    routingFallbackUnitCost: 1,
    routeFailureCooldownMaxValue: 30,
    routeFailureCooldownMaxUnit: 'day',
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
  const [testingCheckin, setTestingCheckin] = useState(false);
  const [savingToken, setSavingToken] = useState(false);
  const [savingSystemProxy, setSavingSystemProxy] = useState(false);
  const [savingProxyTransport, setSavingProxyTransport] = useState(false);
  const [testingSystemProxy, setTestingSystemProxy] = useState(false);
  const [systemProxyTestState, setSystemProxyTestState] = useState<SystemProxyTestState>(null);
  const [savingProxyFailureRules, setSavingProxyFailureRules] = useState(false);
  const [savingRouting, setSavingRouting] = useState(false);
  const [showAdvancedRouting, setShowAdvancedRouting] = useState(false);
  const [allBrandNames, setAllBrandNames] = useState<string[] | null>(null);
  const [blockedBrands, setBlockedBrands] = useState<string[]>([]);
  const [savingBrandFilter, setSavingBrandFilter] = useState(false);
  const [availableModels, setAvailableModels] = useState<string[] | null>(null);
  const [allowedModels, setAllowedModels] = useState<string[]>([]);
  const [allowedModelsInput, setAllowedModelsInput] = useState('');
  const [savingAllowedModels, setSavingAllowedModels] = useState(false);
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
      .sort((a, b) => resolveRouteTitle(a).localeCompare(resolveRouteTitle(b), undefined, { sensitivity: 'base' }))
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
      const matchText = `${resolveRouteTitle(route)} ${route.modelPattern}`;
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
      const routeCooldownInput = resolveRouteCooldownInput(runtimeInfo.tokenRouterFailureCooldownMaxSec);
      setRuntime({
        checkinCron: runtimeInfo.checkinCron || '0 8 * * *',
        checkinScheduleMode: runtimeInfo.checkinScheduleMode === 'interval' ? 'interval' : 'cron',
        checkinIntervalHours: Number(runtimeInfo.checkinIntervalHours) >= 1
          ? Math.min(24, Math.trunc(Number(runtimeInfo.checkinIntervalHours)))
          : 6,
        balanceRefreshCron: runtimeInfo.balanceRefreshCron || '0 * * * *',
        logCleanupCron: runtimeInfo.logCleanupCron || '0 6 * * *',
        logCleanupUsageLogsEnabled: !!runtimeInfo.logCleanupUsageLogsEnabled,
        logCleanupProgramLogsEnabled: !!runtimeInfo.logCleanupProgramLogsEnabled,
        logCleanupRetentionDays: Number(runtimeInfo.logCleanupRetentionDays) >= 1
          ? Math.trunc(Number(runtimeInfo.logCleanupRetentionDays))
          : 30,
        codexUpstreamWebsocketEnabled: !!runtimeInfo.codexUpstreamWebsocketEnabled,
        disableCrossProtocolFallback: !!runtimeInfo.disableCrossProtocolFallback,
        proxySessionChannelConcurrencyLimit: Number(runtimeInfo.proxySessionChannelConcurrencyLimit) >= 0
          ? Math.trunc(Number(runtimeInfo.proxySessionChannelConcurrencyLimit))
          : 2,
        proxySessionChannelQueueWaitMs: Number(runtimeInfo.proxySessionChannelQueueWaitMs) >= 0
          ? Math.trunc(Number(runtimeInfo.proxySessionChannelQueueWaitMs))
          : 1500,
        routingFallbackUnitCost: Number(runtimeInfo.routingFallbackUnitCost) > 0
          ? Number(runtimeInfo.routingFallbackUnitCost)
          : 1,
        routeFailureCooldownMaxValue: routeCooldownInput.value,
        routeFailureCooldownMaxUnit: routeCooldownInput.unit,
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
        globalBlockedBrands: Array.isArray(runtimeInfo.globalBlockedBrands) ? runtimeInfo.globalBlockedBrands : [],
        globalAllowedModels: Array.isArray(runtimeInfo.globalAllowedModels) ? runtimeInfo.globalAllowedModels : [],
      });
      setBlockedBrands(Array.isArray(runtimeInfo.globalBlockedBrands) ? runtimeInfo.globalBlockedBrands : []);
      setAllowedModels(Array.isArray(runtimeInfo.globalAllowedModels) ? runtimeInfo.globalAllowedModels : []);
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
    // Load brand list in background (non-blocking, best-effort)
    api.getBrandList()
      .then((res: any) => setAllBrandNames(Array.isArray(res?.brands) ? res.brands : []))
      .catch(() => setAllBrandNames([]));
    // Load available models in background (non-blocking, best-effort)
    api.getModelTokenCandidates()
      .then((res: any) => {
        const models = res?.models || {};
        const modelNames = Object.keys(models);
        setAvailableModels(modelNames.sort());
      })
      .catch(() => setAvailableModels([]));
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
        checkinScheduleMode: runtime.checkinScheduleMode,
        checkinIntervalHours: runtime.checkinIntervalHours,
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

  const triggerScheduleCheckin = async () => {
    setTestingCheckin(true);
    try {
      await api.triggerCheckinAll();
      toast.success('已开始全部签到，请稍后查看签到日志');
    } catch (err: any) {
      toast.error(err?.message || '触发签到失败');
    } finally {
      setTestingCheckin(false);
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

  const saveProxyTransportSettings = async () => {
    setSavingProxyTransport(true);
    try {
      const res = await api.updateRuntimeSettings({
        codexUpstreamWebsocketEnabled: runtime.codexUpstreamWebsocketEnabled,
        proxySessionChannelConcurrencyLimit: runtime.proxySessionChannelConcurrencyLimit,
        proxySessionChannelQueueWaitMs: runtime.proxySessionChannelQueueWaitMs,
      });
      setRuntime((prev) => ({
        ...prev,
        codexUpstreamWebsocketEnabled: typeof res?.codexUpstreamWebsocketEnabled === 'boolean'
          ? res.codexUpstreamWebsocketEnabled
          : prev.codexUpstreamWebsocketEnabled,
        proxySessionChannelConcurrencyLimit: Number(res?.proxySessionChannelConcurrencyLimit) >= 0
          ? Math.trunc(Number(res.proxySessionChannelConcurrencyLimit))
          : prev.proxySessionChannelConcurrencyLimit,
        proxySessionChannelQueueWaitMs: Number(res?.proxySessionChannelQueueWaitMs) >= 0
          ? Math.trunc(Number(res.proxySessionChannelQueueWaitMs))
          : prev.proxySessionChannelQueueWaitMs,
      }));
      toast.success('传输与会话并发设置已保存');
    } catch (err: any) {
      toast.error(err?.message || '保存失败');
    } finally {
      setSavingProxyTransport(false);
    }
  };

  const testSystemProxy = async () => {
    const proxyUrl = runtime.systemProxyUrl.trim();
    if (!proxyUrl) {
      const message = '请先填写系统代理地址';
      setSystemProxyTestState({ kind: 'error', text: message });
      toast.info(message);
      return;
    }

    setTestingSystemProxy(true);
    setSystemProxyTestState(null);
    try {
      const res = await api.testSystemProxy({ proxyUrl });
      const summary = `连通成功，延迟 ${res.latencyMs} ms`;
      setSystemProxyTestState({ kind: 'success', text: summary });
      toast.success(`系统代理测试成功（${res.latencyMs} ms）`);
    } catch (err: any) {
      const message = err?.message || '系统代理测试失败';
      setSystemProxyTestState({ kind: 'error', text: message });
      toast.error(message);
    } finally {
      setTestingSystemProxy(false);
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
        tokenRouterFailureCooldownMaxSec: toRouteCooldownSeconds(
          runtime.routeFailureCooldownMaxValue,
          runtime.routeFailureCooldownMaxUnit,
        ),
        disableCrossProtocolFallback: runtime.disableCrossProtocolFallback,
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

  const handleSaveBrandFilter = async () => {
    setSavingBrandFilter(true);
    try {
      const res = await api.updateRuntimeSettings({ globalBlockedBrands: blockedBrands });
      const resolved = Array.isArray(res?.globalBlockedBrands) ? res.globalBlockedBrands : blockedBrands;
      setRuntime((prev) => ({ ...prev, globalBlockedBrands: resolved }));
      setBlockedBrands(resolved);
      toast.success('品牌屏蔽设置已保存');
      try {
        await api.rebuildRoutes(false);
        toast.success('路由已重建');
      } catch {
        toast.error('品牌屏蔽已保存，但路由重建失败，请手动重建');
      }
    } catch (err: any) {
      toast.error(err?.message || '保存品牌屏蔽设置失败');
    } finally {
      setSavingBrandFilter(false);
    }
  };

  const handleSaveAllowedModels = async () => {
    setSavingAllowedModels(true);
    try {
      const res = await api.updateRuntimeSettings({ globalAllowedModels: allowedModels });
      const resolved = Array.isArray(res?.globalAllowedModels) ? res.globalAllowedModels : allowedModels;
      setRuntime((prev) => ({ ...prev, globalAllowedModels: resolved }));
      setAllowedModels(resolved);
      toast.success('模型白名单设置已保存');
      try {
        await api.rebuildRoutes(false);
        toast.success('路由已重建');
      } catch {
        toast.error('模型白名单已保存，但路由重建失败，请手动重建');
      }
    } catch (err: any) {
      toast.error(err?.message || '保存模型白名单设置失败');
    } finally {
      setSavingAllowedModels(false);
    }
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
          <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '180px 180px auto', gap: 12, alignItems: 'end', marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>签到方式</div>
              <ModernSelect
                value={runtime.checkinScheduleMode}
                onChange={(value) => setRuntime((prev) => ({
                  ...prev,
                  checkinScheduleMode: value === 'interval' ? 'interval' : 'cron',
                }))}
                options={CHECKIN_SCHEDULE_MODE_OPTIONS.map((item) => ({ ...item }))}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>签到间隔</div>
              <ModernSelect
                value={String(runtime.checkinIntervalHours)}
                onChange={(value) => setRuntime((prev) => ({
                  ...prev,
                  checkinIntervalHours: Math.min(24, Math.max(1, Math.trunc(Number(value) || 1))),
                }))}
                disabled={runtime.checkinScheduleMode !== 'interval'}
                options={CHECKIN_INTERVAL_OPTIONS}
              />
            </div>
            <button
              onClick={triggerScheduleCheckin}
              disabled={testingCheckin}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)', whiteSpace: 'nowrap' }}
            >
              {testingCheckin ? '触发中...' : '测试一次签到'}
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>签到 Cron</div>
              <input
                value={runtime.checkinCron}
                onChange={(e) => setRuntime((prev) => ({ ...prev, checkinCron: e.target.value }))}
                style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                disabled={runtime.checkinScheduleMode !== 'cron'}
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
            <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 160px', gap: 12 }}>
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
            onChange={(e) => {
              setRuntime((prev) => ({ ...prev, systemProxyUrl: e.target.value }));
              setSystemProxyTestState(null);
            }}
            placeholder="系统代理 URL（可选，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080）"
            style={{ ...inputStyle, fontFamily: 'var(--font-mono)', marginBottom: 10 }}
          />
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            <button onClick={saveSystemProxy} disabled={savingSystemProxy} className="btn btn-primary">
              {savingSystemProxy ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存系统代理'}
            </button>
            <button
              onClick={testSystemProxy}
              disabled={testingSystemProxy}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              {testingSystemProxy ? <><span className="spinner spinner-sm" /> 测试中...</> : '测试系统代理'}
            </button>
          </div>
          {systemProxyTestState && (
            <div
              style={{
                fontSize: 12,
                marginTop: 10,
                color: systemProxyTestState.kind === 'success'
                  ? 'var(--color-success)'
                  : 'var(--color-danger)',
              }}
            >
              {systemProxyTestState.text}
            </div>
          )}
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
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>Codex 上游传输与会话并发</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.7 }}>
            默认采用 HTTP 优先。只有这里开启后，metapi 才会在 Codex 请求上尝试把上游升级为 WebSocket。
            下游 Codex 客户端也必须同时启用 `/v1/responses` websocket，单开这里不会生效。
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.7 }}>
            从旧版本升级时，原先账号 `extraConfig.websockets` 的行为不再单独生效；现在统一以这里的全局设置和下游客户端是否开启为准。
          </div>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 14 }}>
            <input
              type="checkbox"
              checked={runtime.codexUpstreamWebsocketEnabled}
              onChange={(e) => setRuntime((prev) => ({ ...prev, codexUpstreamWebsocketEnabled: e.target.checked }))}
            />
            允许 metapi 到 Codex 上游使用 WebSocket
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: 12, marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>会话通道并发上限</div>
              <input
                type="number"
                min={0}
                value={runtime.proxySessionChannelConcurrencyLimit}
                onChange={(e) => {
                  const nextValue = Number(e.target.value);
                  setRuntime((prev) => ({
                    ...prev,
                    proxySessionChannelConcurrencyLimit: Number.isFinite(nextValue) && nextValue >= 0
                      ? Math.trunc(nextValue)
                      : prev.proxySessionChannelConcurrencyLimit,
                  }));
                }}
                style={inputStyle}
              />
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>排队等待时间（毫秒）</div>
              <input
                type="number"
                min={0}
                step={100}
                value={runtime.proxySessionChannelQueueWaitMs}
                onChange={(e) => {
                  const nextValue = Number(e.target.value);
                  setRuntime((prev) => ({
                    ...prev,
                    proxySessionChannelQueueWaitMs: Number.isFinite(nextValue) && nextValue >= 0
                      ? Math.trunc(nextValue)
                      : prev.proxySessionChannelQueueWaitMs,
                  }));
                }}
                style={inputStyle}
              />
            </div>
          </div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.7 }}>
            这组 lease 只作用于能识别稳定 `session_id` 的会话型请求；没有稳定会话标识的普通请求不会进入这个池。
          </div>
          <div>
            <button onClick={saveProxyTransportSettings} disabled={savingProxyTransport} className="btn btn-primary">
              {savingProxyTransport ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存传输与并发'}
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
              display: 'flex',
              gap: 10,
              alignItems: 'stretch',
              marginBottom: 10,
              minWidth: 0,
              flexWrap: 'wrap',
            }}
          >
            <div
              style={{
                ...inputStyle,
                flex: 1,
                minWidth: 200,
                marginBottom: 0,
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
                  background: 'color-mix(in srgb, var(--color-text-muted) 6%, transparent)',
                }}
              >
                {PROXY_TOKEN_PREFIX}
              </span>
              <input
                type="text"
                value={proxyTokenSuffix}
                onChange={(e) => setProxyTokenSuffix(normalizeProxyTokenSuffix(e.target.value))}
                placeholder="请输入 sk- 后的令牌内容"
                style={{
                  flex: 1,
                  minWidth: 0,
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
            <button
              type="button"
              className="btn btn-soft-primary"
              aria-label="随机生成访问令牌后缀"
              title="生成高熵随机后缀（不会自动保存）"
              style={{
                flexShrink: 0,
                padding: '10px 18px',
                fontSize: 13,
                gap: 8,
                alignSelf: 'stretch',
              }}
              onClick={() => {
                const full = generateDownstreamSkKey(PROXY_TOKEN_PREFIX);
                setProxyTokenSuffix(full.slice(PROXY_TOKEN_PREFIX.length));
              }}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden>
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z"
                />
              </svg>
              随机生成
            </button>
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
          <div style={{ marginBottom: 12, maxWidth: 420 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>
              普通失败冷却上限
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'stretch', flexWrap: 'wrap' }}>
              <input
                type="number"
                aria-label="路由失败冷却上限数值"
                min={1}
                step={1}
                value={runtime.routeFailureCooldownMaxValue}
                onChange={(e) => {
                  const nextValue = Number(e.target.value);
                  setRuntime((prev) => ({
                    ...prev,
                    routeFailureCooldownMaxValue: Number.isFinite(nextValue) && nextValue > 0
                      ? Math.max(1, Math.trunc(nextValue))
                      : prev.routeFailureCooldownMaxValue,
                  }));
                }}
                style={{ ...inputStyle, flex: '1 1 180px', marginBottom: 0 }}
              />
              <div style={{ width: 132, minWidth: 132 }}>
                <ModernSelect
                  size="sm"
                  value={runtime.routeFailureCooldownMaxUnit}
                  onChange={(nextValue) => {
                    setRuntime((prev) => ({
                      ...prev,
                      routeFailureCooldownMaxUnit: nextValue as RouteCooldownUnit,
                    }));
                  }}
                  options={ROUTE_COOLDOWN_UNIT_OPTIONS.map((option) => ({
                    value: option.value,
                    label: option.label,
                  }))}
                  placeholder="选择单位"
                />
              </div>
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 6, lineHeight: 1.6 }}>
              支持秒、分钟、小时、天。只封顶普通失败与轮询分级冷却；429 限额类冷却仍优先遵循上游 reset 提示，避免过早重试。
            </div>
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

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 12, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={runtime.disableCrossProtocolFallback}
              onChange={(e) => setRuntime((prev) => ({
                ...prev,
                disableCrossProtocolFallback: e.target.checked,
              }))}
              style={{ marginTop: 2 }}
            />
            <span>
              <span style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                失败时不尝试其他协议
              </span>
              <span style={{ display: 'block', fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.7 }}>
                仅影响 chat / messages / responses 之间的协议切换；不会关闭同协议兼容重试、OAuth 刷新或通道级重试。
              </span>
            </span>
          </label>

          <div className={`anim-collapse ${showAdvancedRouting ? 'is-open' : ''}`.trim()}>
            <div className="anim-collapse-inner" style={{ paddingTop: 2 }}>
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: 12 }}>
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

        {/* Global Brand Filter */}
        <div className="card animate-slide-up stagger-6" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>全局品牌屏蔽</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.6 }}>
            屏蔽选定品牌后，路由重建时将自动跳过匹配该品牌的所有模型。点击品牌切换屏蔽状态，保存后自动触发路由重建。
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
            {(allBrandNames || []).map((brand) => {
              const isBlocked = blockedBrands.includes(brand);
              return (
                <button
                  key={brand}
                  type="button"
                  role="switch"
                  aria-checked={isBlocked}
                  onClick={() => {
                    if (isBlocked) {
                      setBlockedBrands((prev) => prev.filter((b) => b !== brand));
                    } else {
                      setBlockedBrands((prev) => [...prev, brand]);
                    }
                  }}
                  className={`badge ${isBlocked ? 'badge-warning' : 'badge-muted'}`}
                  style={{
                    fontSize: 12, cursor: 'pointer', border: 'none', padding: '5px 12px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  {brand}
                </button>
              );
            })}
            {allBrandNames === null && (
              <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>加载品牌列表中...</span>
            )}
            {allBrandNames !== null && allBrandNames.length === 0 && (
              <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无可用品牌</span>
            )}
          </div>
          {blockedBrands.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--color-warning)', marginBottom: 10 }}>
              已屏蔽 {blockedBrands.length} 个品牌：{blockedBrands.join('、')}
            </div>
          )}
          <button onClick={handleSaveBrandFilter} disabled={savingBrandFilter} className="btn btn-primary" style={{ fontSize: 12, padding: '6px 16px' }}>
            {savingBrandFilter ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存品牌屏蔽'}
          </button>
        </div>

        {/* Global Allowed Models Whitelist */}
        <div className="card animate-slide-up stagger-7" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>全局模型白名单</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12, lineHeight: 1.6 }}>
            配置白名单后，路由重建和候选生成将只针对白名单中的模型。留空表示允许所有模型（向后兼容）。保存后自动触发路由重建。
          </div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <input
                type="text"
                placeholder="输入模型名称，如：gpt-4"
                value={allowedModelsInput}
                onChange={(e) => setAllowedModelsInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && allowedModelsInput.trim()) {
                    const model = allowedModelsInput.trim();
                    if (!allowedModels.includes(model)) {
                      setAllowedModels((prev) => [...prev, model]);
                    }
                    setAllowedModelsInput('');
                  }
                }}
                style={{ flex: 1, ...inputStyle }}
              />
              <button
                onClick={() => {
                  if (allowedModelsInput.trim()) {
                    const model = allowedModelsInput.trim();
                    if (!allowedModels.includes(model)) {
                      setAllowedModels((prev) => [...prev, model]);
                    }
                    setAllowedModelsInput('');
                  }
                }}
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)', fontSize: 12, padding: '6px 12px' }}
              >
                添加
              </button>
            </div>
            {availableModels && availableModels.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>
                  或从当前可用模型中选择：
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 120, overflowY: 'auto', border: '1px solid var(--color-border)', padding: 8, borderRadius: 4 }}>
                  {availableModels.map((model) => {
                    const isAllowed = allowedModels.includes(model);
                    return (
                      <button
                        key={model}
                        type="button"
                        onClick={() => {
                          if (isAllowed) {
                            setAllowedModels((prev) => prev.filter((m) => m !== model));
                          } else {
                            setAllowedModels((prev) => [...prev, model]);
                          }
                        }}
                        className={`badge ${isAllowed ? 'badge-success' : 'badge-muted'}`}
                        style={{
                          fontSize: 11, cursor: 'pointer', border: 'none', padding: '4px 10px',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        {model}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {allowedModels.length > 0 && (
              <div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6 }}>
                  已选择 {allowedModels.length} 个模型：
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {allowedModels.map((model) => (
                    <div
                      key={model}
                      className="badge badge-success"
                      style={{ fontSize: 11, padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 4 }}
                    >
                      {model}
                      <button
                        onClick={() => setAllowedModels((prev) => prev.filter((m) => m !== model))}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'inherit',
                          cursor: 'pointer',
                          padding: 0,
                          fontSize: 14,
                          lineHeight: 1,
                        }}
                        title="移除"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          <button onClick={handleSaveAllowedModels} disabled={savingAllowedModels} className="btn btn-primary" style={{ fontSize: 12, padding: '6px 16px' }}>
            {savingAllowedModels ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存模型白名单'}
          </button>
        </div>

        <div className="card animate-slide-up stagger-8" style={{ padding: 20 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 10 }}>数据库迁移（SQLite / MySQL / PostgreSQL）</div>
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
            可先测试连接，再迁移数据；迁移完成后可保存为运行数据库配置（重启容器后生效）。
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '180px 1fr', gap: 10, marginBottom: 10, alignItems: 'center' }}>
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
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr 1fr', gap: 10, marginBottom: 8 }}>
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
                <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: 10, marginBottom: 8 }}>
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

        <UpdateCenterSection />

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
      <DownstreamApiKeyModal
        presence={downstreamModalPresence}
        editingDownstreamId={editingDownstreamId}
        downstreamCreate={downstreamCreate}
        downstreamSaving={downstreamSaving}
        inputStyle={inputStyle}
        onChange={(updater) => setDownstreamCreate((prev) => updater(prev))}
        onOpenSelector={async () => {
          if (selectorRoutes.length === 0) await loadRouteSelectorRoutes();
          setSelectorModelSearch('');
          setSelectorGroupSearch('');
          setSelectorOpen(true);
        }}
        onClose={closeDownstreamModal}
        onSave={saveDownstreamKey}
      />
      <FactoryResetModal
        presence={factoryResetPresence}
        factoryResetting={factoryResetting}
        factoryResetSecondsLeft={factoryResetSecondsLeft}
        adminToken={FACTORY_RESET_ADMIN_TOKEN}
        onClose={closeFactoryResetModal}
        onConfirm={handleFactoryReset}
      />
      <RouteSelectorModal
        presence={selectorModalPresence}
        loading={selectorLoading}
        exactModelOptions={exactModelOptions}
        filteredExactModelOptions={filteredExactModelOptions}
        groupRouteOptions={groupRouteOptions}
        filteredGroupRouteOptions={filteredGroupRouteOptions}
        selectorModelSearch={selectorModelSearch}
        selectorGroupSearch={selectorGroupSearch}
        onSelectorModelSearchChange={setSelectorModelSearch}
        onSelectorGroupSearchChange={setSelectorGroupSearch}
        selection={{
          selectedModels: downstreamCreate.selectedModels,
          selectedGroupRouteIds: downstreamCreate.selectedGroupRouteIds,
        }}
        onToggleModelSelection={toggleModelSelection}
        onToggleGroupRouteSelection={toggleGroupRouteSelection}
        onClose={closeSelectorModal}
        inputStyle={inputStyle}
      />
    </div>
  );
}
