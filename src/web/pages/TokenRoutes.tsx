import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { arrayMove } from '@dnd-kit/sortable';
import type { DragEndEvent } from '@dnd-kit/core';
import { api } from '../api.js';
import { BrandGlyph, getBrand, InlineBrandIcon, type BrandInfo } from '../components/BrandIcon.js';
import { useToast } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import { MobileDrawer } from '../components/MobileDrawer.js';
import { useIsMobile } from '../components/useIsMobile.js';
import { tr } from '../i18n.js';
import {
  buildRouteModelCandidatesIndex,
  type RouteCandidateView,
  type RouteModelCandidatesByModelName,
} from './helpers/routeModelCandidatesIndex.js';
import { getInitialVisibleCount, getNextVisibleCount } from './helpers/progressiveRender.js';
import {
  buildRouteMissingTokenIndex,
  normalizeMissingTokenModels,
  type MissingTokenModelsByName,
} from './helpers/routeMissingTokenHints.js';
import { buildVisibleRouteList } from './helpers/routeListVisibility.js';
import { buildZeroChannelPlaceholderRoutes } from './helpers/zeroChannelRoutes.js';

import type {
  RouteSortBy,
  RouteSortDir,
  GroupFilter,
  RouteSummaryRow,
  RouteRoutingStrategy,
  RouteMode,
  RouteDecision,
  RouteIconOption,
  MissingTokenRouteSiteActionItem,
  MissingTokenGroupRouteSiteActionItem,
  GroupRouteItem,
} from './token-routes/types.js';
import {
  AUTO_ROUTE_DECISION_LIMIT,
  ROUTE_RENDER_CHUNK,
  isExactModelPattern,
  isExplicitGroupRoute,
  isRouteExactModel,
  matchesModelPattern,
  normalizeRouteMode,
  resolveRouteTitle,
  resolveRouteBrand,
  resolveRouteIcon,
  toBrandIconValue,
  normalizeRouteDisplayIconValue,
  inferEndpointTypesFromPlatform,
  getModelPatternError,
} from './token-routes/utils.js';
import { useRouteChannels } from './token-routes/useRouteChannels.js';
import RouteFilterBar from './token-routes/RouteFilterBar.js';
import ManualRoutePanel from './token-routes/ManualRoutePanel.js';
import RouteCard from './token-routes/RouteCard.js';
import AddChannelModal from './token-routes/AddChannelModal.js';

const EMPTY_ROUTE_CANDIDATE_VIEW: RouteCandidateView = {
  routeCandidates: [],
  accountOptions: [],
  tokenOptionsByAccountId: {},
};
const EMPTY_MISSING_ITEMS: MissingTokenRouteSiteActionItem[] = [];
const EMPTY_MISSING_GROUP_ITEMS: MissingTokenGroupRouteSiteActionItem[] = [];
const ROUTE_ICON_OPTIONS: RouteIconOption[] = [
  { value: '', label: '自动品牌图标', description: '按模型匹配规则自动识别品牌', iconText: '✦' },
];

type RouteEditorForm = {
  routeMode: RouteMode;
  displayName: string;
  displayIcon: string;
  modelPattern: string;
  sourceRouteIds: number[];
  advancedOpen: boolean;
};

const EMPTY_ROUTE_FORM: RouteEditorForm = {
  routeMode: 'explicit_group',
  displayName: '',
  displayIcon: '',
  modelPattern: '',
  sourceRouteIds: [],
  advancedOpen: false,
};

export default function TokenRoutes() {
  const navigate = useNavigate();
  const [routeSummaries, setRouteSummaries] = useState<RouteSummaryRow[]>([]);
  const [modelCandidates, setModelCandidates] = useState<RouteModelCandidatesByModelName>({});
  const [missingTokenModelsByName, setMissingTokenModelsByName] = useState<MissingTokenModelsByName>({});
  const [missingTokenGroupModelsByName, setMissingTokenGroupModelsByName] = useState<MissingTokenModelsByName>({});
  const [endpointTypesByModel, setEndpointTypesByModel] = useState<Record<string, string[]>>({});

  const [search, setSearch] = useState('');
  const [activeBrand, setActiveBrand] = useState<string | null>(null);
  const [activeSite, setActiveSite] = useState<string | null>(null);
  const [activeEndpointType, setActiveEndpointType] = useState<string | null>(null);
  const [activeGroupFilter, setActiveGroupFilter] = useState<GroupFilter>(null);
  const [filterCollapsed, setFilterCollapsed] = useState(true);
  const [showFilters, setShowFilters] = useState(false);
  const [showZeroChannelRoutes, setShowZeroChannelRoutes] = useState(false);
  const [sortBy, setSortBy] = useState<RouteSortBy>('channelCount');
  const [sortDir, setSortDir] = useState<RouteSortDir>('desc');

  const [showManual, setShowManual] = useState(false);
  const [form, setForm] = useState<RouteEditorForm>(EMPTY_ROUTE_FORM);
  const [editingRouteId, setEditingRouteId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);

  const [channelTokenDraft, setChannelTokenDraft] = useState<Record<number, number>>({});
  const [updatingChannel, setUpdatingChannel] = useState<Record<number, boolean>>({});
  const [savingPriorityByRoute, setSavingPriorityByRoute] = useState<Record<number, boolean>>({});
  const [updatingRoutingStrategyByRoute, setUpdatingRoutingStrategyByRoute] = useState<Record<number, boolean>>({});

  const [decisionByRoute, setDecisionByRoute] = useState<Record<number, RouteDecision | null>>({});
  const [loadingDecision, setLoadingDecision] = useState(false);
  const [decisionAutoSkipped, setDecisionAutoSkipped] = useState(false);
  const [visibleRouteCount, setVisibleRouteCount] = useState(ROUTE_RENDER_CHUNK);
  const [expandedSourceGroupMap, setExpandedSourceGroupMap] = useState<Record<string, boolean>>({});
  const [expandedRouteIds, setExpandedRouteIds] = useState<number[]>([]);
  const [addChannelModalRouteId, setAddChannelModalRouteId] = useState<number | null>(null);
  const isMobile = useIsMobile(768);

  const {
    channelsByRouteId,
    loadingChannelsByRouteId,
    loadChannels,
    invalidateChannels,
    setChannels,
  } = useRouteChannels();

  const toast = useToast();

  const loadRouteDecisions = async (
    routeRows: RouteSummaryRow[],
    options?: { force?: boolean; refreshPricingCatalog?: boolean; persistSnapshots?: boolean },
  ) => {
    const rows = routeRows || [];
    const exactRoutes = rows.filter((route) => isRouteExactModel(route));
    const wildcardRouteIds = rows
      .filter((route) => !isRouteExactModel(route))
      .map((route) => route.id);

    const requestedModels = Array.from(new Set<string>(exactRoutes.map((route) => route.modelPattern)));

    const defaultState: Record<number, RouteDecision | null> = {};
    for (const route of rows) defaultState[route.id] = null;

    if (requestedModels.length === 0 && wildcardRouteIds.length === 0) {
      setDecisionByRoute(defaultState);
      setDecisionAutoSkipped(false);
      return;
    }

    const totalDecisionRequests = requestedModels.length + wildcardRouteIds.length;
    if (!options?.force && totalDecisionRequests > AUTO_ROUTE_DECISION_LIMIT) {
      setDecisionByRoute(defaultState);
      setDecisionAutoSkipped(true);
      return;
    }

    setLoadingDecision(true);
    try {
      setDecisionAutoSkipped(false);
      const decisionRequestOptions = options?.refreshPricingCatalog
        ? {
          refreshPricingCatalog: true as const,
          ...(options?.persistSnapshots ? { persistSnapshots: true as const } : {}),
        }
        : options?.persistSnapshots
          ? { persistSnapshots: true as const }
          : undefined;
      const [exactRes, wildcardRes] = await Promise.all([
        requestedModels.length > 0
          ? api.getRouteDecisionsBatch(requestedModels, decisionRequestOptions)
          : Promise.resolve({ decisions: {} }),
        wildcardRouteIds.length > 0
          ? api.getRouteWideDecisionsBatch(wildcardRouteIds, decisionRequestOptions)
          : Promise.resolve({ decisions: {} }),
      ]);

      const decisionMap = (exactRes?.decisions || {}) as Record<string, RouteDecision | null>;
      const wildcardDecisionMap = (wildcardRes?.decisions || {}) as Record<string, RouteDecision | null>;
      const next = { ...defaultState };
      for (const route of exactRoutes) {
        next[route.id] = decisionMap[route.modelPattern] || null;
      }
      for (const routeId of wildcardRouteIds) {
        next[routeId] = wildcardDecisionMap[String(routeId)] || null;
      }

      setDecisionByRoute(next);
    } catch {
      setDecisionByRoute(defaultState);
      setDecisionAutoSkipped(false);
    } finally {
      setLoadingDecision(false);
    }
  };

  const load = async () => {
    const [summaryRows, candidateRows] = await Promise.all([
      api.getRoutesSummary(),
      api.getModelTokenCandidates(),
    ]);

    const summaries = (summaryRows || []) as RouteSummaryRow[];
    setRouteSummaries(summaries);
    setModelCandidates((candidateRows?.models || {}) as RouteModelCandidatesByModelName);
    setMissingTokenModelsByName(
      normalizeMissingTokenModels((candidateRows?.modelsWithoutToken || {}) as MissingTokenModelsByName),
    );
    setMissingTokenGroupModelsByName(
      normalizeMissingTokenModels((candidateRows?.modelsMissingTokenGroups || {}) as MissingTokenModelsByName),
    );
    setEndpointTypesByModel(candidateRows?.endpointTypesByModel || {});
    const decisionPlaceholder: Record<number, RouteDecision | null> = {};
    for (const route of summaries) {
      decisionPlaceholder[route.id] = route.decisionSnapshot || null;
    }
    setDecisionByRoute(decisionPlaceholder);
    setDecisionAutoSkipped(
      summaries.some((route) => isRouteExactModel(route) && !route.decisionSnapshot),
    );
  };

  useEffect(() => {
    (async () => {
      try {
        await load();
      } catch {
        toast.error('加载路由配置失败');
      }
    })();
  }, []);

  const handleRebuild = async () => {
    try {
      setRebuilding(true);
      const res = await api.rebuildRoutes(true);
      if (res?.queued) {
        toast.info(res.message || '已开始重建路由，请稍后查看日志');
        await load();
        return;
      }
      const createdRoutes = res?.rebuild?.createdRoutes ?? 0;
      const createdChannels = res?.rebuild?.createdChannels ?? 0;
      toast.success(`自动重建完成（新增 ${createdRoutes} 条路由 / ${createdChannels} 个通道）`);
      await load();
    } catch (e: any) {
      toast.error(e.message || '重建路由失败');
    } finally {
      setRebuilding(false);
    }
  };

  const handleRefreshRouteDecisions = async () => {
    try {
      await loadRouteDecisions(routeSummaries, { force: true, refreshPricingCatalog: true, persistSnapshots: true });
      toast.success('路由选择概率已刷新');
    } catch {
      toast.error('刷新路由选择概率失败');
    }
  };

  const exactRouteCount = useMemo(
    () => buildVisibleRouteList(routeSummaries, isExactModelPattern, matchesModelPattern)
      .filter((route) => isRouteExactModel(route)).length,
    [routeSummaries],
  );

  const zeroChannelPlaceholderRoutes = useMemo(
    () => buildZeroChannelPlaceholderRoutes(routeSummaries, missingTokenModelsByName, missingTokenGroupModelsByName),
    [routeSummaries, missingTokenModelsByName, missingTokenGroupModelsByName],
  );

  const visibleRouteRows = useMemo(
    () => (showZeroChannelRoutes ? [...routeSummaries, ...zeroChannelPlaceholderRoutes] : routeSummaries),
    [routeSummaries, showZeroChannelRoutes, zeroChannelPlaceholderRoutes],
  );

  const canSaveRoute = useMemo(() => {
    if (saving) return false;
    if (form.routeMode === 'explicit_group') {
      return !!form.displayName.trim() && form.sourceRouteIds.length > 0;
    }
    return !!form.modelPattern.trim() && !getModelPatternError(form.modelPattern);
  }, [form.displayName, form.modelPattern, form.routeMode, form.sourceRouteIds.length, saving]);

  const previewModelSamples = useMemo(() => {
    const names = new Set<string>();
    for (const modelName of Object.keys(modelCandidates || {})) {
      const normalized = modelName.trim();
      if (normalized) names.add(normalized);
    }
    for (const route of routeSummaries) {
      if (!isRouteExactModel(route)) continue;
      const normalized = route.modelPattern.trim();
      if (normalized) names.add(normalized);
    }
    return Array.from(names)
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
      .slice(0, 800);
  }, [modelCandidates, routeSummaries]);

  const exactSourceRouteOptions = useMemo(
    () => routeSummaries.filter((route) => isRouteExactModel(route)),
    [routeSummaries],
  );

  const resetRouteForm = () => {
    setForm(EMPTY_ROUTE_FORM);
    setEditingRouteId(null);
  };

  const handleAddRoute = async () => {
    const trimmedDisplayName = form.displayName.trim() ? form.displayName.trim() : undefined;
    const trimmedDisplayIcon = form.displayIcon.trim() ? form.displayIcon.trim() : undefined;
    const trimmedModelPattern = form.modelPattern.trim();
    const routeMode = normalizeRouteMode(form.routeMode);
    if (routeMode === 'explicit_group') {
      if (!trimmedDisplayName) {
        toast.error('请填写对外模型名');
        return;
      }
      if (form.sourceRouteIds.length === 0) {
        toast.error('请至少选择一个来源模型');
        return;
      }
    } else {
      if (!trimmedModelPattern) return;
      const modelPatternError = getModelPatternError(form.modelPattern);
      if (modelPatternError) {
        toast.error(modelPatternError);
        return;
      }
    }

    setSaving(true);
    try {
      if (editingRouteId) {
        const currentRoute = routeSummaries.find((route) => route.id === editingRouteId) || null;
        const modelPatternChanged = routeMode === 'pattern' && !!currentRoute && currentRoute.modelPattern !== trimmedModelPattern;
        await api.updateRoute(editingRouteId, {
          routeMode,
          ...(routeMode === 'pattern' ? { modelPattern: trimmedModelPattern } : {}),
          displayName: trimmedDisplayName,
          displayIcon: trimmedDisplayIcon,
          ...(routeMode === 'explicit_group' ? { sourceRouteIds: form.sourceRouteIds } : {}),
        });
        toast.success(routeMode === 'pattern' && modelPatternChanged ? tr('群组已更新并重新匹配通道') : tr('群组已更新'));
      } else {
        await api.addRoute({
          routeMode,
          ...(routeMode === 'pattern' ? { modelPattern: trimmedModelPattern } : {}),
          displayName: trimmedDisplayName,
          displayIcon: trimmedDisplayIcon,
          ...(routeMode === 'explicit_group' ? { sourceRouteIds: form.sourceRouteIds } : {}),
        });
        toast.success(tr('群组已创建'));
      }
      setShowManual(false);
      resetRouteForm();
      await load();
    } catch (e: any) {
      toast.error(e.message || (editingRouteId ? tr('更新群组失败') : tr('创建群组失败')));
    } finally {
      setSaving(false);
    }
  };

  const handleEditRoute = (route: RouteSummaryRow) => {
    setEditingRouteId(route.id);
    const routeMode = normalizeRouteMode(route.routeMode);
    setForm({
      routeMode,
      modelPattern: route.modelPattern || '',
      displayName: route.displayName || '',
      displayIcon: normalizeRouteDisplayIconValue(route.displayIcon),
      sourceRouteIds: routeMode === 'explicit_group' ? [...(route.sourceRouteIds || [])] : [],
      advancedOpen: routeMode === 'pattern',
    });
    setShowManual(true);
  };

  const handleCancelEditRoute = () => {
    resetRouteForm();
    setShowManual(false);
  };

  const handleDeleteRoute = async (routeId: number) => {
    try {
      await api.deleteRoute(routeId);
      toast.success('路由已删除');
      await load();
    } catch (e: any) {
      toast.error(e.message || '删除路由失败');
    }
  };

  const handleToggleRouteEnabled = async (route: RouteSummaryRow) => {
    const newEnabled = !route.enabled;
    setRouteSummaries((prev) =>
      prev.map((item) => (item.id === route.id ? { ...item, enabled: newEnabled } : item)),
    );
    try {
      await api.updateRoute(route.id, { enabled: newEnabled });
      toast.success(newEnabled ? '路由已启用' : '路由已禁用');
    } catch (e: any) {
      setRouteSummaries((prev) =>
        prev.map((item) => (item.id === route.id ? { ...item, enabled: route.enabled } : item)),
      );
      toast.error(e.message || '切换路由状态失败');
    }
  };

  const handleRoutingStrategyChange = async (route: RouteSummaryRow, routingStrategy: RouteRoutingStrategy) => {
    const currentStrategy = route.routingStrategy === 'round_robin' ? 'round_robin' : 'weighted';
    if (routingStrategy === currentStrategy) return;

    setUpdatingRoutingStrategyByRoute((prev) => ({ ...prev, [route.id]: true }));
    setRouteSummaries((prev) => prev.map((item) => (
      item.id === route.id
        ? { ...item, routingStrategy }
        : item
    )));
    try {
      await api.updateRoute(route.id, { routingStrategy });
      toast.success(routingStrategy === 'round_robin' ? '已切换为轮询策略' : '已切换为权重随机策略');
    } catch (e: any) {
      setRouteSummaries((prev) => prev.map((item) => (
        item.id === route.id
          ? { ...item, routingStrategy: currentStrategy }
          : item
      )));
      toast.error(e.message || '更新路由策略失败');
      return;
    } finally {
      setUpdatingRoutingStrategyByRoute((prev) => ({ ...prev, [route.id]: false }));
    }

    try {
      await load();
    } catch (e: any) {
      toast.error(e?.message || '路由策略已保存，但刷新列表失败');
    }
  };

  // Stable derived value: only changes when route patterns change (not on enabled toggle)
  const routePatterns = useMemo(
    () => visibleRouteRows.map((r) => ({ id: r.id, modelPattern: r.modelPattern, routeMode: r.routeMode })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [visibleRouteRows.map((r) => `${r.id}:${r.modelPattern}:${r.routeMode || 'pattern'}`).join(',')],
  );

  const routeBrandById = useMemo(() => {
    const next = new Map<number, BrandInfo | null>();
    for (const route of visibleRouteRows) {
      next.set(route.id, resolveRouteBrand(route));
    }
    return next;
  }, [visibleRouteRows]);

  const listVisibleRoutes = useMemo(
    () => buildVisibleRouteList(visibleRouteRows, isExactModelPattern, matchesModelPattern),
    [visibleRouteRows],
  );

  const brandList = useMemo(() => {
    const grouped = new Map<string, { count: number; brand: BrandInfo }>();
    let otherCount = 0;

    for (const route of listVisibleRoutes) {
      const brand = routeBrandById.get(route.id) || null;
      if (!brand) {
        otherCount++;
        continue;
      }

      const existing = grouped.get(brand.name);
      if (existing) {
        existing.count++;
      } else {
        grouped.set(brand.name, { count: 1, brand });
      }
    }

    return {
      list: [...grouped.entries()].sort((a, b) => {
        if (a[1].count === b[1].count) return a[0].localeCompare(b[0]);
        return b[1].count - a[1].count;
      }) as [string, { count: number; brand: BrandInfo }][],
      otherCount,
    };
  }, [listVisibleRoutes, routeBrandById]);

  const siteList = useMemo(() => {
    const grouped = new Map<string, { count: number; siteId: number }>();

    for (const route of listVisibleRoutes) {
      const seenSites = new Set<string>();
      for (const siteName of route.siteNames || []) {
        if (!siteName || seenSites.has(siteName)) continue;
        seenSites.add(siteName);

        const existing = grouped.get(siteName);
        if (existing) {
          existing.count++;
        } else {
          grouped.set(siteName, { count: 1, siteId: 0 });
        }
      }
    }

    return [...grouped.entries()].sort((a, b) => {
      if (a[1].count === b[1].count) return a[0].localeCompare(b[0]);
      return b[1].count - a[1].count;
    }) as [string, { count: number; siteId: number }][];
  }, [listVisibleRoutes]);

  const routeEndpointTypesByRouteId = useMemo(() => {
    const index: Record<number, Set<string>> = {};
    const entries = Object.entries(endpointTypesByModel || {});
    for (const route of routePatterns) {
      const pattern = (route.modelPattern || '').trim();
      if (!pattern) {
        index[route.id] = new Set<string>();
        continue;
      }
      const endpointTypes = new Set<string>();
      for (const [modelName, rawTypes] of entries) {
        if (!matchesModelPattern(modelName, pattern)) continue;
        for (const rawType of Array.isArray(rawTypes) ? rawTypes : []) {
          const endpointType = String(rawType || '').trim();
          if (!endpointType) continue;
          endpointTypes.add(endpointType);
        }
      }
      // Fallback: infer from siteNames isn't possible without platform info,
      // but we'll keep endpoint types from model availability
      index[route.id] = endpointTypes;
    }
    return index;
  }, [routePatterns, endpointTypesByModel]);

  const endpointTypeList = useMemo(() => {
    const grouped = new Map<string, number>();
    for (const route of listVisibleRoutes) {
      const endpointTypes = routeEndpointTypesByRouteId[route.id] || new Set<string>();
      for (const endpointType of endpointTypes) {
        grouped.set(endpointType, (grouped.get(endpointType) || 0) + 1);
      }
    }
    return [...grouped.entries()].sort((a, b) => {
      if (a[1] === b[1]) return a[0].localeCompare(b[0], undefined, { sensitivity: 'base' });
      return b[1] - a[1];
    }) as [string, number][];
  }, [listVisibleRoutes, routeEndpointTypesByRouteId]);

  const sourceEndpointTypesByRouteId = useMemo(() => {
    const next: Record<number, string[]> = {};
    for (const route of exactSourceRouteOptions) {
      next[route.id] = Array.from(routeEndpointTypesByRouteId[route.id] || new Set<string>())
        .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    }
    return next;
  }, [exactSourceRouteOptions, routeEndpointTypesByRouteId]);

  const routeBrandIconCandidates = useMemo(() => {
    const byIcon = new Map<string, BrandInfo>();

    for (const route of visibleRouteRows) {
      const brand = resolveRouteBrand(route);
      if (brand) byIcon.set(brand.icon, brand);
    }

    for (const modelName of Object.keys(modelCandidates || {})) {
      const brand = getBrand(modelName);
      if (brand) byIcon.set(brand.icon, brand);
    }

    return Array.from(byIcon.values())
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  }, [visibleRouteRows, modelCandidates]);

  const routeIconSelectOptions = useMemo<RouteIconOption[]>(() => ([
    ...ROUTE_ICON_OPTIONS,
    ...routeBrandIconCandidates.map((brand) => ({
      value: toBrandIconValue(brand.icon),
      label: brand.name,
      description: `${brand.name} 品牌图标`,
      iconNode: <BrandGlyph brand={brand} size={14} fallbackText={brand.name} />,
    })),
  ]), [routeBrandIconCandidates]);

  const groupRouteList = useMemo<GroupRouteItem[]>(() => (
    listVisibleRoutes
      .filter((route) => !isRouteExactModel(route))
      .map((route) => ({
        id: route.id,
        title: resolveRouteTitle(route),
        icon: resolveRouteIcon(route),
        brand: routeBrandById.get(route.id) || null,
        modelPattern: route.modelPattern,
        channelCount: route.channelCount,
        sourceRouteCount: Array.isArray(route.sourceRouteIds) ? route.sourceRouteIds.length : 0,
      }))
      .sort((a, b) => {
        if (a.channelCount === b.channelCount) return a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
        return b.channelCount - a.channelCount;
      })
  ), [listVisibleRoutes, routeBrandById]);

  const activeGroupRoute = useMemo(() => {
    if (typeof activeGroupFilter !== 'number') return null;
    return listVisibleRoutes.find((route) => route.id === activeGroupFilter) || null;
  }, [activeGroupFilter, listVisibleRoutes]);

  const sortedRoutes = useMemo(() => (
    [...listVisibleRoutes].sort((a, b) => {
      if (sortBy === 'channelCount') {
        const countCmp = a.channelCount - b.channelCount;
        if (countCmp !== 0) return sortDir === 'asc' ? countCmp : -countCmp;
      }

      const nameCmp = a.modelPattern.localeCompare(b.modelPattern, undefined, { sensitivity: 'base' });
      return sortDir === 'asc' ? nameCmp : -nameCmp;
    })
  ), [listVisibleRoutes, sortBy, sortDir]);

  const filteredRoutes = useMemo(() => {
    let list = sortedRoutes;

    if (activeGroupFilter === '__all__') {
      list = list.filter((route) => !isRouteExactModel(route));
    } else if (typeof activeGroupFilter === 'number') {
      list = list.filter((route) => route.id === activeGroupFilter);
    }

    if (activeBrand) {
      if (activeBrand === '__other__') {
        list = list.filter((route) => !(routeBrandById.get(route.id) || null));
      } else {
        list = list.filter((route) => (routeBrandById.get(route.id)?.name || '') === activeBrand);
      }
    }

    if (activeSite) {
      list = list.filter((route) =>
        route.siteNames?.includes(activeSite),
      );
    }

    if (activeEndpointType) {
      list = list.filter((route) =>
        (routeEndpointTypesByRouteId[route.id] || new Set<string>()).has(activeEndpointType),
      );
    }

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((route) => {
        const modelPattern = route.modelPattern.toLowerCase();
        const displayName = (route.displayName || '').toLowerCase();
        const title = resolveRouteTitle(route).toLowerCase();
        return modelPattern.includes(q) || displayName.includes(q) || title.includes(q);
      });
    }

    return list;
  }, [
    sortedRoutes,
    activeGroupFilter,
    activeBrand,
    activeSite,
    activeEndpointType,
    search,
    routeBrandById,
    routeEndpointTypesByRouteId,
  ]);

  useEffect(() => {
    setVisibleRouteCount(getInitialVisibleCount(filteredRoutes.length, ROUTE_RENDER_CHUNK));
  }, [filteredRoutes.length]);

  const handleLoadMoreRoutes = useCallback(() => {
    setVisibleRouteCount((current) => getNextVisibleCount(current, filteredRoutes.length, ROUTE_RENDER_CHUNK));
  }, [filteredRoutes.length]);

  const loadMoreSentinelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = loadMoreSentinelRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => { if (entries[0]?.isIntersecting) handleLoadMoreRoutes(); },
      { rootMargin: '200px' },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [handleLoadMoreRoutes]);

  const visibleRoutes = useMemo(
    () => filteredRoutes.slice(0, visibleRouteCount),
    [filteredRoutes, visibleRouteCount],
  );

  const routeModelCandidateIndex = useMemo(
    () => buildRouteModelCandidatesIndex(routePatterns, modelCandidates, matchesModelPattern),
    [routePatterns, modelCandidates],
  );

  const routeMissingTokenIndex = useMemo(
    () => buildRouteMissingTokenIndex(routePatterns, missingTokenModelsByName, matchesModelPattern),
    [routePatterns, missingTokenModelsByName],
  );
  const routeMissingTokenGroupIndex = useMemo(
    () => buildRouteMissingTokenIndex(routePatterns, missingTokenGroupModelsByName, matchesModelPattern),
    [routePatterns, missingTokenGroupModelsByName],
  );

  const getRouteCandidateView = (routeId: number): RouteCandidateView => {
    return routeModelCandidateIndex[routeId] || EMPTY_ROUTE_CANDIDATE_VIEW;
  };

  const routeById = useMemo(
    () => new Map(visibleRouteRows.map((route) => [route.id, route])),
    [visibleRouteRows],
  );

  const handleCreateTokenForMissingAccount = (accountId: number, modelName: string) => {
    if (!Number.isFinite(accountId) || accountId <= 0) return;
    const params = new URLSearchParams();
    params.set('create', '1');
    params.set('accountId', String(accountId));
    params.set('model', modelName);
    params.set('from', 'routes');
    navigate(`/tokens?${params.toString()}`);
  };

  const handleDeleteChannel = async (channelId: number, routeId: number) => {
    try {
      await api.deleteChannel(channelId);
      toast.success('通道已移除');
      // Reload channels for this route
      await loadChannels(routeId, true);
      // Update channel count in summary
      setRouteSummaries((prev) =>
        prev.map((r) => r.id === routeId ? { ...r, channelCount: Math.max(0, r.channelCount - 1) } : r),
      );
    } catch (e: any) {
      toast.error(e.message || '移除通道失败');
    }
  };

  const handleChannelTokenSave = async (routeId: number, channelId: number, accountId: number) => {
    const tokenId = channelTokenDraft[channelId];
    const tokenOptions = getRouteCandidateView(routeId).tokenOptionsByAccountId[accountId] || [];

    if (tokenId && tokenOptions.length > 0 && !tokenOptions.some((token) => token.id === tokenId)) {
      toast.error('该令牌不支持当前模型');
      return;
    }

    setUpdatingChannel((prev) => ({ ...prev, [channelId]: true }));
    try {
      await api.updateChannel(channelId, { tokenId: tokenId || null });
      toast.success('通道令牌已更新');
      await loadChannels(routeId, true);
    } catch (e: any) {
      toast.error(e.message || '更新令牌失败');
    } finally {
      setUpdatingChannel((prev) => ({ ...prev, [channelId]: false }));
    }
  };

  const handleChannelDragEnd = async (routeId: number, event: DragEndEvent) => {
    if (savingPriorityByRoute[routeId]) return;

    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const channels = channelsByRouteId[routeId] || [];
    const oldIndex = channels.findIndex((channel) => channel.id === Number(active.id));
    const newIndex = channels.findIndex((channel) => channel.id === Number(over.id));

    if (oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) return;

    const previousChannels = [...channels];
    const reordered = arrayMove(channels, oldIndex, newIndex).map((channel, index) => ({
      ...channel,
      priority: index,
    }));

    setChannels(routeId, reordered);
    setSavingPriorityByRoute((prev) => ({ ...prev, [routeId]: true }));

    try {
      await api.batchUpdateChannels(
        reordered.map((channel) => ({
          id: channel.id,
          priority: channel.priority,
        })),
      );

      const route = routeSummaries.find((r) => r.id === routeId);
      if (route && isRouteExactModel(route)) {
        try {
          const res = await api.getRouteDecision(route.modelPattern);
          setDecisionByRoute((prev) => ({
            ...prev,
            [routeId]: (res?.decision || null) as RouteDecision | null,
          }));
        } catch {
          // ignore route decision refresh failures after reorder
        }
      }
    } catch (e: any) {
      setChannels(routeId, previousChannels);
      toast.error(e.message || '保存通道优先级失败，已回滚');
    } finally {
      setSavingPriorityByRoute((prev) => ({ ...prev, [routeId]: false }));
    }
  };

  const toggleExpand = async (routeId: number) => {
    const isCurrentlyExpanded = expandedRouteIds.includes(routeId);
    if (isCurrentlyExpanded) {
      setExpandedRouteIds((prev) => prev.filter((id) => id !== routeId));
    } else {
      setExpandedRouteIds((prev) => [...prev, routeId]);
      // Load channels on demand
      const route = routeById.get(routeId) || null;
      const isReadOnlyRoute = route?.kind === 'zero_channel' || route?.readOnly === true || route?.isVirtual === true;
      if (!channelsByRouteId[routeId] && !isReadOnlyRoute) {
        try {
          await loadChannels(routeId);
        } catch {
          toast.error('加载通道失败');
        }
      }
    }
  };

  const missingTokenSiteItemsByRouteId = useMemo(() => {
    const result: Record<number, MissingTokenRouteSiteActionItem[]> = {};
    for (const routeId of Object.keys(routeMissingTokenIndex).map(Number)) {
      const missingTokenHints = routeMissingTokenIndex[routeId] || [];
      const siteMap = new Map<string, MissingTokenRouteSiteActionItem>();
      for (const hint of missingTokenHints) {
        for (const account of hint.accounts) {
          if (!Number.isFinite(account.accountId) || account.accountId <= 0) continue;
          const siteName = (account.siteName || '').trim() || `site-${account.siteId || 'unknown'}`;
          const key = `${account.siteId || 0}::${siteName.toLowerCase()}`;
          const accountLabel = account.username || `account-${account.accountId}`;
          const existing = siteMap.get(key);
          if (!existing) {
            siteMap.set(key, { key, siteName, accountId: account.accountId, accountLabel });
            continue;
          }
          if (account.accountId < existing.accountId) {
            existing.accountId = account.accountId;
            existing.accountLabel = accountLabel;
          }
        }
      }
      result[routeId] = Array.from(siteMap.values()).sort((a, b) => (
        a.siteName.localeCompare(b.siteName, undefined, { sensitivity: 'base' })
      ));
    }
    return result;
  }, [routeMissingTokenIndex]);

  const missingTokenGroupItemsByRouteId = useMemo(() => {
    const result: Record<number, MissingTokenGroupRouteSiteActionItem[]> = {};
    for (const routeId of Object.keys(routeMissingTokenGroupIndex).map(Number)) {
      const missingGroupHints = routeMissingTokenGroupIndex[routeId] || [];
      const siteMap = new Map<string, MissingTokenGroupRouteSiteActionItem>();
      for (const hint of missingGroupHints) {
        for (const account of hint.accounts) {
          if (!Number.isFinite(account.accountId) || account.accountId <= 0) continue;
          const siteName = (account.siteName || '').trim() || `site-${account.siteId || 'unknown'}`;
          const key = `${account.siteId || 0}::${siteName.toLowerCase()}`;
          const accountLabel = account.username || `account-${account.accountId}`;
          const missingGroups = Array.isArray(account.missingGroups) ? account.missingGroups : [];
          const requiredGroups = Array.isArray(account.requiredGroups) ? account.requiredGroups : [];
          const availableGroups = Array.isArray(account.availableGroups) ? account.availableGroups : [];
          const existing = siteMap.get(key);
          if (!existing) {
            siteMap.set(key, {
              key,
              siteName,
              accountId: account.accountId,
              accountLabel,
              missingGroups: [...missingGroups],
              requiredGroups: [...requiredGroups],
              availableGroups: [...availableGroups],
              ...(account.groupCoverageUncertain === true ? { groupCoverageUncertain: true } : {}),
            });
            continue;
          }
          if (account.accountId < existing.accountId) {
            existing.accountId = account.accountId;
            existing.accountLabel = accountLabel;
          }
          existing.missingGroups = Array.from(new Set([...existing.missingGroups, ...missingGroups]))
            .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
          existing.requiredGroups = Array.from(new Set([...existing.requiredGroups, ...requiredGroups]))
            .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
          existing.availableGroups = Array.from(new Set([...existing.availableGroups, ...availableGroups]))
            .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
          if (account.groupCoverageUncertain === true) {
            existing.groupCoverageUncertain = true;
          }
        }
      }
      result[routeId] = Array.from(siteMap.values()).sort((a, b) => (
        a.siteName.localeCompare(b.siteName, undefined, { sensitivity: 'base' })
      ));
    }
    return result;
  }, [routeMissingTokenGroupIndex]);

  // Stable callbacks for RouteCard memo (use refs to avoid dependency on closure variables)
  const toggleExpandRef = useRef(toggleExpand);
  toggleExpandRef.current = toggleExpand;
  const stableToggleExpand = useCallback((routeId: number) => toggleExpandRef.current(routeId), []);
  const handleEditRouteRef = useRef(handleEditRoute);
  handleEditRouteRef.current = handleEditRoute;
  const stableEditRoute = useCallback((route: RouteSummaryRow) => handleEditRouteRef.current(route), []);
  const handleDeleteRouteRef = useRef(handleDeleteRoute);
  handleDeleteRouteRef.current = handleDeleteRoute;
  const stableDeleteRoute = useCallback((routeId: number) => { handleDeleteRouteRef.current(routeId); }, []);
  const handleToggleEnabledRef = useRef(handleToggleRouteEnabled);
  handleToggleEnabledRef.current = handleToggleRouteEnabled;
  const stableToggleEnabled = useCallback((route: RouteSummaryRow) => { handleToggleEnabledRef.current(route); }, []);
  const handleRoutingStrategyChangeRef = useRef(handleRoutingStrategyChange);
  handleRoutingStrategyChangeRef.current = handleRoutingStrategyChange;
  const stableRoutingStrategyChange = useCallback(
    (route: RouteSummaryRow, strategy: RouteRoutingStrategy) => handleRoutingStrategyChangeRef.current(route, strategy),
    [],
  );
  const stableTokenDraftChange = useCallback(
    (channelId: number, tokenId: number) => setChannelTokenDraft((prev) => ({ ...prev, [channelId]: tokenId })),
    [],
  );
  const stableAddChannel = useCallback((routeId: number) => setAddChannelModalRouteId(routeId), []);
  const stableToggleSourceGroup = useCallback(
    (groupKey: string) => setExpandedSourceGroupMap((prev) => ({ ...prev, [groupKey]: !prev[groupKey] })),
    [],
  );
  const handleChannelTokenSaveRef = useRef(handleChannelTokenSave);
  handleChannelTokenSaveRef.current = handleChannelTokenSave;
  const stableChannelTokenSave = useCallback(
    (routeId: number, channelId: number, accountId: number) => handleChannelTokenSaveRef.current(routeId, channelId, accountId),
    [],
  );
  const handleDeleteChannelRef = useRef(handleDeleteChannel);
  handleDeleteChannelRef.current = handleDeleteChannel;
  const stableDeleteChannel = useCallback(
    (channelId: number, routeId: number) => handleDeleteChannelRef.current(channelId, routeId),
    [],
  );
  const handleChannelDragEndRef = useRef(handleChannelDragEnd);
  handleChannelDragEndRef.current = handleChannelDragEnd;
  const stableChannelDragEnd = useCallback(
    (routeId: number, event: DragEndEvent) => handleChannelDragEndRef.current(routeId, event),
    [],
  );
  const handleCreateTokenRef = useRef(handleCreateTokenForMissingAccount);
  handleCreateTokenRef.current = handleCreateTokenForMissingAccount;
  const stableCreateTokenForMissing = useCallback(
    (accountId: number, modelName: string) => handleCreateTokenRef.current(accountId, modelName),
    [],
  );

  const addChannelModalRoute = addChannelModalRouteId
    ? routeSummaries.find((r) => r.id === addChannelModalRouteId) || null
    : null;

  const handleAddChannelSuccess = async () => {
    if (!addChannelModalRouteId) return;
    // Reload channels for this route
    await loadChannels(addChannelModalRouteId, true);
    // Refresh summary to update channel count
    await load();
  };

  return (
    <div className="animate-fade-in" style={{ minHeight: 400 }}>
      {/* Toolbar: search + sort + actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
        <div className="toolbar-search" style={{ minWidth: 220, flex: 1, maxWidth: 360 }}>
          <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={tr('搜索模型路由...')}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ minWidth: 128 }}>
            <ModernSelect
              size="sm"
              value={sortBy}
              onChange={(nextValue) => {
                const nextSortBy = nextValue as RouteSortBy;
                setSortBy(nextSortBy);
                setSortDir(nextSortBy === 'modelPattern' ? 'asc' : 'desc');
              }}
              options={[
                { value: 'modelPattern', label: tr('模型名称') },
                { value: 'channelCount', label: tr('通道数量') },
              ]}
              placeholder={tr('排序字段')}
            />
          </div>
          <button
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 12px', fontSize: 12 }}
            onClick={() => setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))}
            data-tooltip={tr('切换排序方向')}
            aria-label={tr('切换排序方向')}
          >
            {sortDir === 'asc' ? tr('升序 ↑') : tr('降序 ↓')}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, borderLeft: '1px solid var(--color-border)', paddingLeft: 8 }}>
          <button
            onClick={handleRefreshRouteDecisions}
            disabled={loadingDecision}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {loadingDecision ? (
              <><span className="spinner spinner-sm" /> {tr('刷新中...')}</>
            ) : (
              tr('刷新选中概率')
            )}
          </button>

          <button
            onClick={handleRebuild}
            disabled={rebuilding}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {rebuilding ? (
              <><span className="spinner spinner-sm" /> {tr('重建中...')}</>
            ) : (
              tr('自动重建')
            )}
          </button>

          <button
            onClick={() => {
              resetRouteForm();
              setShowManual(true);
            }}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {tr('新建群组')}
          </button>

          <button
            type="button"
            aria-pressed={showZeroChannelRoutes}
            onClick={() => setShowZeroChannelRoutes((prev) => !prev)}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {showZeroChannelRoutes ? tr('隐藏 0 通道路由') : tr('显示 0 通道路由')}
          </button>
        </div>

        <span className="badge badge-info" style={{ fontSize: 12, fontWeight: 500, marginLeft: 'auto' }}>
          {tr('共')} {filteredRoutes.length} {tr('条路由')}
        </span>
      </div>

      {/* Collapsible filter panel */}
      {isMobile ? (
        <>
          <button
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px', marginBottom: 12 }}
            onClick={() => setShowFilters(true)}
          >
            {tr('筛选')}
          </button>
          <MobileDrawer open={showFilters} onClose={() => setShowFilters(false)}>
            <div className="mobile-filter-panel">
              <RouteFilterBar
                totalRouteCount={listVisibleRoutes.length}
                activeBrand={activeBrand}
                setActiveBrand={setActiveBrand}
                activeSite={activeSite}
                setActiveSite={setActiveSite}
                activeEndpointType={activeEndpointType}
                setActiveEndpointType={setActiveEndpointType}
                activeGroupFilter={activeGroupFilter}
                setActiveGroupFilter={setActiveGroupFilter}
                brandList={brandList}
                siteList={siteList}
                endpointTypeList={endpointTypeList}
                groupRouteList={groupRouteList}
                collapsed={false}
                onToggle={() => setShowFilters(false)}
              />
            </div>
          </MobileDrawer>
        </>
      ) : (
        <RouteFilterBar
          totalRouteCount={listVisibleRoutes.length}
          activeBrand={activeBrand}
          setActiveBrand={setActiveBrand}
          activeSite={activeSite}
          setActiveSite={setActiveSite}
          activeEndpointType={activeEndpointType}
          setActiveEndpointType={setActiveEndpointType}
          activeGroupFilter={activeGroupFilter}
          setActiveGroupFilter={setActiveGroupFilter}
          brandList={brandList}
          siteList={siteList}
          endpointTypeList={endpointTypeList}
          groupRouteList={groupRouteList}
          collapsed={filterCollapsed}
          onToggle={() => setFilterCollapsed((prev) => !prev)}
        />
      )}

      {/* Info tip */}
      <div className="info-tip" style={{ marginBottom: 12 }}>
        {tr('系统会根据模型可用性自动生成路由。精确模型路由会自动过滤只支持该模型的账号和令牌。优先级 P0 最高，数字越大优先级越低。选中概率表示请求到达时该通道被选中的概率。成本来源优先级为：实测成本 → 账号配置成本 → 目录参考价 → 默认回退单价。')}
      </div>

      {/* Manual route panel */}
      <ManualRoutePanel
        show={showManual}
        editingRouteId={editingRouteId}
        form={form}
        setForm={setForm}
        saving={saving}
        canSave={canSaveRoute}
        routeIconSelectOptions={routeIconSelectOptions}
        previewModelSamples={previewModelSamples}
        exactSourceRouteOptions={exactSourceRouteOptions}
        sourceEndpointTypesByRouteId={sourceEndpointTypesByRouteId}
        onSave={handleAddRoute}
        onCancel={handleCancelEditRoute}
      />

      {/* Route card grid */}
      <div className={isMobile ? 'mobile-card-list' : 'route-card-grid'}>
        {visibleRoutes.map((route) => {
          const isExpanded = expandedRouteIds.includes(route.id);
          const isReadOnlyRoute = route.kind === 'zero_channel' || route.readOnly === true || route.isVirtual === true;

          if (isMobile) {
            return (
              <MobileCard
                key={route.id}
                title={resolveRouteTitle(route)}
                actions={(
                  <span className={`badge ${isReadOnlyRoute ? 'badge-muted' : (route.enabled ? 'badge-success' : 'badge-muted')}`} style={{ fontSize: 10 }}>
                    {isReadOnlyRoute ? tr('未生成') : (route.enabled ? tr('启用') : tr('禁用'))}
                  </span>
                )}
              >
                <MobileField label="模型" value={route.modelPattern} />
                <MobileField label="通道" value={route.channelCount} />
                <MobileField label="策略" value={isReadOnlyRoute ? tr('未生成') : (route.routingStrategy === 'round_robin' ? tr('轮询') : tr('权重随机'))} />
                <MobileField label="状态" value={isReadOnlyRoute ? tr('未生成') : (route.enabled ? tr('启用') : tr('禁用'))} />
                <div className="mobile-card-actions">
                  <button
                    type="button"
                    className="btn btn-link"
                    onClick={() => toggleExpand(route.id)}
                  >
                    {isExpanded ? '收起' : '详情'}
                  </button>
                </div>
              </MobileCard>
            );
          }

          return (
            <RouteCard
              key={route.id}
              route={route}
              brand={routeBrandById.get(route.id) || null}
              expanded={isExpanded}
              onToggleExpand={stableToggleExpand}
              onEdit={stableEditRoute}
              onDelete={stableDeleteRoute}
              onToggleEnabled={stableToggleEnabled}
              onRoutingStrategyChange={stableRoutingStrategyChange}
              updatingRoutingStrategy={!!updatingRoutingStrategyByRoute[route.id]}
              channels={channelsByRouteId[route.id]}
              loadingChannels={!!loadingChannelsByRouteId[route.id]}
              routeDecision={decisionByRoute[route.id] || null}
              loadingDecision={loadingDecision}
              candidateView={getRouteCandidateView(route.id)}
              channelTokenDraft={channelTokenDraft}
              updatingChannel={updatingChannel}
              savingPriority={!!savingPriorityByRoute[route.id]}
              onTokenDraftChange={stableTokenDraftChange}
              onSaveToken={stableChannelTokenSave}
              onDeleteChannel={stableDeleteChannel}
              onChannelDragEnd={stableChannelDragEnd}
              missingTokenSiteItems={missingTokenSiteItemsByRouteId[route.id] || EMPTY_MISSING_ITEMS}
              missingTokenGroupItems={missingTokenGroupItemsByRouteId[route.id] || EMPTY_MISSING_GROUP_ITEMS}
              onCreateTokenForMissing={stableCreateTokenForMissing}
              onAddChannel={stableAddChannel}
              expandedSourceGroupMap={expandedSourceGroupMap}
              onToggleSourceGroup={stableToggleSourceGroup}
            />
          );
        })}
      </div>

      {filteredRoutes.length > 0 && visibleRouteCount < filteredRoutes.length && (
        <div
          ref={loadMoreSentinelRef}
          style={{ textAlign: 'center', padding: '12px 0', fontSize: 12, color: 'var(--color-text-muted)' }}
        >
          {tr('当前已加载路由')} {visibleRouteCount} / {filteredRoutes.length}
        </div>
      )}

      {filteredRoutes.length === 0 && (
        <div className="card">
          <div className="empty-state">
            <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"
              />
            </svg>
            <div className="empty-state-title">{routeSummaries.length === 0 ? '暂无路由' : '没有匹配的路由'}</div>
            <div className="empty-state-desc">
              {routeSummaries.length === 0
                ? '点击"自动重建"可按当前模型可用性生成路由。'
                : '请调整品牌筛选、搜索词或排序条件。'}
            </div>
          </div>
        </div>
      )}

      {/* Add channel modal */}
      {addChannelModalRoute && (
        <AddChannelModal
          open={!!addChannelModalRouteId}
          onClose={() => setAddChannelModalRouteId(null)}
          routeId={addChannelModalRoute.id}
          routeTitle={resolveRouteTitle(addChannelModalRoute)}
          candidateView={getRouteCandidateView(addChannelModalRoute.id)}
          onSuccess={handleAddChannelSuccess}
          missingTokenHints={routeMissingTokenIndex[addChannelModalRoute.id] || []}
          onCreateTokenForMissing={handleCreateTokenForMissingAccount}
          existingChannelAccountIds={new Set((channelsByRouteId[addChannelModalRoute.id] || []).map((c) => c.accountId))}
        />
      )}
    </div>
  );
}
