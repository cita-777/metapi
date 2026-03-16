import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import CenteredModal from '../components/CenteredModal.js';
import { useToast } from '../components/Toast.js';
import ModernSelect from '../components/ModernSelect.js';
import { MobileCard, MobileField } from '../components/MobileCard.js';
import { useIsMobile } from '../components/useIsMobile.js';
import DeleteConfirmModal from '../components/DeleteConfirmModal.js';
import { formatDateTimeLocal } from './helpers/checkinLogTime.js';
import { clearFocusParams, readFocusSiteId } from './helpers/navigationFocus.js';
import { tr } from '../i18n.js';
import { buildCustomReorderUpdates, sortItemsForDisplay, type SortMode } from './helpers/listSorting.js';
import { shouldIgnoreRowSelectionClick } from './helpers/rowSelection.js';
import { resolveInitialConnectionSegment } from './helpers/defaultConnectionSegment.js';
import {
  buildSiteSaveAction,
  emptySiteCustomHeader,
  emptySiteForm,
  serializeSiteCustomHeaders,
  siteFormFromSite,
  type SiteEditorState,
  type SiteForm,
} from './helpers/sitesEditor.js';

type SiteRow = {
  id: number;
  name: string;
  url: string;
  externalCheckinUrl?: string | null;
  platform?: string;
  status?: string;
  useSystemProxy?: boolean;
  customHeaders?: string | null;
  globalWeight?: number;
  isPinned?: boolean;
  sortOrder?: number;
  totalBalance?: number;
  createdAt?: string;
};

function hasConfiguredCustomHeaders(customHeaders?: string | null): boolean {
  return typeof customHeaders === 'string' && customHeaders.trim().length > 0;
}

const platformColors: Record<string, string> = {
  'new-api': 'badge-info',
  'one-api': 'badge-success',
  anyrouter: 'badge-warning',
  veloera: 'badge-warning',
  'one-hub': 'badge-muted',
  'done-hub': 'badge-muted',
  sub2api: 'badge-muted',
  openai: 'badge-success',
  codex: 'badge-success',
  claude: 'badge-warning',
  gemini: 'badge-info',
  cliproxyapi: 'badge-info',
};

const SITE_PLATFORM_OPTIONS = [
  { value: '', label: '平台类型（可自动检测）' },
  { value: 'new-api', label: 'new-api' },
  { value: 'one-api', label: 'one-api' },
  { value: 'anyrouter', label: 'anyrouter' },
  { value: 'veloera', label: 'veloera' },
  { value: 'one-hub', label: 'one-hub' },
  { value: 'done-hub', label: 'done-hub' },
  { value: 'sub2api', label: 'sub2api' },
  { value: 'openai', label: 'openai' },
  { value: 'codex', label: 'codex' },
  { value: 'claude', label: 'claude' },
  { value: 'gemini', label: 'gemini' },
  { value: 'cliproxyapi', label: 'cliproxyapi' },
];

export default function Sites() {
  const location = useLocation();
  const navigate = useNavigate();
  const [sites, setSites] = useState<SiteRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [sortMode, setSortMode] = useState<SortMode>('custom');
  const [highlightSiteId, setHighlightSiteId] = useState<number | null>(null);
  const [editor, setEditor] = useState<SiteEditorState | null>(null);
  const [form, setForm] = useState<SiteForm>(emptySiteForm());
  const [detecting, setDetecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [togglingSiteId, setTogglingSiteId] = useState<number | null>(null);
  const [orderingSiteId, setOrderingSiteId] = useState<number | null>(null);
  const [pinningSiteId, setPinningSiteId] = useState<number | null>(null);
  const [selectedSiteIds, setSelectedSiteIds] = useState<number[]>([]);
  const [expandedSiteIds, setExpandedSiteIds] = useState<number[]>([]);
  const isMobile = useIsMobile(768);
  const [batchActionLoading, setBatchActionLoading] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<null | {
    mode: 'single' | 'batch';
    siteId?: number;
    siteName?: string;
    count?: number;
  }>(null);
  const lastEditorRef = useRef<SiteEditorState | null>(null);
  const rowRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());
  const highlightTimerRef = useRef<number | null>(null);
  const toast = useToast();
  const [disabledModels, setDisabledModels] = useState<string[]>([]);
  const [disabledModelInput, setDisabledModelInput] = useState('');
  const [disabledModelsLoading, setDisabledModelsLoading] = useState(false);
  const [disabledModelsSaving, setDisabledModelsSaving] = useState(false);

  if (editor) lastEditorRef.current = editor;
  const activeEditor = editor || lastEditorRef.current;
  const isEditing = activeEditor?.mode === 'edit';
  const isAdding = editor?.mode === 'add';
  const formInputStyle = {
    width: '100%',
    padding: '10px 14px',
    border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)',
    fontSize: 13,
    outline: 'none',
    background: 'var(--color-bg)',
    color: 'var(--color-text-primary)',
  } as const;

  const load = async () => {
    try {
      const rows = await api.getSites();
      setSites(rows || []);
      setSelectedSiteIds((current) => current.filter((id) => (rows || []).some((site: SiteRow) => site.id === id)));
    } catch {
      toast.error('加载站点列表失败');
    } finally {
      setLoaded(true);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const sortedSites = useMemo(
    () => sortItemsForDisplay(sites, sortMode, (site) => site.totalBalance || 0),
    [sites, sortMode],
  );

  const platformOptions = useMemo(() => {
    const current = form.platform.trim();
    if (!current || SITE_PLATFORM_OPTIONS.some((option) => option.value === current)) {
      return SITE_PLATFORM_OPTIONS;
    }
    return [
      ...SITE_PLATFORM_OPTIONS,
      { value: current, label: `${current}（当前值）` },
    ];
  }, [form.platform]);

  useEffect(() => {
    return () => {
      if (highlightTimerRef.current) {
        window.clearTimeout(highlightTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    const focusSiteId = readFocusSiteId(location.search);
    if (!focusSiteId || !loaded) return;

    const row = rowRefs.current.get(focusSiteId);
    const cleanedSearch = clearFocusParams(location.search);
    if (!row) {
      navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
      return;
    }

    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setHighlightSiteId(focusSiteId);
    if (highlightTimerRef.current) window.clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = window.setTimeout(() => {
      setHighlightSiteId((current) => (current === focusSiteId ? null : current));
    }, 2200);

    navigate({ pathname: location.pathname, search: cleanedSearch }, { replace: true });
  }, [loaded, location.pathname, location.search, navigate, sortedSites]);

  const closeEditor = () => {
    setEditor(null);
    setForm(emptySiteForm());
  };

  const scrollToEditorTop = () => {
    const scrollTo = (globalThis as { scrollTo?: (options?: ScrollToOptions) => void }).scrollTo;
    if (typeof scrollTo === 'function') {
      scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const openAdd = () => {
    if (isAdding) {
      closeEditor();
      return;
    }
    setEditor({ mode: 'add' });
    setForm(emptySiteForm());
    scrollToEditorTop();
  };

  const openEdit = (site: SiteRow) => {
    setEditor({ mode: 'edit', editingSiteId: site.id });
    setForm(siteFormFromSite(site));
    scrollToEditorTop();
    // Load disabled models for this site
    setDisabledModelsLoading(true);
    setDisabledModels([]);
    setDisabledModelInput('');
    api.getSiteDisabledModels(site.id)
      .then((res: any) => setDisabledModels(Array.isArray(res?.models) ? res.models : []))
      .catch(() => { })
      .finally(() => setDisabledModelsLoading(false));
  };

  const handleAddDisabledModel = () => {
    const model = disabledModelInput.trim();
    if (!model) return;
    if (disabledModels.includes(model)) {
      toast.info(`模型 "${model}" 已在禁用列表中`);
      setDisabledModelInput('');
      return;
    }
    setDisabledModels((prev) => [...prev, model]);
    setDisabledModelInput('');
  };

  const handleRemoveDisabledModel = (model: string) => {
    setDisabledModels((prev) => prev.filter((m) => m !== model));
  };

  const handleSaveDisabledModels = async () => {
    if (!editor || editor.mode !== 'edit') return;
    setDisabledModelsSaving(true);
    try {
      await api.updateSiteDisabledModels(editor.editingSiteId, disabledModels);
      try {
        await api.rebuildRoutes(false, false);
        toast.success('禁用模型列表已保存，路由已重建');
      } catch {
        toast.error('禁用模型列表已保存，但路由重建失败，请手动刷新路由');
      }
    } catch (e: any) {
      toast.error(e.message || '保存禁用模型失败');
    } finally {
      setDisabledModelsSaving(false);
    }
  };

  const handleSave = async () => {
    if (!editor) return;
    const parsedGlobalWeight = Number(form.globalWeight);
    if (!Number.isFinite(parsedGlobalWeight) || parsedGlobalWeight <= 0) {
      toast.error('全局权重必须是大于 0 的数字');
      return;
    }
    const serializedCustomHeaders = serializeSiteCustomHeaders(form.customHeaders);
    if (!serializedCustomHeaders.valid) {
      toast.error(serializedCustomHeaders.error || '自定义请求头格式不正确');
      return;
    }

    const payload = {
      name: form.name.trim(),
      url: form.url.trim(),
      externalCheckinUrl: form.externalCheckinUrl.trim(),
      platform: form.platform.trim(),
      useSystemProxy: !!form.useSystemProxy,
      customHeaders: serializedCustomHeaders.customHeaders,
      globalWeight: Number(parsedGlobalWeight.toFixed(3)),
    };
    if (!payload.name || !payload.url) {
      toast.error('请填写站点名称和 URL');
      return;
    }

    setSaving(true);
    try {
      const action = buildSiteSaveAction(editor, payload);
      if (action.kind === 'add') {
        const created = await api.addSite(action.payload);
        toast.success(`站点 "${payload.name}" 已添加`);
        const createdSiteId = Number(created?.id) || 0;
        if (createdSiteId > 0) {
          const createdPlatform = typeof created?.platform === 'string' && created.platform.trim()
            ? created.platform.trim()
            : payload.platform;
          const params = new URLSearchParams({
            create: '1',
            siteId: String(createdSiteId),
          });
          if (String(createdPlatform || '').trim().toLowerCase() === 'codex') {
            params.set('provider', 'codex');
            navigate(`/oauth?${params.toString()}`);
            return;
          }
          const initialSegment = resolveInitialConnectionSegment(createdPlatform);
          if (initialSegment === 'apikey') {
            params.set('segment', 'apikey');
          }
          navigate(`/accounts?${params.toString()}`);
        }
      } else {
        await api.updateSite(action.id, action.payload);
        toast.success(`站点 "${payload.name}" 已更新`);
      }
      closeEditor();
      await load();
    } catch (e: any) {
      toast.error(e.message || '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const updateCustomHeaderRow = (index: number, field: 'key' | 'value', value: string) => {
    setForm((prev) => ({
      ...prev,
      customHeaders: prev.customHeaders.map((item, itemIndex) => (
        itemIndex === index
          ? { ...item, [field]: value }
          : item
      )),
    }));
  };

  const addCustomHeaderRow = () => {
    setForm((prev) => ({
      ...prev,
      customHeaders: [...prev.customHeaders, emptySiteCustomHeader()],
    }));
  };

  const removeCustomHeaderRow = (index: number) => {
    setForm((prev) => {
      const nextHeaders = prev.customHeaders.filter((_, itemIndex) => itemIndex !== index);
      return {
        ...prev,
        customHeaders: nextHeaders.length > 0 ? nextHeaders : [emptySiteCustomHeader()],
      };
    });
  };

  const handleDetect = async () => {
    if (!form.url.trim()) {
      toast.error('请先输入 URL');
      return;
    }
    setDetecting(true);
    try {
      const result = await api.detectSite(form.url.trim());
      if (result?.platform) {
        setForm((prev) => ({ ...prev, platform: result.platform }));
        toast.success(`检测到平台: ${result.platform}`);
      } else {
        toast.error(result?.error || '无法识别平台类型');
      }
    } catch (e: any) {
      toast.error(e.message || '自动检测失败');
    } finally {
      setDetecting(false);
    }
  };

  const handleDelete = async (site: SiteRow) => {
    setDeleteConfirm({ mode: 'single', siteId: site.id, siteName: site.name });
  };

  const handleToggleStatus = async (site: SiteRow) => {
    const nextStatus = site.status === 'disabled' ? 'active' : 'disabled';
    setTogglingSiteId(site.id);
    try {
      await api.updateSite(site.id, { status: nextStatus });
      toast.success(nextStatus === 'disabled' ? `站点 "${site.name}" 已禁用` : `站点 "${site.name}" 已启用`);
      await load();
    } catch (e: any) {
      toast.error(e.message || '切换站点状态失败');
    } finally {
      setTogglingSiteId(null);
    }
  };

  const handleTogglePin = async (site: SiteRow) => {
    const nextPinned = !site.isPinned;
    setPinningSiteId(site.id);
    try {
      await api.updateSite(site.id, { isPinned: nextPinned });
      toast.success(nextPinned ? `站点 "${site.name}" 已置顶` : `站点 "${site.name}" 已取消置顶`);
      await load();
    } catch (e: any) {
      toast.error(e.message || '切换置顶失败');
    } finally {
      setPinningSiteId(null);
    }
  };

  const handleMoveCustomOrder = async (site: SiteRow, direction: 'up' | 'down') => {
    const updates = buildCustomReorderUpdates(sites, site.id, direction);
    if (updates.length === 0) return;

    setOrderingSiteId(site.id);
    try {
      await Promise.all(updates.map((update) => api.updateSite(update.id, { sortOrder: update.sortOrder })));
      await load();
    } catch (e: any) {
      toast.error(e.message || '更新排序失败');
    } finally {
      setOrderingSiteId(null);
    }
  };

  const toggleSiteSelection = (siteId: number, checked: boolean) => {
    setSelectedSiteIds((current) => (
      checked
        ? Array.from(new Set([...current, siteId]))
        : current.filter((id) => id !== siteId)
    ));
  };

  const toggleSelectAllVisible = (checked: boolean) => {
    if (!checked) {
      setSelectedSiteIds([]);
      return;
    }
    setSelectedSiteIds(sortedSites.map((site) => site.id));
  };

  const toggleSiteDetails = (siteId: number) => {
    setExpandedSiteIds((current) => (
      current.includes(siteId)
        ? current.filter((id) => id !== siteId)
        : [...current, siteId]
    ));
  };

  const runBatchAction = async (action: 'enable' | 'disable' | 'delete' | 'enableSystemProxy' | 'disableSystemProxy', skipDeleteConfirm = false) => {
    if (selectedSiteIds.length === 0) return;
    if (action === 'delete' && !skipDeleteConfirm) {
      setDeleteConfirm({ mode: 'batch', count: selectedSiteIds.length });
      return;
    }

    setBatchActionLoading(true);
    try {
      const result = await api.batchUpdateSites({
        ids: selectedSiteIds,
        action,
      });
      const successIds = Array.isArray(result?.successIds) ? result.successIds.map((id: unknown) => Number(id)) : [];
      const failedItems = Array.isArray(result?.failedItems) ? result.failedItems : [];
      if (failedItems.length > 0) {
        toast.info(`批量操作完成：成功 ${successIds.length}，失败 ${failedItems.length}`);
      } else {
        toast.success(`批量操作完成：成功 ${successIds.length}`);
      }
      setSelectedSiteIds(failedItems.map((item: any) => Number(item.id)).filter((id: number) => Number.isFinite(id) && id > 0));
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
    if (target.mode === 'single' && target.siteId) {
      setDeleting(target.siteId);
      try {
        await api.deleteSite(target.siteId);
        toast.success(`站点 "${target.siteName || target.siteId}" 已删除`);
        await load();
      } catch (e: any) {
        toast.error(e.message || '删除失败');
      } finally {
        setDeleting(null);
      }
      return;
    }

    await runBatchAction('delete', true);
  };

  const handleSiteRowClick = (siteId: number, event: React.MouseEvent<HTMLTableRowElement>) => {
    if (shouldIgnoreRowSelectionClick(event.target)) return;
    const isSelected = selectedSiteIds.includes(siteId);
    toggleSiteSelection(siteId, !isSelected);
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">{tr('站点管理')}</h2>
        <div className="page-actions sites-page-actions">
          <div className="sites-sort-select" style={{ minWidth: 156, position: 'relative', zIndex: 20 }}>
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
          <button onClick={openAdd} className="btn btn-primary">
            {isAdding ? '取消' : '+ 添加站点'}
          </button>
        </div>
      </div>

      {!isMobile && selectedSiteIds.length > 0 && (
        <div className="card" style={{ padding: 12, marginBottom: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 13, fontWeight: 600 }}>已选 {selectedSiteIds.length} 项</span>
          <button
            data-testid="sites-batch-enable-system-proxy"
            onClick={() => runBatchAction('enableSystemProxy')}
            disabled={batchActionLoading}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            批量开启系统代理
          </button>
          <button
            onClick={() => runBatchAction('disableSystemProxy')}
            disabled={batchActionLoading}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)' }}
          >
            批量关闭系统代理
          </button>
          <button onClick={() => runBatchAction('enable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量启用
          </button>
          <button onClick={() => runBatchAction('disable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
            批量禁用
          </button>
          <button onClick={() => runBatchAction('delete')} disabled={batchActionLoading} className="btn btn-link btn-link-danger">
            批量删除
          </button>
        </div>
      )}

      {isMobile && selectedSiteIds.length > 0 && (
        <div className="mobile-actions-bar">
          <span className="mobile-actions-info">已选 {selectedSiteIds.length} 项</span>
          <div className="mobile-actions-row">
            <button
              data-testid="sites-batch-enable-system-proxy"
              onClick={() => runBatchAction('enableSystemProxy')}
              disabled={batchActionLoading}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              批量开启系统代理
            </button>
            <button
              onClick={() => runBatchAction('disableSystemProxy')}
              disabled={batchActionLoading}
              className="btn btn-ghost"
              style={{ border: '1px solid var(--color-border)' }}
            >
              批量关闭系统代理
            </button>
            <button onClick={() => runBatchAction('enable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
              批量启用
            </button>
            <button onClick={() => runBatchAction('disable')} disabled={batchActionLoading} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
              批量禁用
            </button>
            <button onClick={() => runBatchAction('delete')} disabled={batchActionLoading} className="btn btn-link btn-link-danger">
              批量删除
            </button>
          </div>
        </div>
      )}

      <div className="info-tip" style={{ marginBottom: 12 }}>
        站点权重说明：最终站点倍率 = 站点全局权重 × 设置页中下游 API Key 的站点倍率。它会与路由策略因子（基础权重、价值分、成本、余额、使用频次）共同作用。数值越大，该站点在同优先级下越容易被选中。建议范围 0.5-3，默认 1；长期不建议超过 5。
      </div>

      <DeleteConfirmModal
        open={Boolean(deleteConfirm)}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={confirmDelete}
        title="确认删除站点"
        confirmText="确认删除"
        loading={batchActionLoading || (deleteConfirm?.mode === 'single' && deleting === deleteConfirm?.siteId)}
        description={deleteConfirm?.mode === 'single'
          ? <>确定要删除站点 <strong>{deleteConfirm.siteName || `#${deleteConfirm.siteId}`}</strong> 吗？</>
          : <>确定要删除选中的 <strong>{deleteConfirm?.count || 0}</strong> 个站点吗？</>}
      />

      {activeEditor && (
        <CenteredModal
          open={Boolean(editor)}
          onClose={closeEditor}
          title={(
            <div style={{ fontSize: 14, fontWeight: 600 }}>
              {isEditing ? '编辑站点' : '添加站点'}
            </div>
          )}
          maxWidth={920}
          bodyStyle={{
            maxHeight: isMobile ? '78vh' : '72vh',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: 12,
          }}
          footer={(
            <>
              <button onClick={closeEditor} className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }}>
                取消
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !form.name.trim() || !form.url.trim()}
                className="btn btn-primary"
              >
                {saving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : (isEditing ? '保存修改' : '保存站点')}
              </button>
            </>
          )}
        >
          <input
            placeholder="站点名称"
            value={form.name}
            onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
            style={formInputStyle}
          />
          <div style={{ display: 'flex', gap: 8, flexDirection: isMobile ? 'column' : 'row' }}>
            <input
              placeholder="站点 URL (例如 https://api.example.com)"
              value={form.url}
              onChange={(e) => setForm((prev) => ({ ...prev, url: e.target.value }))}
              onBlur={() => {
                if (form.url.trim() && !form.platform.trim()) {
                  handleDetect();
                }
              }}
              style={{ ...formInputStyle, flex: 1 }}
            />
            <button
              onClick={handleDetect}
              disabled={detecting || !form.url.trim()}
              className="btn btn-ghost"
              style={{ padding: '10px 14px', minWidth: 96, border: '1px solid var(--color-border)' }}
            >
              {detecting ? <><span className="spinner spinner-sm" /> 检测中</> : '自动检测'}
            </button>
          </div>
          <div
            style={{
              border: `1px solid ${form.platform.trim() ? 'color-mix(in srgb, var(--color-success) 48%, transparent)' : 'var(--color-border)'}`,
              borderRadius: 'var(--radius-sm)',
              background: form.platform.trim() ? 'color-mix(in srgb, var(--color-success) 10%, var(--color-bg))' : 'var(--color-bg)',
              transition: 'all 0.2s',
            }}
          >
            <ModernSelect
              value={form.platform}
              onChange={(value) => setForm((prev) => ({ ...prev, platform: value }))}
              options={platformOptions}
              placeholder="平台类型（可自动检测）"
            />
          </div>
          <input
            placeholder="外部签到/福利站点 URL（可选）"
            value={form.externalCheckinUrl}
            onChange={(e) => setForm((prev) => ({ ...prev, externalCheckinUrl: e.target.value }))}
            style={formInputStyle}
          />
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
              padding: 12,
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-sm)',
              background: 'color-mix(in srgb, var(--color-surface) 82%, transparent)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>
                站点自定义请求头
              </div>
              <button
                type="button"
                onClick={addCustomHeaderRow}
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)' }}
              >
                + 添加请求头
              </button>
            </div>
            {form.customHeaders.map((header, index) => (
              <div
                key={`custom-header-${index}`}
                style={{
                  display: 'flex',
                  gap: 8,
                  flexDirection: isMobile ? 'column' : 'row',
                  alignItems: isMobile ? 'stretch' : 'center',
                }}
              >
                <input
                  placeholder="Header 名称"
                  value={header.key}
                  onChange={(e) => updateCustomHeaderRow(index, 'key', e.target.value)}
                  style={{ ...formInputStyle, flex: 1, fontFamily: 'var(--font-mono)' }}
                />
                <input
                  placeholder="Header 值"
                  value={header.value}
                  onChange={(e) => updateCustomHeaderRow(index, 'value', e.target.value)}
                  style={{ ...formInputStyle, flex: 1, fontFamily: 'var(--font-mono)' }}
                />
                <button
                  type="button"
                  onClick={() => removeCustomHeaderRow(index)}
                  className="btn btn-link btn-link-danger"
                  style={isMobile ? { alignSelf: 'flex-end' } : undefined}
                >
                  删除
                </button>
              </div>
            ))}
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', lineHeight: 1.6 }}>
              按 key/value 逐条填写。整行留空会自动忽略；同名请求头不允许重复；请求本身显式传入的请求头优先级更高。
            </div>
            {isEditing && (
              <div style={{ marginTop: 16, padding: '14px', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg)' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>禁用模型管理</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 10 }}>
                  在此站点禁用指定模型后，路由重建时将不为该站点的这些模型创建通道。
                </div>
                {disabledModelsLoading ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--color-text-muted)' }}>
                    <span className="spinner spinner-sm" /> 加载中...
                  </div>
                ) : (
                  <>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10, minHeight: 24 }}>
                      {disabledModels.length === 0 && (
                        <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>暂无禁用模型</span>
                      )}
                      {disabledModels.map((model) => (
                        <span
                          key={model}
                          className="badge badge-muted"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '3px 8px' }}
                        >
                          {model}
                          <button
                            type="button"
                            onClick={() => handleRemoveDisabledModel(model)}
                            style={{
                              background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                              fontSize: 13, lineHeight: 1, color: 'var(--color-text-muted)',
                            }}
                            title={`移除 ${model}`}
                          >
                            ×
                          </button>
                        </span>
                      ))}
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input
                        placeholder="输入模型名称，如 gpt-4o"
                        value={disabledModelInput}
                        onChange={(e) => setDisabledModelInput(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddDisabledModel(); } }}
                        style={{
                          flex: 1, padding: '8px 12px', border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius-sm)', fontSize: 12, outline: 'none',
                          background: 'var(--color-bg)', color: 'var(--color-text-primary)',
                        }}
                      />
                      <button onClick={handleAddDisabledModel} className="btn btn-ghost" style={{ padding: '8px 14px', fontSize: 12, border: '1px solid var(--color-border)' }}>
                        添加
                      </button>
                    </div>
                    <button
                      onClick={handleSaveDisabledModels}
                      disabled={disabledModelsSaving}
                      className="btn btn-primary"
                      style={{ marginTop: 10, fontSize: 12, padding: '6px 16px' }}
                    >
                      {disabledModelsSaving ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存禁用列表'}
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '10px 14px',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 13,
            background: 'var(--color-bg)',
            color: 'var(--color-text-primary)',
          }}>
            <input
              type="checkbox"
              checked={form.useSystemProxy}
              onChange={(e) => setForm((prev) => ({ ...prev, useSystemProxy: e.target.checked }))}
            />
            使用系统代理
          </label>
          <input
            placeholder="站点全局权重（默认 1）"
            value={form.globalWeight}
            onChange={(e) => setForm((prev) => ({ ...prev, globalWeight: e.target.value }))}
            style={formInputStyle}
          />
          <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
            越大越容易被路由选中。建议 0.5-3，默认 1。
          </div>
        </CenteredModal>
      )}

      <div className="card" style={{ overflowX: 'auto' }}>
        {sites.length > 0 ? (
          isMobile ? (
            <div className="mobile-card-list">
              {sortedSites.map((site) => {
                const isExpanded = expandedSiteIds.includes(site.id);
                return (
                  <MobileCard
                    key={site.id}
                    title={site.name || '-'}
                    actions={(
                      <input
                        type="checkbox"
                        aria-label={`选择站点 ${site.name || site.id}`}
                        checked={selectedSiteIds.includes(site.id)}
                        onChange={(event) => toggleSiteSelection(site.id, event.target.checked)}
                      />
                    )}
                  >
                    <MobileField
                      label="状态"
                      value={(
                        <span className={`badge ${site.status === 'disabled' ? 'badge-muted' : 'badge-success'}`} style={{ fontSize: 11 }}>
                          {site.status === 'disabled' ? '禁用' : '启用'}
                        </span>
                      )}
                    />
                    <MobileField
                      label="平台"
                      value={(
                        <span className={`badge ${platformColors[site.platform || ''] || 'badge-muted'}`} style={{ fontSize: 11 }}>
                          {site.platform || '-'}
                        </span>
                      )}
                    />
                    <MobileField label="余额" value={`$${(site.totalBalance || 0).toFixed(2)}`} />
                    <MobileField label="权重" value={(site.globalWeight || 1).toFixed(2)} />
                    {isExpanded ? (
                      <div className="mobile-card-extra">
                        <MobileField
                          label="系统代理"
                          value={(
                            <span className={`badge ${site.useSystemProxy ? 'badge-info' : 'badge-muted'}`} style={{ fontSize: 11 }}>
                              {site.useSystemProxy ? '已开启' : '未开启'}
                            </span>
                          )}
                        />
                        <MobileField
                          label="外部签到站URL"
                          value={site.externalCheckinUrl ? (
                            <a
                              href={site.externalCheckinUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="sites-url-link"
                              style={{
                                fontSize: 12,
                                fontFamily: 'var(--font-mono)',
                                color: 'var(--color-primary)',
                                textDecoration: 'underline',
                                wordBreak: 'break-all',
                              }}
                            >
                              {site.externalCheckinUrl}
                            </a>
                          ) : '-'}
                        />
                        <MobileField
                          label="自定义头"
                          value={hasConfiguredCustomHeaders(site.customHeaders) ? '已配置' : '-'}
                        />
                        <MobileField
                          label="创建时间"
                          value={formatDateTimeLocal(site.createdAt)}
                        />
                      </div>
                    ) : null}
                    <div className="mobile-card-actions">
                      <button
                        type="button"
                        onClick={() => toggleSiteDetails(site.id)}
                        className="btn btn-link"
                      >
                        {isExpanded ? '收起' : '详情'}
                      </button>
                      <button
                        onClick={() => handleTogglePin(site)}
                        disabled={pinningSiteId === site.id}
                        className={`btn btn-link ${site.isPinned ? 'btn-link-warning' : 'btn-link-primary'}`}
                      >
                        {pinningSiteId === site.id ? <span className="spinner spinner-sm" /> : (site.isPinned ? '取消置顶' : '置顶')}
                      </button>
                      {sortMode === 'custom' && (
                        <>
                          <button
                            onClick={() => handleMoveCustomOrder(site, 'up')}
                            disabled={orderingSiteId === site.id}
                            className="btn btn-link btn-link-muted"
                          >
                            ↑
                          </button>
                          <button
                            onClick={() => handleMoveCustomOrder(site, 'down')}
                            disabled={orderingSiteId === site.id}
                            className="btn btn-link btn-link-muted"
                          >
                            ↓
                          </button>
                        </>
                      )}
                      <button
                        onClick={() => openEdit(site)}
                        className="btn btn-link btn-link-primary"
                      >
                        编辑
                      </button>
                      <button
                        onClick={() => handleToggleStatus(site)}
                        disabled={togglingSiteId === site.id}
                        className={`btn btn-link ${site.status === 'disabled' ? 'btn-link-primary' : 'btn-link-warning'}`}
                      >
                        {togglingSiteId === site.id ? <span className="spinner spinner-sm" /> : (site.status === 'disabled' ? '启用' : '禁用')}
                      </button>
                      <button
                        onClick={() => handleDelete(site)}
                        disabled={deleting === site.id}
                        className="btn btn-link btn-link-danger"
                      >
                        {deleting === site.id ? <span className="spinner spinner-sm" /> : null}
                        删除
                      </button>
                    </div>
                  </MobileCard>
                );
              })}
            </div>
          ) : (
            <table className="data-table sites-table">
              <thead>
                <tr>
                  <th style={{ width: 44 }}>
                    <input
                      type="checkbox"
                      checked={sortedSites.length > 0 && selectedSiteIds.length === sortedSites.length}
                      onChange={(e) => toggleSelectAllVisible(e.target.checked)}
                    />
                  </th>
                  <th>名称</th>
                  <th>外部签到站URL</th>
                  <th>总余额</th>
                  <th>状态</th>
                  <th>系统代理</th>
                  <th>权重</th>
                  <th>平台</th>
                  <th>创建时间</th>
                  <th className="sites-actions-col" style={{ textAlign: 'right' }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {sortedSites.map((site, i) => (
                  <tr
                    key={site.id}
                    data-testid={`site-row-${site.id}`}
                    ref={(node) => {
                      if (node) rowRefs.current.set(site.id, node);
                      else rowRefs.current.delete(site.id);
                    }}
                    onClick={(event) => handleSiteRowClick(site.id, event)}
                    className={`animate-slide-up stagger-${Math.min(i + 1, 5)} row-selectable ${selectedSiteIds.includes(site.id) ? 'row-selected' : ''} ${highlightSiteId === site.id ? 'row-focus-highlight' : ''}`.trim()}
                  >
                    <td>
                      <input
                        data-testid={`site-select-${site.id}`}
                        type="checkbox"
                        checked={selectedSiteIds.includes(site.id)}
                        onChange={(e) => toggleSiteSelection(site.id, e.target.checked)}
                      />
                    </td>
                    <td style={{ fontWeight: 600 }}>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          color: 'var(--color-text-primary)',
                          textDecoration: 'underline',
                        }}
                      >
                        {site.name}
                      </a>
                    </td>
                    <td className="sites-url-cell" style={{ maxWidth: 300 }}>
                      {site.externalCheckinUrl ? (
                        <a
                          href={site.externalCheckinUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="sites-url-link"
                          style={{
                            fontSize: 12,
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-primary)',
                            textDecoration: 'underline',
                            wordBreak: 'break-all',
                          }}
                        >
                          {site.externalCheckinUrl}
                        </a>
                      ) : null}
                    </td>
                    <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                      ${(site.totalBalance || 0).toFixed(2)}
                    </td>
                    <td>
                      <span className={`badge ${site.status === 'disabled' ? 'badge-muted' : 'badge-success'}`} style={{ fontSize: 11 }}>
                        {site.status === 'disabled' ? '禁用' : '启用'}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${site.useSystemProxy ? 'badge-info' : 'badge-muted'}`} style={{ fontSize: 11 }}>
                        {site.useSystemProxy ? '已开启' : '未开启'}
                      </span>
                    </td>
                    <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                      {(site.globalWeight || 1).toFixed(2)}
                    </td>
                    <td>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ textDecoration: 'none' }}
                      >
                        <span className={`badge ${platformColors[site.platform || ''] || 'badge-muted'}`}>
                          {site.platform || '-'}
                        </span>
                      </a>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: 'var(--color-text-muted)', textDecoration: 'underline' }}
                      >
                        {formatDateTimeLocal(site.createdAt)}
                      </a>
                    </td>
                    <td className="sites-actions-cell" style={{ textAlign: 'right' }}>
                      <div className="sites-row-actions">
                        <button
                          onClick={() => handleTogglePin(site)}
                          disabled={pinningSiteId === site.id}
                          className={`btn btn-link ${site.isPinned ? 'btn-link-warning' : 'btn-link-primary'}`}
                        >
                          {pinningSiteId === site.id ? <span className="spinner spinner-sm" /> : (site.isPinned ? '取消置顶' : '置顶')}
                        </button>
                        {sortMode === 'custom' && (
                          <>
                            <button
                              onClick={() => handleMoveCustomOrder(site, 'up')}
                              disabled={orderingSiteId === site.id}
                              className="btn btn-link btn-link-muted"
                            >
                              ↑
                            </button>
                            <button
                              onClick={() => handleMoveCustomOrder(site, 'down')}
                              disabled={orderingSiteId === site.id}
                              className="btn btn-link btn-link-muted"
                            >
                              ↓
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => openEdit(site)}
                          className="btn btn-link btn-link-primary"
                        >
                          编辑
                        </button>
                        <button
                          onClick={() => handleToggleStatus(site)}
                          disabled={togglingSiteId === site.id}
                          className={`btn btn-link ${site.status === 'disabled' ? 'btn-link-primary' : 'btn-link-warning'}`}
                        >
                          {togglingSiteId === site.id ? <span className="spinner spinner-sm" /> : (site.status === 'disabled' ? '启用' : '禁用')}
                        </button>
                        <button
                          onClick={() => handleDelete(site)}
                          disabled={deleting === site.id}
                          className="btn btn-link btn-link-danger"
                        >
                          {deleting === site.id ? <span className="spinner spinner-sm" /> : null}
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          <div className="empty-state">
            <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"
              />
            </svg>
            <div className="empty-state-title">暂无站点</div>
            <div className="empty-state-desc">点击“+ 添加站点”开始使用。</div>
          </div>
        )}
      </div>
    </div>
  );
}
