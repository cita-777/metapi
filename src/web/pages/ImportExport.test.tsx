import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import { MemoryRouter } from 'react-router-dom';
import ModernSelect from '../components/ModernSelect.js';
import ImportExport from './ImportExport.js';

const { apiMock, toastMock } = vi.hoisted(() => ({
  apiMock: {
    exportBackup: vi.fn(),
    importBackup: vi.fn(),
    getBackupWebdavConfig: vi.fn(),
    saveBackupWebdavConfig: vi.fn(),
    exportBackupToWebdav: vi.fn(),
    importBackupFromWebdav: vi.fn(),
  },
  toastMock: {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    toast: vi.fn(),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

vi.mock('../components/Toast.js', () => ({
  ToastProvider: ({ children }: { children: React.ReactNode }) => children,
  useToast: () => toastMock,
}));

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

const allApiHubV2Payload = JSON.stringify({
  version: '2.0',
  timestamp: 1735689600000,
  accounts: {
    accounts: [
      {
        id: 'managed-account',
        site_url: 'https://newapi.example.com',
        site_type: 'new-api',
        site_name: 'Managed Site',
        authType: 'access_token',
        account_info: {
          id: 7788,
          username: 'managed-user',
          access_token: 'managed-session-token',
        },
      },
      {
        id: 'direct-account',
        site_url: 'https://api.openai.com',
        site_type: 'openai',
        site_name: 'OpenAI Direct',
        authType: 'access_token',
        account_info: {
          username: 'openai-user',
          access_token: 'sk-openai-account',
        },
      },
    ],
    bookmarks: [
      {
        id: 'bookmark-1',
        name: 'Ignored Bookmark',
        url: 'https://bookmark.example.com',
      },
    ],
    pinnedAccountIds: ['direct-account'],
    orderedAccountIds: ['managed-account', 'direct-account'],
    last_updated: 1735689601000,
  },
  preferences: {
    language: 'zh-CN',
  },
  channelConfigs: {
    bySite: {
      demo: { enabled: true },
    },
  },
  tagStore: {
    version: 1,
    tagsById: {},
  },
  apiCredentialProfiles: {
    version: 2,
    profiles: [
      {
        id: 'profile-openai',
        name: 'OpenAI Profile',
        apiType: 'openai',
        baseUrl: 'https://api.openai.com/v1',
        apiKey: 'sk-profile-openai',
        tagIds: [],
        notes: '',
        createdAt: 1735689602000,
        updatedAt: 1735689603000,
      },
      {
        id: 'profile-gemini',
        name: 'Gemini Profile',
        apiType: 'google',
        baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
        apiKey: 'gemini-profile-key',
        tagIds: [],
        notes: '',
        createdAt: 1735689604000,
        updatedAt: 1735689605000,
      },
    ],
    lastUpdated: 1735689606000,
  },
});

const nativeMetapiPayload = JSON.stringify({
  version: '2.1',
  timestamp: 1735689600000,
  accounts: {
    sites: [
      {
        id: 1,
        name: 'Native Site',
        url: 'https://native.example.com',
        platform: 'new-api',
      },
    ],
    accounts: [
      {
        id: 1,
        siteId: 1,
        username: 'native-user',
        accessToken: 'session-token',
        apiToken: 'api-token',
        status: 'active',
      },
    ],
    accountTokens: [
      {
        id: 1,
        accountId: 1,
        name: 'default',
        token: 'sk-native',
        enabled: true,
        isDefault: true,
      },
    ],
    tokenRoutes: [
      {
        id: 1,
        modelPattern: 'gpt-5-nano',
        enabled: true,
      },
    ],
    routeChannels: [
      {
        id: 1,
        routeId: 1,
        accountId: 1,
        tokenId: 1,
        enabled: true,
        manualOverride: false,
      },
    ],
    routeGroupSources: [],
    siteDisabledModels: [
      {
        siteId: 1,
        modelName: 'gpt-hidden',
      },
    ],
    manualModels: [
      {
        accountId: 1,
        modelName: 'gpt-manual',
      },
    ],
    downstreamApiKeys: [
      {
        name: 'Shared Key',
        key: 'downstream-native',
        enabled: true,
        supportedModels: '["gpt-5-nano"]',
      },
    ],
  },
  preferences: {
    settings: [
      { key: 'locale', value: 'zh-CN' },
    ],
  },
});

describe('ImportExport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal('window', {
      confirm: vi.fn(() => true),
    });
    apiMock.getBackupWebdavConfig.mockResolvedValue({
      success: true,
      config: {
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi.json',
        username: 'alice',
        exportType: 'all',
        autoSyncEnabled: true,
        autoSyncCron: '0 */6 * * *',
        hasPassword: true,
        passwordMasked: 'se****ss',
      },
      state: {
        lastSyncAt: null,
        lastError: null,
      },
    });
    apiMock.saveBackupWebdavConfig.mockResolvedValue({
      success: true,
      config: {
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi.json',
        username: 'alice',
        exportType: 'all',
        autoSyncEnabled: true,
        autoSyncCron: '0 */6 * * *',
        hasPassword: true,
        passwordMasked: 'se****ss',
      },
      state: {
        lastSyncAt: null,
        lastError: null,
      },
    });
    apiMock.exportBackupToWebdav.mockResolvedValue({
      success: true,
      fileUrl: 'https://dav.example.com/backups/metapi.json',
      exportType: 'all',
    });
    apiMock.importBackupFromWebdav.mockResolvedValue({
      success: true,
      sections: {
        accounts: true,
        preferences: true,
      },
      appliedSettings: [],
    });
    apiMock.importBackup.mockResolvedValue({
      allImported: true,
      sections: {
        accounts: true,
        preferences: true,
      },
      appliedSettings: [],
      summary: {
        importedSites: 3,
        importedAccounts: 2,
        importedProfiles: 2,
        importedApiKeyConnections: 3,
        skippedAccounts: 1,
        ignoredSections: ['accounts.bookmarks', 'channelConfigs', 'tagStore'],
      },
      warnings: ['跳过 ALL-API-Hub 账号 skipped-account：authType=none 不支持离线迁移'],
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it('shows ALL-API-Hub V2 preview counts and ignored sections', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });

      const textarea = root!.root.findByType('textarea');
      await act(async () => {
        textarea.props.onChange({ target: { value: allApiHubV2Payload } });
      });
      await flushMicrotasks();

      const rendered = collectText(root!.root);
      expect(rendered).toContain('ALL-API-Hub V2');
      expect(rendered).toContain('统计：账号 2 / 书签 1 / 独立 API 凭据 2');
      expect(rendered).toContain('accounts.bookmarks、channelConfigs、tagStore');
    } finally {
      root?.unmount();
    }
  });

  it('does not label native metapi backups as ALL-API-Hub V2', async () => {
    let root!: WebTestRenderer;
    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });

      const textarea = root!.root.findByType('textarea');
      await act(async () => {
        textarea.props.onChange({ target: { value: nativeMetapiPayload } });
      });
      await flushMicrotasks();

      const rendered = collectText(root!.root);
      expect(rendered).not.toContain('ALL-API-Hub V2');
      expect(rendered).toContain('统计：站点 1 / 账号 1 / 令牌 1 / 路由 1 / 通道 1 / 站点禁用模型 1 / 手工模型 1 / 下游 Key 1 / 设置 1');
    } finally {
      root?.unmount();
    }
  });

  it('uses backend import summary in the completion toast', async () => {
    const confirmSpy = vi.mocked((window as { confirm: (...args: unknown[]) => boolean }).confirm);
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });

      const textarea = root!.root.findByType('textarea');
      await act(async () => {
        textarea.props.onChange({ target: { value: allApiHubV2Payload } });
      });
      await flushMicrotasks();

      const importButton = root!.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('导入')
      )).at(-1);

      expect(importButton).toBeTruthy();

      await act(async () => {
        importButton!.props.onClick();
      });
      await flushMicrotasks();

      expect(confirmSpy).toHaveBeenCalled();
      expect(confirmSpy).toHaveBeenCalledWith(
        '导入会覆盖备份中的连接/路由/策略配置或系统设置，但会保留本机日志、公告、缓存和统计，确认继续？',
      );
      expect(apiMock.importBackup).toHaveBeenCalledTimes(1);
      expect(toastMock.success).toHaveBeenCalledWith(
        expect.stringContaining('导入完成：连接与路由策略、系统设置'),
      );
      expect(toastMock.success).toHaveBeenCalledWith(
        expect.stringContaining('站点 3 / 账号 2 / API Key 连接 3 / 跳过 1'),
      );
      expect(toastMock.success).toHaveBeenCalledWith(
        expect.stringContaining('accounts.bookmarks、channelConfigs、tagStore'),
      );
    } finally {
      root?.unmount();
    }
  });

  it('loads webdav config and saves updates from the import/export page', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rendered = collectText(root!.root);
      expect(apiMock.getBackupWebdavConfig).toHaveBeenCalledTimes(1);
      expect(rendered).toContain('WebDAV');
      expect(rendered).toContain('自动同步');

      const saveButton = root!.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存 WebDAV 配置')
      )).at(-1);

      expect(saveButton).toBeTruthy();

      await act(async () => {
        saveButton!.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.saveBackupWebdavConfig).toHaveBeenCalledTimes(1);
    } finally {
      root?.unmount();
    }
  });

  it('shows v2.1 config-backup wording and local-state notice', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const rendered = collectText(root!.root);
      expect(rendered).toContain('Schema v2.1');
      expect(rendered).toContain('导出全部（连接 + 路由 + 策略 + 设置）');
      expect(rendered).toContain('仅导出连接与路由策略');
      expect(rendered).toContain('覆盖备份中的连接/路由/策略配置，但会保留本机日志、公告、缓存和统计。');
    } finally {
      root?.unmount();
    }
  });

  it('renders webdav export type with ModernSelect instead of a native select', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const fileUrlInput = root!.root.findAll((node) => (
        node.type === 'input'
        && node.props.placeholder === 'https://dav.example.com/backups/metapi.json'
      )).at(-1);
      const cronInput = root!.root.findAll((node) => (
        node.type === 'input'
        && node.props.placeholder === '0 */6 * * *'
      )).at(-1);
      const selects = root!.root.findAllByType(ModernSelect);
      const exportTypeSelect = selects.at(-1);

      expect(fileUrlInput?.props.style).toEqual(expect.objectContaining({
        width: '100%',
        padding: '10px 14px',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 13,
        background: 'var(--color-bg)',
        color: 'var(--color-text-primary)',
      }));
      expect(root!.root.findAll((node) => node.type === 'select')).toHaveLength(0);
      expect(exportTypeSelect?.props.value).toBe('all');
      expect(exportTypeSelect?.props.options).toEqual([
        { value: 'all', label: '全部' },
        { value: 'accounts', label: '连接与路由策略' },
        { value: 'preferences', label: '系统设置' },
      ]);
      expect(cronInput?.props.style).toEqual(expect.objectContaining({
        fontFamily: 'var(--font-mono)',
      }));
    } finally {
      root?.unmount();
    }
  });

  it('disables webdav actions while config has unsaved changes', async () => {
    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const fileUrlInput = root!.root.findAll((node) => (
        node.type === 'input'
        && node.props.placeholder === 'https://dav.example.com/backups/metapi.json'
      )).at(-1);

      expect(fileUrlInput).toBeTruthy();

      await act(async () => {
        fileUrlInput!.props.onChange({ target: { value: 'https://dav.example.com/backups/changed.json' } });
      });
      await flushMicrotasks();

      const exportButton = root!.root.findAll((node) => (
        node.type === 'button'
        && collectText(node).includes('立即导出到 WebDAV')
      )).at(-1);
      const importButton = root!.root.findAll((node) => (
        node.type === 'button'
        && collectText(node).includes('从 WebDAV 拉取')
      )).at(-1);

      expect(exportButton?.props.disabled).toBe(true);
      expect(importButton?.props.disabled).toBe(true);
    } finally {
      root?.unmount();
    }
  });

  it('can clear a saved webdav password', async () => {
    apiMock.saveBackupWebdavConfig.mockResolvedValueOnce({
      success: true,
      config: {
        enabled: true,
        fileUrl: 'https://dav.example.com/backups/metapi.json',
        username: 'alice',
        exportType: 'all',
        autoSyncEnabled: true,
        autoSyncCron: '0 */6 * * *',
        hasPassword: false,
        passwordMasked: '',
      },
      state: {
        lastSyncAt: null,
        lastError: null,
      },
    });

    let root!: WebTestRenderer;

    try {
      await act(async () => {
        root = create(
          <MemoryRouter>
            <ImportExport />
          </MemoryRouter>,
        );
      });
      await flushMicrotasks();

      const clearPasswordToggle = root!.root.findAll((node) => (
        node.type === 'label'
        && collectText(node).includes('清空已保存密码')
      )).at(-1);

      expect(clearPasswordToggle).toBeTruthy();

      const checkbox = clearPasswordToggle!.findByType('input');
      await act(async () => {
        checkbox.props.onChange({ target: { checked: true } });
      });
      await flushMicrotasks();

      const saveButton = root!.root.findAll((node) => (
        node.type === 'button'
        && typeof node.props.onClick === 'function'
        && collectText(node).includes('保存 WebDAV 配置')
      )).at(-1);

      expect(saveButton).toBeTruthy();

      await act(async () => {
        saveButton!.props.onClick();
      });
      await flushMicrotasks();

      expect(apiMock.saveBackupWebdavConfig).toHaveBeenCalledWith(expect.objectContaining({
        clearPassword: true,
      }));
    } finally {
      root?.unmount();
    }
  });
});
