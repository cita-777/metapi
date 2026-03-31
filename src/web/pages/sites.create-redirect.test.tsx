import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import ModernSelect from '../components/ModernSelect.js';
import { ToastProvider } from '../components/Toast.js';
import Sites from './Sites.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSites: vi.fn(),
    addSite: vi.fn(),
    getSiteDisabledModels: vi.fn().mockResolvedValue({ models: [] }),
    getSiteAvailableModels: vi.fn().mockResolvedValue({ models: [] }),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function collectText(node: any): string {
  const children = node?.children || [];
  return children.map((child: any) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

async function flushMicrotasks() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function LocationProbe() {
  const location = useLocation();
  return <div>{`${location.pathname}${location.search}`}</div>;
}

async function createSiteAndClickModalChoice(createdSite: { id: number; name: string; platform?: string | null }, choice: 'session' | 'apikey' | 'later') {
  apiMock.getSites.mockResolvedValue([]);
  apiMock.addSite.mockResolvedValue(createdSite);

  let root!: WebTestRenderer;
  try {
    await act(async () => {
      root = create(
        <ToastProvider>
          <MemoryRouter initialEntries={['/sites']}>
            <Routes>
              <Route path="/sites" element={<Sites />} />
              <Route path="/accounts" element={<LocationProbe />} />
              <Route path="/oauth" element={<LocationProbe />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>,
      );
    });
    await flushMicrotasks();

    const addButton = root.root.find((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && typeof node.props.className === 'string'
      && node.props.className.includes('btn btn-primary')
      && JSON.stringify(node.props.children).includes('添加站点')
    ));

    await act(async () => {
      addButton.props.onClick();
    });
    await flushMicrotasks();

    const nameInput = root.root.find((node) => node.type === 'input' && node.props.placeholder === '站点名称');
    const urlInput = root.root.find((node) => (
      node.type === 'input'
      && node.props.placeholder === '站点 URL (例如 https://api.example.com)'
    ));
    const selects = root.root.findAllByType(ModernSelect);
    const platformSelect = selects.at(-1);
    const saveButton = root.root.find((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && collectText(node).includes('保存站点')
    ));

    await act(async () => {
      nameInput.props.onChange({ target: { value: 'Demo Site' } });
      urlInput.props.onChange({ target: { value: 'https://demo.example.com' } });
      platformSelect?.props.onChange(createdSite.platform || '');
    });

    await act(async () => {
      await saveButton.props.onClick();
    });
    await flushMicrotasks();

    // Find the modal dialog and click the appropriate button
    const modalDialog = root.root.find((node) => node.type === 'dialog');
    const modalButtons = modalDialog.findAll((node) => node.type === 'button');

    // Find the button based on choice
    let targetButton;
    if (choice === 'session') {
      targetButton = modalButtons.find((btn) => collectText(btn).includes('添加账号（用户名密码登录）'));
    } else if (choice === 'apikey') {
      targetButton = modalButtons.find((btn) => collectText(btn).includes('添加 API Key'));
    } else {
      targetButton = modalButtons.find((btn) => collectText(btn).includes('稍后配置'));
    }

    if (targetButton) {
      await act(async () => {
        targetButton.props.onClick();
      });
      await flushMicrotasks();
    }

    return JSON.stringify(root.toJSON());
  } finally {
    root?.unmount();
  }
}

describe('Sites create redirect', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows modal after creating a site and navigates to session account when user chooses it', async () => {
    const rendered = await createSiteAndClickModalChoice({ id: 21, name: 'Demo Site', platform: 'new-api' }, 'session');

    expect(rendered).toContain('/accounts?create=1&siteId=21');
    expect(rendered).not.toContain('segment=apikey');
  });

  it('shows modal after creating a site and navigates to API key when user chooses it', async () => {
    const rendered = await createSiteAndClickModalChoice({ id: 22, name: 'Demo Site', platform: 'openai' }, 'apikey');

    expect(rendered).toContain('/accounts?');
    expect(rendered).toContain('segment=apikey');
    expect(rendered).toContain('create=1');
    expect(rendered).toContain('siteId=22');
  });

  it('shows modal after creating a codex site and allows choosing later', async () => {
    const rendered = await createSiteAndClickModalChoice({ id: 23, name: 'Demo Site', platform: 'codex' }, 'later');

    // User chose "later", so should stay on sites page (no navigation to accounts or oauth)
    expect(rendered).not.toContain('/oauth?');
    expect(rendered).not.toContain('/accounts?');
  });

  it('shows modal after creating a codex site and navigates to OAuth when user chooses session', async () => {
    const rendered = await createSiteAndClickModalChoice({ id: 24, name: 'Demo Site', platform: 'codex' }, 'session');

    expect(rendered).toContain('/oauth?');
    expect(rendered).toContain('provider=codex');
    expect(rendered).toContain('create=1');
    expect(rendered).toContain('siteId=24');
  });

  it('shows modal with all three choices after creating a site', async () => {
    apiMock.getSites.mockResolvedValue([]);
    apiMock.addSite.mockResolvedValue({ id: 24, name: 'Demo Site', platform: 'new-api' });

    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <ToastProvider>
          <MemoryRouter initialEntries={['/sites']}>
            <Routes>
              <Route path="/sites" element={<Sites />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>,
      );
    });
    await flushMicrotasks();

    // Click add button
    const addButton = root.root.find((node) => (
      node.type === 'button'
      && node.props.className?.includes('btn btn-primary')
      && JSON.stringify(node.props.children).includes('添加站点')
    ));
    await act(async () => {
      addButton.props.onClick();
    });
    await flushMicrotasks();

    // Fill form
    const nameInput = root.root.find((node) => node.type === 'input' && node.props.placeholder === '站点名称');
    const urlInput = root.root.find((node) => (
      node.type === 'input'
      && node.props.placeholder === '站点 URL (例如 https://api.example.com)'
    ));
    const selects = root.root.findAllByType(ModernSelect);
    const platformSelect = selects.at(-1);
    const saveButton = root.root.find((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && collectText(node).includes('保存站点')
    ));

    await act(async () => {
      nameInput.props.onChange({ target: { value: 'Demo Site' } });
      urlInput.props.onChange({ target: { value: 'https://demo.example.com' } });
      platformSelect?.props.onChange('new-api');
    });

    await act(async () => {
      await saveButton.props.onClick();
    });
    await flushMicrotasks();

    // Check modal appears with all three buttons
    const rendered = JSON.stringify(root.toJSON());
    expect(rendered).toContain('站点创建成功');
    expect(rendered).toContain('添加账号（用户名密码登录）');
    expect(rendered).toContain('添加 API Key');
    expect(rendered).toContain('稍后配置');

    root.unmount();
  });
});
