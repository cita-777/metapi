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

async function createSiteAndCollectLocation(createdSite: { id: number; platform?: string | null }) {
  apiMock.getSites.mockResolvedValue([]);
  apiMock.addSite.mockResolvedValue(createdSite);

  let root: ReturnType<typeof create> | null = null;
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

  it('redirects a session-capable site to the session connection create flow', async () => {
    const rendered = await createSiteAndCollectLocation({ id: 21, platform: 'new-api' });

    expect(rendered).toContain('/accounts?create=1&siteId=21');
    expect(rendered).not.toContain('segment=apikey');
  });

  it('redirects an official API-key-only site to the apikey connection create flow', async () => {
    const rendered = await createSiteAndCollectLocation({ id: 22, platform: 'openai' });

    expect(rendered).toContain('/accounts?');
    expect(rendered).toContain('segment=apikey');
    expect(rendered).toContain('create=1');
    expect(rendered).toContain('siteId=22');
  });

  it('redirects a codex site to oauth management instead of legacy account import', async () => {
    const rendered = await createSiteAndCollectLocation({ id: 23, platform: 'codex' });

    expect(rendered).toContain('/oauth?');
    expect(rendered).toContain('provider=codex');
    expect(rendered).toContain('create=1');
    expect(rendered).toContain('siteId=23');
  });
});
