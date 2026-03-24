import { describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ToastProvider } from '../components/Toast.js';
import Tokens from './Tokens.js';

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAccountTokens: vi.fn().mockResolvedValue([]),
    getAccounts: vi.fn().mockResolvedValue([]),
    getAccountTokenGroups: vi.fn().mockResolvedValue({ groups: ['default'] }),
  },
}));

vi.mock('../api.js', () => ({
  api: apiMock,
}));

function LocationProbe() {
  const location = useLocation();
  return <div>{`${location.pathname}${location.search}`}</div>;
}

describe('Tokens legacy route redirect', () => {
  it('redirects /tokens to the merged accounts tokens segment', async () => {
    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <ToastProvider>
          <MemoryRouter initialEntries={['/tokens?create=1&accountId=23&model=gpt-4.1']}>
            <Routes>
              <Route path="/tokens" element={<Tokens />} />
              <Route path="/accounts" element={<LocationProbe />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>,
      );
    });

    const rendered = JSON.stringify(root?.toJSON());
    expect(rendered).toContain('/accounts?');
    expect(rendered).toContain('segment=tokens');
    expect(rendered).toContain('create=1');
    expect(rendered).toContain('accountId=23');
    expect(rendered).toContain('model=gpt-4.1');
    root?.unmount();
  });
});
