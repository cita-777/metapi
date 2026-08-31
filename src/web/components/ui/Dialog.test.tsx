import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { Dialog, Drawer } from './Dialog.js';
import { getBodyScrollLockCount } from './lifecycle.js';

type FakeDocument = {
  body: {
    style: { overflow: string };
    appendChild: () => unknown;
    removeChild: () => unknown;
  };
  activeElement: { focus: ReturnType<typeof vi.fn> };
  addEventListener: ReturnType<typeof vi.fn>;
  removeEventListener: ReturnType<typeof vi.fn>;
};

function installDocument(initialOverflow = 'auto'): FakeDocument {
  const fakeDocument: FakeDocument = {
    body: {
      style: { overflow: initialOverflow },
      appendChild: vi.fn(),
      removeChild: vi.fn(),
    },
    activeElement: { focus: vi.fn() },
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
  vi.stubGlobal('document', fakeDocument);
  return fakeDocument;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('project-owned dialog and drawer wrappers', () => {
  it('preserves modal classes while exposing an accessible dialog contract', async () => {
    const document = installDocument();
    const onClose = vi.fn();
    let root!: WebTestRenderer;

    await act(async () => {
      root = create(
        <Dialog open onClose={onClose} title="设置">
          <div>内容</div>
        </Dialog>,
      );
    });

    const panel = root.root.find((node) => node.props['data-ui-surface'] === 'dialog');
    expect(panel.props.role).toBe('dialog');
    expect(panel.props['aria-modal']).toBe(true);
    expect(panel.props['aria-labelledby']).toEqual(expect.any(String));
    expect(panel.props.className).toContain('modal-content');

    const backdrop = root.root.find((node) => (
      typeof node.props.className === 'string'
      && node.props.className.includes('modal-backdrop')
    ));
    expect(backdrop.props.onClick).toBeUndefined();
    expect(document.body.style.overflow).toBe('hidden');

    await act(async () => {
      root.unmount();
    });
    expect(document.body.style.overflow).toBe('auto');
    expect(getBodyScrollLockCount()).toBe(0);
  });

  it('provides an explicit aria-label when a drawer has no visible title', async () => {
    installDocument();
    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <Drawer open onClose={() => {}} showCloseButton={false} ariaLabel="筛选面板">
          <div>筛选内容</div>
        </Drawer>,
      );
    });
    const panel = root.root.find((node) => node.props['data-ui-surface'] === 'drawer');
    expect(panel.props['aria-labelledby']).toBeUndefined();
    expect(panel.props['aria-label']).toBe('筛选面板');
    root.unmount();
  });

  it('applies drawer content styles through the shared facade', async () => {
    installDocument();
    let root!: WebTestRenderer;
    await act(async () => {
      root = create(
        <Drawer
          open
          onClose={() => {}}
          contentStyle={{ width: 420, maxWidth: '90vw' }}
        >
          <div>内容</div>
        </Drawer>,
      );
    });

    const panel = root.root.find((node) => node.props['data-ui-surface'] === 'drawer');
    expect(panel.props.style).toMatchObject({ width: 420, maxWidth: '90vw' });
    root.unmount();
  });

  it('keeps body locked until every independently mounted surface closes', async () => {
    const document = installDocument('visible');
    let root!: WebTestRenderer;

    await act(async () => {
      root = create(
        <>
          <Dialog open onClose={() => {}} title="一个">
            <div />
          </Dialog>
          <Drawer open onClose={() => {}} title="两个">
            <div />
          </Drawer>
        </>,
      );
    });
    expect(document.body.style.overflow).toBe('hidden');
    expect(getBodyScrollLockCount()).toBe(2);

    await act(async () => {
      root.update(
        <>
          <Dialog open={false} onClose={() => {}} title="一个">
            <div />
          </Dialog>
          <Drawer open onClose={() => {}} title="两个">
            <div />
          </Drawer>
        </>,
      );
    });
    expect(document.body.style.overflow).toBe('hidden');
    expect(getBodyScrollLockCount()).toBe(1);

    await act(async () => {
      root.update(
        <>
          <Dialog open={false} onClose={() => {}} title="一个">
            <div />
          </Dialog>
          <Drawer open={false} onClose={() => {}} title="两个">
            <div />
          </Drawer>
        </>,
      );
    });
    expect(document.body.style.overflow).toBe('visible');
    expect(getBodyScrollLockCount()).toBe(0);
    root.unmount();
  });

  it('restores focus to the opener and only the top overlay handles Escape', async () => {
    vi.useFakeTimers();
    const document = installDocument();
    const opener = { focus: vi.fn() };
    document.activeElement = opener;
    const outerClose = vi.fn();
    const innerClose = vi.fn();
    let root!: WebTestRenderer;

    await act(async () => {
      root = create(
        <>
          <Dialog open closeOnEscape onClose={outerClose} title="外层">
            <div />
          </Dialog>
          <Drawer open closeOnEscape onClose={innerClose} title="内层">
            <div />
          </Drawer>
        </>,
      );
    });

    const keydownHandlers = document.addEventListener.mock.calls
      .map((call) => call[1])
      .filter((handler): handler is (event: KeyboardEvent) => void => typeof handler === 'function');
    expect(keydownHandlers.length).toBeGreaterThan(0);
    keydownHandlers.forEach((handler) => handler({ key: 'Escape' } as KeyboardEvent));
    expect(innerClose).toHaveBeenCalledTimes(1);
    expect(outerClose).not.toHaveBeenCalled();

    await act(async () => {
      root.update(<Dialog open={false} onClose={() => {}} title="外层"><div /></Dialog>);
    });
    vi.runAllTimers();
    expect(opener.focus).toHaveBeenCalled();
    root.unmount();
  });
});
