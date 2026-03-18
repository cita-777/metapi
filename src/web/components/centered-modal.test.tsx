import { describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import CenteredModal from './CenteredModal.js';

describe('CenteredModal component', () => {
  it('does not close on backdrop click by default and exposes an explicit close button', async () => {
    const onClose = vi.fn();
    let root: ReturnType<typeof create> | null = null;

    try {
      await act(async () => {
        root = create(
          <CenteredModal open onClose={onClose} title="测试弹框">
            <div>content</div>
          </CenteredModal>,
        );
      });

      const closeButton = root.root.find((node) => (
        node.type === 'button'
        && node.props['aria-label'] === '关闭弹框'
      ));

      const backdrop = root.root.find((node) => (
        typeof node.props.className === 'string'
        && node.props.className.includes('modal-backdrop')
      ));

      expect(backdrop.props.onClick).toBeUndefined();
      expect(onClose).not.toHaveBeenCalled();

      await act(async () => {
        closeButton.props.onClick();
      });

      expect(onClose).toHaveBeenCalledTimes(1);
    } finally {
      root?.unmount();
    }
  });

  it('uses the shared centered modal shell pattern', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/components/CenteredModal.tsx'), 'utf8');

    expect(source).toContain('modal-backdrop');
    expect(source).toContain('modal-content');
    expect(source).toContain('useAnimatedVisibility');
    expect(source).toContain('createPortal');
  });
});
