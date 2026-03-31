import { describe, expect, it, vi } from 'vitest';
import { act, create } from 'react-test-renderer';
import SiteCreatedModal from './SiteCreatedModal.js';

describe('SiteCreatedModal', () => {
  it('routes native dialog cancel events through onClose cleanup', async () => {
    const onChoice = vi.fn();
    const onClose = vi.fn();
    const root = create(
      <SiteCreatedModal
        siteName="Demo Site"
        onChoice={onChoice}
        onClose={onClose}
      />,
    );

    const dialog = root.root.findByType('dialog');
    expect(typeof dialog.props.onCancel).toBe('function');

    const preventDefault = vi.fn();
    await act(async () => {
      dialog.props.onCancel({ preventDefault });
    });

    expect(preventDefault).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onChoice).not.toHaveBeenCalled();
  });
});
