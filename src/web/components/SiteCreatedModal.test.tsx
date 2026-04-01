import { describe, expect, it, vi } from 'vitest';
import { act, create, type ReactTestInstance } from 'react-test-renderer';
import SiteCreatedModal from './SiteCreatedModal.js';

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

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

  it('keeps both next-step actions visible while promoting API key flow for api-key-first presets', async () => {
    const onChoice = vi.fn();
    const onClose = vi.fn();
    const root = create(
      <SiteCreatedModal
        siteName="CodingPlan"
        initializationPresetId="codingplan-openai"
        initialSegment="apikey"
        onChoice={onChoice}
        onClose={onClose}
      />,
    );

    const choiceButtons = root.root.findAll((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && collectText(node) !== '稍后配置'
    ));

    expect(choiceButtons.map((button) => collectText(button))).toEqual([
      '添加 API Key（推荐）',
      '添加账号（用户名密码登录）',
    ]);

    await act(async () => {
      choiceButtons[1]!.props.onClick();
    });

    expect(onChoice).toHaveBeenCalledWith('session');
  });
});
