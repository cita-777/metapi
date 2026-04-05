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
  it('uses the shared centered modal shell and close button instead of a native dialog skin', async () => {
    const onChoice = vi.fn();
    const onClose = vi.fn();
    const root = create(
      <SiteCreatedModal
        siteName="Demo Site"
        onChoice={onChoice}
        onClose={onClose}
      />,
    );

    expect(root.root.findAllByType('dialog')).toHaveLength(0);

    const backdrop = root.root.find((node) => (
      typeof node.props.className === 'string'
      && node.props.className.includes('modal-backdrop')
    ));
    const footer = root.root.find((node) => (
      typeof node.props.className === 'string'
      && node.props.className.includes('modal-footer')
    ));
    const closeButton = root.root.find((node) => (
      node.type === 'button'
      && node.props['aria-label'] === '关闭弹框'
    ));

    expect(backdrop).toBeTruthy();
    expect(footer).toBeTruthy();

    await act(async () => {
      closeButton.props.onClick();
    });

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
      && node.props['aria-label'] !== '关闭弹框'
      && collectText(node) !== '稍后配置'
    ));

    expect(choiceButtons.map((button) => collectText(button))).toEqual(
      expect.arrayContaining([
        '添加 API Key（推荐）',
        '添加账号（用户名密码登录）',
      ]),
    );
    expect(choiceButtons.every((button) => !String(button.props.className || '').includes('btn-outline'))).toBe(true);

    const sessionButton = choiceButtons.find((button) => collectText(button) === '添加账号（用户名密码登录）');
    await act(async () => {
      sessionButton!.props.onClick();
    });

    expect(onChoice).toHaveBeenCalledWith('session');
  });

  it('uses the supplied session label for OAuth-style session actions', () => {
    const root = create(
      <SiteCreatedModal
        siteName="Codex Site"
        initialSegment="session"
        sessionLabel="添加 OAuth 连接"
        onChoice={() => {}}
        onClose={() => {}}
      />,
    );

    const buttons = root.root.findAll((node) => (
      node.type === 'button'
      && typeof node.props.onClick === 'function'
      && node.props['aria-label'] !== '关闭弹框'
    ));

    expect(buttons.some((button) => collectText(button) === '添加 OAuth 连接')).toBe(true);
  });
});
