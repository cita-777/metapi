import { describe, expect, it, vi } from 'vitest';
import { create } from 'react-test-renderer';
import { AsyncButton, Button } from './Button.js';

describe('Button primitives', () => {
  it('keeps the existing btn theme and defaults non-submit actions to button', () => {
    const root = create(<Button variant="ghost">取消</Button>);
    const button = root.root.findByType('button');
    expect(button.props.type).toBe('button');
    expect(button.props.className).toContain('btn btn-ghost');
    expect(button.props.disabled).toBeFalsy();
  });

  it('marks async actions busy, disabled, and visibly loading', () => {
    const onClick = vi.fn();
    const root = create(
      <AsyncButton variant="primary" pending onClick={onClick} loadingLabel="保存中...">
        保存
      </AsyncButton>,
    );
    const button = root.root.findByType('button');
    expect(button.props.disabled).toBe(true);
    expect(button.props['aria-busy']).toBe(true);
    expect(button.findAll((node) => node.props.className === 'spinner spinner-sm')).toHaveLength(1);
    expect(button.children.join('')).toContain('保存中...');
    // The native disabled contract prevents activation; the facade does not
    // swallow the callback when a test invokes it directly.
    expect(button.props.type).toBe('button');
  });
});
