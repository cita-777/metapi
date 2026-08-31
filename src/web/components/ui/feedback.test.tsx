import { describe, expect, it } from 'vitest';
import { create } from 'react-test-renderer';
import { EmptyState, ErrorState, LoadingState } from './feedback.js';

describe('feedback primitives', () => {
  it('exposes translated content through the existing semantic state classes', () => {
    const root = create(
      <>
        <LoadingState label="加载账号" size="sm" />
        <EmptyState title="暂无账号" description="请先添加一个站点" />
        <ErrorState title="加载失败" description="请重试" />
      </>,
    );
    const statusNodes = root.root.findAll((node) => node.props?.role === 'status');
    expect(statusNodes).toHaveLength(2);
    expect(statusNodes[0].props['aria-live']).toBe('polite');
    expect(statusNodes[1].props.className).toContain('empty-state');
    const error = root.root.find((node) => node.props?.role === 'alert');
    expect(error.props['aria-live']).toBe('assertive');
    expect(error.props.className).toContain('alert-error');
  });
});
