import { describe, expect, it, vi } from 'vitest';
import { create, type ReactTestInstance } from 'react-test-renderer';
import { Login } from './App.js';
import { SITE_DOCS_URL, SITE_GITHUB_URL } from './docsLink.js';

function collectText(node: ReactTestInstance): string {
  return (node.children || []).map((child) => {
    if (typeof child === 'string') return child;
    return collectText(child);
  }).join('');
}

describe('Login surface', () => {
  it('uses the site root as the documentation URL', () => {
    expect(SITE_DOCS_URL).toBe('https://metapi.cita777.me');
  });

  it('uses the author github profile for the login github shortcut', () => {
    expect(SITE_GITHUB_URL).toBe('https://github.com/cita-777');
  });

  it('renders the landing hero with a transparent brand mark and admin login form', () => {
    const root = create(
      <Login onLogin={vi.fn()} t={(text) => text} />,
    );

    try {
      const pageText = collectText(root.root);
      const heroArt = root.root.find((node) => (
        node.type === 'div'
        && typeof node.props.className === 'string'
        && node.props.className.includes('landing-hero-art')
      ));
      const landingForm = root.root.find((node) => (
        node.type === 'form'
        && typeof node.props.className === 'string'
        && node.props.className.includes('landing-login-form')
      ));
      const transparentLogos = root.root.findAll((node) => (
        node.type === 'img'
        && node.props.src === '/logo-transparent.png'
      ));

      expect(pageText).toContain('METAPI');
      expect(pageText).toContain('中转站的中转站');
      expect(pageText).toContain('聚合 New API、One API、OneHub 等上游站点');
      expect(pageText).toContain('一个 Key，一个入口');
      expect(pageText).toContain('统一代理网关');
      expect(pageText).toContain('智能路由引擎');
      expect(pageText).toContain('自动模型发现');
      expect(pageText).toContain('部署文档');
      expect(heroArt).toBeTruthy();
      expect(landingForm).toBeTruthy();
      expect(transparentLogos.length).toBeGreaterThanOrEqual(2);

      const docsLink = root.root.find((node) => (
        node.type === 'a'
        && node.props.href === SITE_DOCS_URL
      ));
      const tokenInput = root.root.find((node) => (
        node.type === 'input'
        && node.props.placeholder === '输入管理员令牌'
      ));
      const githubLink = root.root.find((node) => (
        node.type === 'a'
        && node.props.href === SITE_GITHUB_URL
      ));

      expect(docsLink.props.target).toBe('_blank');
      expect(githubLink.props['aria-label']).toBe('GitHub');
      expect(githubLink.props.target).toBe('_blank');
      expect(tokenInput.props.type).toBe('password');
    } finally {
      root?.unmount();
    }
  });
});
