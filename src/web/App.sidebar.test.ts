import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('App sidebar config', () => {
  it('uses 连接管理 for /accounts and removes standalone /tokens navigation item', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/App.tsx'), 'utf8');

    expect(source).toContain("{ to: '/accounts', label: '连接管理'");
    expect(source).not.toContain("{ to: '/accounts', label: '账号'");
    expect(source).not.toContain("{ to: '/tokens', label: '令牌管理'");
  });

  it('places downstream key navigation under 控制台 instead of 系统', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/App.tsx'), 'utf8');
    const consoleGroupIndex = source.indexOf("label: '控制台'");
    const downstreamIndex = source.indexOf("{ to: '/downstream-keys', label: '下游密钥'");
    const systemGroupIndex = source.indexOf("label: '系统'");

    expect(consoleGroupIndex).toBeGreaterThanOrEqual(0);
    expect(downstreamIndex).toBeGreaterThan(consoleGroupIndex);
    expect(systemGroupIndex).toBeGreaterThan(downstreamIndex);
  });

  it('adds standalone OAuth 管理 navigation entry', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/App.tsx'), 'utf8');

    expect(source).toContain("{ to: '/oauth', label: 'OAuth 管理'");
    expect(source).toContain("const OAuthManagement = lazy(() => import('./pages/OAuthManagement.js'));");
    expect(source).toContain('<Route path="/oauth" element={<OAuthManagement />} />');
  });
});
