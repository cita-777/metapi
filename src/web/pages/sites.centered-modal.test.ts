import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Sites centered modal adoption', () => {
  it('uses CenteredModal for add/edit site flows instead of inline form panels', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Sites.tsx'), 'utf8');

    expect(source).toContain("import CenteredModal from '../components/CenteredModal.js'");
    expect(source).toContain('<CenteredModal');
    expect(source).not.toContain('editorPresence.shouldRender && activeEditor && (');
  });

  it('uses API request wording for dedicated site endpoint copy', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Sites.tsx'), 'utf8');

    expect(source).toContain('API 请求地址池');
    expect(source).toContain('+ 添加 API 地址');
    expect(source).toContain('准确主站点 URL（面板/登录/签到地址，如 https://nih.cc）');
    expect(source).toContain('API 请求地址（如 https://api.nih.cc）');
    expect(source).toContain('label="API 请求地址"');
    expect(source).toContain('API 地址: {buildSiteApiEndpointSummary(site)}');
    expect(source).not.toContain('站点 URL（面板/登录/签到地址，如 https://console.example.com）');
    expect(source).not.toContain('API 请求地址（如 https://api.example.com）');
    expect(source).not.toContain('AI 请求地址池');
    expect(source).not.toContain('+ 添加 AI 地址');
    expect(source).not.toContain('label="AI 请求地址"');
    expect(source).not.toContain('AI 地址: {buildSiteApiEndpointSummary(site)}');
  });
});
