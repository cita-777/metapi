import { existsSync, globSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitepress';
import { withMermaid } from 'vitepress-plugin-mermaid';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const resolveDependencyEntry = (hoistedRelativePath: string, pnpmPattern: string) => {
  const hoistedEntry = resolve(repoRoot, hoistedRelativePath);
  if (existsSync(hoistedEntry)) return hoistedEntry;

  const [pnpmEntry] = globSync(resolve(repoRoot, pnpmPattern));
  return pnpmEntry;
};

const dayjsEsmEntry = resolveDependencyEntry(
  'node_modules/dayjs/esm/index.js',
  'node_modules/.pnpm/dayjs@*/node_modules/dayjs/esm/index.js',
);
const sanitizeUrlSourceEntry = resolveDependencyEntry(
  'node_modules/@braintree/sanitize-url/src/index.ts',
  'node_modules/.pnpm/@braintree+sanitize-url@*/node_modules/@braintree/sanitize-url/src/index.ts',
);

if (!dayjsEsmEntry) {
  throw new Error('Unable to resolve the dayjs ESM entry required by vitepress-plugin-mermaid.');
}

if (!sanitizeUrlSourceEntry) {
  throw new Error('Unable to resolve the sanitize-url source entry required by vitepress-plugin-mermaid.');
}

export default withMermaid(
  defineConfig({
    lang: 'zh-CN',
    title: 'Metapi 文档',
    description: 'Metapi 使用文档、FAQ 与维护协作指南',
    head: [
      ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/favicon.png' }],
      ['link', { rel: 'icon', type: 'image/png', sizes: '64x64', href: '/favicon-64.png' }],
      ['link', { rel: 'shortcut icon', href: '/favicon.ico' }],
    ],
    cleanUrls: true,
    lastUpdated: true,
    ignoreDeadLinks: true,
    vite: {
      resolve: {
        alias: [
          { find: /^dayjs$/, replacement: dayjsEsmEntry },
          { find: /^@braintree\/sanitize-url$/, replacement: sanitizeUrlSourceEntry },
        ],
      },
    },
    themeConfig: {
      siteTitle: 'Metapi Docs',
      logo: '/logos/logo-icon-512.png',
      nav: [
        { text: '首页', link: '/' },
        { text: '快速上手', link: '/getting-started' },
        { text: '上游接入', link: '/upstream-integration' },
        { text: 'OAuth 管理', link: '/oauth' },
        { text: 'FAQ', link: '/faq' },
        { text: '文档维护', link: '/README' },
        { text: '项目主页', link: 'https://github.com/cita-777/metapi' },
      ],
      sidebar: [
        {
          text: '开始',
          items: [
            { text: '文档首页', link: '/' },
            { text: '快速上手', link: '/getting-started' },
            { text: '部署指南', link: '/deployment' },
          ],
        },
        {
          text: '使用与运维',
          items: [
            { text: '上游接入', link: '/upstream-integration' },
            { text: 'OAuth 管理', link: '/oauth' },
            { text: '配置说明', link: '/configuration' },
            { text: 'K3s 更新中心（高级）', link: '/k3s-update-center' },
            { text: '客户端接入', link: '/client-integration' },
            { text: '管理 API', link: '/management-api' },
            { text: '运维手册', link: '/operations' },
            { text: '常见问题 FAQ', link: '/faq' },
          ],
        },
        {
          text: '文档维护',
          items: [
            { text: '文档维护与贡献', link: '/README' },
            { text: '目录规范', link: '/project-structure' },
            { text: 'FAQ/教程贡献规范', link: '/community/faq-tutorial-guidelines' },
          ],
        },
      ],
      socialLinks: [
        { icon: 'github', link: 'https://github.com/cita-777/metapi' },
      ],
      outline: {
        level: [2, 3],
      },
      footer: {
        message: 'MIT Licensed',
        copyright: 'Copyright (c) 2026 Metapi Contributors',
      },
      search: {
        provider: 'local',
      },
    },
  }),
);
