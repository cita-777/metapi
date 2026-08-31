import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatRepoDriftReport, runRepoDriftCheck } from './repo-drift-check.js';

function writeWorkspaceFiles(root: string, files: Record<string, string>): void {
  for (const [relativePath, contents] of Object.entries(files)) {
    const fullPath = join(root, relativePath);
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, contents);
  }
}

describe('repo drift check', () => {
  it('separates new violations from tracked debt', () => {
    const root = mkdtempSync(join(tmpdir(), 'metapi-repo-drift-'));
    writeWorkspaceFiles(root, {
      'src/server/transformers/openai/responses/routeCompatibility.ts': "import type { EndpointAttemptContext } from '../../../routes/proxy/endpointFlow.js';\n",
      'src/server/proxy-core/surfaces/chatSurface.ts': 'const payload = await upstream.text();\n',
      'src/server/proxy-core/surfaces/sharedSurface.ts': "import { dispatchRuntimeRequest } from '../../routes/proxy/runtimeExecutor.js';\n",
      'src/web/pages/Accounts.tsx': "import { TokensPanel } from './Tokens.js';\n",
      'src/web/pages/Tokens.tsx': 'export const TokensPanel = () => null;\n',
    });

    const report = runRepoDriftCheck({ root });

    expect(report.violations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'proxy-surface-body-read',
        file: 'src/server/proxy-core/surfaces/chatSurface.ts',
      }),
      expect.objectContaining({
        ruleId: 'transformers-route-blind',
        file: 'src/server/transformers/openai/responses/routeCompatibility.ts',
      }),
      expect.objectContaining({
        ruleId: 'proxy-core-routes-proxy-import',
        file: 'src/server/proxy-core/surfaces/sharedSurface.ts',
      }),
    ]));
    expect(report.violations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'web-page-to-page-import',
        file: 'src/web/pages/Accounts.tsx',
      }),
    ]));
  });

  it('keeps third-party UI primitives behind the web wrapper boundary', () => {
    const root = mkdtempSync(join(tmpdir(), 'metapi-repo-drift-ui-'));
    writeWorkspaceFiles(root, {
      'src/web/components/ui/dialog.tsx': "import * as DialogPrimitive from '@radix-ui/react-dialog';\nexport const Dialog = DialogPrimitive.Root;\n",
      'src/web/pages/Settings.tsx': "import * as DialogPrimitive from '@radix-ui/react-dialog';\nexport const Settings = () => null;\n",
      'src/web/components/Feature.tsx': "import { Button } from '@chakra-ui/react';\nexport const Feature = () => null;\n",
      'src/web/pages/SideEffect.tsx': "import '@mui/material';\nexport const SideEffect = () => null;\n",
    });

    const report = runRepoDriftCheck({ root });

    expect(report.violations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'web-ui-third-party-import',
        file: 'src/web/pages/Settings.tsx',
      }),
      expect.objectContaining({
        ruleId: 'web-ui-third-party-import',
        file: 'src/web/components/Feature.tsx',
      }),
      expect.objectContaining({
        ruleId: 'web-ui-third-party-import',
        file: 'src/web/pages/SideEffect.tsx',
      }),
    ]));
    expect(report.violations).not.toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'web-ui-third-party-import',
        file: 'src/web/components/ui/dialog.tsx',
      }),
    ]));
  });

  it('rejects page-specific style runtimes and duplicate Tailwind entries', () => {
    const root = mkdtempSync(join(tmpdir(), 'metapi-repo-drift-style-'));
    writeWorkspaceFiles(root, {
      'src/web/pages/LocalStyles.tsx': "import styles from './LocalStyles.module.css';\nexport const LocalStyles = () => null;\n",
      'src/web/pages/LocalStyles.module.css': '.root { color: red; }\n',
      'src/web/pages/extra.css': '@import "tailwindcss";\n',
      'src/web/index.css': '@import "tailwindcss";\n',
    });

    const report = runRepoDriftCheck({ root });

    expect(report.violations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'web-style-runtime-import',
        file: 'src/web/pages/LocalStyles.tsx',
      }),
      expect.objectContaining({
        ruleId: 'web-tailwind-entry',
        file: 'src/web/pages/extra.css',
      }),
    ]));
    expect(report.violations).not.toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: 'web-tailwind-entry',
        file: 'src/web/index.css',
      }),
    ]));
  });

  it('keeps the current repository within the first-wave ratchet', () => {
    const report = runRepoDriftCheck({ root: process.cwd() });
    expect(report.violations).toEqual([]);
    expect(report.trackedDebt).toEqual([]);
  });

  it('can render markdown reports for scheduled cleanup jobs', () => {
    const report = runRepoDriftCheck({ root: process.cwd() });
    const markdown = formatRepoDriftReport(report, 'markdown');

    expect(markdown).toContain('# Repo Drift Report');
    expect(markdown).toContain('## Violations');
    expect(markdown).toContain('## Tracked Debt');
  });
});
