import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, extname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

type ReportFormat = 'text' | 'markdown';
type Severity = 'violation' | 'tracked_debt';

type DriftFinding = {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  excerpt: string;
};

type DriftReport = {
  root: string;
  generatedAt: string;
  violations: DriftFinding[];
  trackedDebt: DriftFinding[];
};

type RuleSpec = {
  id: string;
  description: string;
  fileFilter: (file: string) => boolean;
  lineMatch: (line: string, file: string) => boolean;
  message: string | ((file: string, line: string) => string);
  allowlistedFiles?: Set<string>;
};

type RunOptions = {
  root: string;
};

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);

const ROUTES_PROXY_IMPORT_ALLOWLIST = new Set([
  'src/server/proxy-core/surfaces/chatSurface.ts',
  'src/server/proxy-core/surfaces/filesSurface.ts',
  'src/server/proxy-core/surfaces/geminiSurface.ts',
  'src/server/proxy-core/surfaces/openAiResponsesSurface.ts',
  'src/server/proxy-core/surfaces/sharedSurface.ts',
]);

const TOP_LEVEL_PAGE_IMPORT_ALLOWLIST = new Set([
  'src/web/pages/Accounts.tsx',
]);

function normalizeRelativePath(root: string, fullPath: string): string {
  return relative(root, fullPath).replaceAll('\\', '/');
}

function walkFiles(root: string, currentDir = root): string[] {
  const entries = readdirSync(currentDir).sort((left, right) => left.localeCompare(right, 'en'));
  const files: string[] = [];

  for (const entry of entries) {
    if (entry === '.git' || entry === 'node_modules' || entry === 'dist' || entry === 'coverage') {
      continue;
    }

    const fullPath = resolve(currentDir, entry);
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      continue;
    }
    if (stat.isDirectory()) {
      files.push(...walkFiles(root, fullPath));
      continue;
    }

    const extension = extname(entry);
    if (SOURCE_EXTENSIONS.has(extension)) {
      files.push(fullPath);
    }
  }

  return files;
}

function readWorkspaceLines(root: string, file: string): Array<{ lineNumber: number; text: string }> {
  const source = readFileSync(resolve(root, file), 'utf8').replaceAll('\r\n', '\n');
  return source.split('\n').map((text, index) => ({
    lineNumber: index + 1,
    text,
  }));
}

function isNonTestSource(file: string): boolean {
  return !file.endsWith('.test.ts')
    && !file.endsWith('.test.tsx')
    && !file.endsWith('.test.js')
    && !file.endsWith('.test.jsx');
}

function isTopLevelPageFile(file: string): boolean {
  return /^src\/web\/pages\/[^/]+\.(ts|tsx|js|jsx)$/.test(file)
    && isNonTestSource(file);
}

function createRules(): RuleSpec[] {
  return [
    {
      id: 'transformers-route-blind',
      description: 'Transformers must not import route-layer proxy helpers',
      fileFilter: (file) => file.startsWith('src/server/transformers/')
        && isNonTestSource(file),
      lineMatch: (line) => /from\s+['"][^'"]*routes\/proxy\//.test(line),
      message: 'transformer imports route-layer proxy code',
    },
    {
      id: 'proxy-surface-body-read',
      description: 'Proxy-core surfaces should use readRuntimeResponseText() for whole-body reads',
      fileFilter: (file) => file.startsWith('src/server/proxy-core/surfaces/')
        && isNonTestSource(file),
      lineMatch: (line) => /\.text\(/.test(line),
      message: 'proxy-core surface reads a full upstream body via .text()',
    },
    {
      id: 'proxy-core-routes-proxy-import',
      description: 'Proxy-core imports from routes/proxy are tracked debt and should not grow',
      fileFilter: (file) => file.startsWith('src/server/proxy-core/')
        && isNonTestSource(file),
      lineMatch: (line) => /from\s+['"][^'"]*routes\/proxy\//.test(line),
      message: 'proxy-core imports a helper from routes/proxy',
      allowlistedFiles: ROUTES_PROXY_IMPORT_ALLOWLIST,
    },
    {
      id: 'web-page-to-page-import',
      description: 'Top-level route pages should not import other top-level route pages',
      fileFilter: (file) => isTopLevelPageFile(file),
      lineMatch: (line, file) => {
        const match = line.match(/from\s+['"]\.\/([^/'"]+?)(?:\.(?:js|ts|tsx|jsx))?['"]/);
        if (!match) return false;
        const importedPage = match[1];
        const currentPage = file.replace(/^src\/web\/pages\//, '').replace(/\.(ts|tsx|js|jsx)$/, '');
        return importedPage !== currentPage;
      },
      message: (file, line) => {
        const match = line.match(/from\s+['"](\.\/[^'"]+)['"]/);
        const imported = match?.[1] ?? 'another page file';
        return `top-level page imports ${imported}`;
      },
      allowlistedFiles: TOP_LEVEL_PAGE_IMPORT_ALLOWLIST,
    },
  ];
}

export function runRepoDriftCheck(options: Partial<RunOptions> = {}): DriftReport {
  const root = resolve(options.root ?? process.cwd());
  const report: DriftReport = {
    root,
    generatedAt: new Date().toISOString(),
    violations: [],
    trackedDebt: [],
  };

  const files = walkFiles(root).map((file) => normalizeRelativePath(root, file));
  const rules = createRules();

  for (const rule of rules) {
    for (const file of files) {
      if (!rule.fileFilter(file)) continue;

      for (const { lineNumber, text } of readWorkspaceLines(root, file)) {
        if (!rule.lineMatch(text, file)) continue;

        const finding: DriftFinding = {
          ruleId: rule.id,
          severity: rule.allowlistedFiles?.has(file) ? 'tracked_debt' : 'violation',
          file,
          line: lineNumber,
          message: typeof rule.message === 'function' ? rule.message(file, text) : rule.message,
          excerpt: text.trim(),
        };

        if (finding.severity === 'tracked_debt') {
          report.trackedDebt.push(finding);
        } else {
          report.violations.push(finding);
        }
      }
    }
  }

  return report;
}

function formatFindingText(finding: DriftFinding): string {
  return `- [${finding.ruleId}] ${finding.file}:${finding.line} ${finding.message}\n  ${finding.excerpt}`;
}

function formatFindingMarkdownRow(finding: DriftFinding): string {
  const escapedMessage = finding.message.replaceAll('|', '\\|');
  const escapedExcerpt = finding.excerpt.replaceAll('|', '\\|');
  return `| \`${finding.ruleId}\` | \`${finding.file}:${finding.line}\` | ${escapedMessage} | \`${escapedExcerpt}\` |`;
}

export function formatRepoDriftReport(report: DriftReport, format: ReportFormat = 'text'): string {
  if (format === 'markdown') {
    const lines: string[] = [
      '# Repo Drift Report',
      '',
      `- Root: \`${report.root}\``,
      `- Generated at: \`${report.generatedAt}\``,
      `- Violations: **${report.violations.length}**`,
      `- Tracked debt: **${report.trackedDebt.length}**`,
      '',
    ];

    if (report.violations.length > 0) {
      lines.push('## Violations', '', '| Rule | Location | Message | Excerpt |', '| --- | --- | --- | --- |');
      for (const finding of report.violations) {
        lines.push(formatFindingMarkdownRow(finding));
      }
      lines.push('');
    } else {
      lines.push('## Violations', '', 'No new violations found.', '');
    }

    if (report.trackedDebt.length > 0) {
      lines.push('## Tracked Debt', '', '| Rule | Location | Message | Excerpt |', '| --- | --- | --- | --- |');
      for (const finding of report.trackedDebt) {
        lines.push(formatFindingMarkdownRow(finding));
      }
      lines.push('');
    } else {
      lines.push('## Tracked Debt', '', 'No tracked debt entries were observed.', '');
    }

    return lines.join('\n');
  }

  const lines: string[] = [
    `Repo drift report for ${report.root}`,
    `Generated at ${report.generatedAt}`,
    '',
    `Violations: ${report.violations.length}`,
  ];

  if (report.violations.length > 0) {
    lines.push(...report.violations.map(formatFindingText));
  } else {
    lines.push('- none');
  }

  lines.push('', `Tracked debt: ${report.trackedDebt.length}`);
  if (report.trackedDebt.length > 0) {
    lines.push(...report.trackedDebt.map(formatFindingText));
  } else {
    lines.push('- none');
  }

  return lines.join('\n');
}

type CliOptions = {
  format: ReportFormat;
  output?: string;
  reportOnly: boolean;
  root?: string;
};

function parseCliOptions(argv: string[]): CliOptions {
  const options: CliOptions = {
    format: 'text',
    reportOnly: false,
  };

  const readRequiredValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`${flag} requires a value`);
    }
    return value;
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--format') {
      const value = readRequiredValue(arg, index);
      if (value !== 'text' && value !== 'markdown') {
        throw new Error(`--format must be one of: text, markdown`);
      }
      options.format = value;
      index += 1;
      continue;
    }
    if (arg === '--output') {
      options.output = readRequiredValue(arg, index);
      index += 1;
      continue;
    }
    if (arg === '--report-only') {
      options.reportOnly = true;
      continue;
    }
    if (arg === '--root') {
      options.root = readRequiredValue(arg, index);
      index += 1;
    }
  }

  return options;
}

function maybeWriteReport(outputPath: string | undefined, contents: string): void {
  if (!outputPath) return;
  const resolved = resolve(outputPath);
  mkdirSync(dirname(resolved), { recursive: true });
  writeFileSync(resolved, contents);
}

const isMainModule = (() => {
  try {
    return process.argv[1] != null && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMainModule) {
  try {
    const options = parseCliOptions(process.argv.slice(2));
    const report = runRepoDriftCheck({ root: options.root });
    const contents = formatRepoDriftReport(report, options.format);
    maybeWriteReport(options.output, contents);
    console.log(contents);
    process.exit(report.violations.length > 0 && !options.reportOnly ? 1 : 0);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exit(1);
  }
}
