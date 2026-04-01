import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SERVER_ROOT = fileURLToPath(new URL('../', import.meta.url));
const FORBIDDEN_PATTERN = '.returning(';
const INSERT_ID_PATTERN = 'lastInsertRowid';

function collectProductionServerFiles(rootDir: string): string[] {
  const entries = readdirSync(rootDir).sort();
  const files: string[] = [];

  for (const entry of entries) {
    const absolutePath = join(rootDir, entry);
    const stats = statSync(absolutePath);
    if (stats.isDirectory()) {
      files.push(...collectProductionServerFiles(absolutePath));
      continue;
    }
    if (!entry.endsWith('.ts')) continue;
    if (entry.endsWith('.test.ts')) continue;
    files.push(absolutePath);
  }

  return files;
}

describe('server database dialect architecture boundaries', () => {
  it('keeps production server code free of drizzle builder returning calls', () => {
    const rootDir = SERVER_ROOT;
    const offenders = collectProductionServerFiles(rootDir)
      .filter((filePath) => readFileSync(filePath, 'utf8').includes(FORBIDDEN_PATTERN))
      .map((filePath) => relative(rootDir, filePath));

    expect(offenders).toEqual([]);
  });

  it('keeps lastInsertRowid handling inside the db layer', () => {
    const rootDir = SERVER_ROOT;
    const offenders = collectProductionServerFiles(rootDir)
      .filter((filePath) => !relative(rootDir, filePath).split(sep).join('/').startsWith('db/'))
      .filter((filePath) => readFileSync(filePath, 'utf8').includes(INSERT_ID_PATTERN))
      .map((filePath) => relative(rootDir, filePath));

    expect(offenders).toEqual([]);
  });
});
