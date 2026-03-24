import { cpSync, existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function resolveRepoRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '../..');
}

function shouldCopySharedArtifact(sourcePath: string): boolean {
  if (statSync(sourcePath).isDirectory()) return true;
  const filename = basename(sourcePath);
  return filename.endsWith('.js') || filename.endsWith('.d.ts');
}

export function copyRuntimeDbGeneratedAssets(repoRoot: string = resolveRepoRoot()): void {
  const sourceDir = resolve(repoRoot, 'src/server/db/generated');
  const targetDir = resolve(repoRoot, 'dist/server/db/generated');
  const sharedSourceDir = resolve(repoRoot, 'src/shared');
  const sharedTargetDir = resolve(repoRoot, 'dist/shared');

  if (!existsSync(sourceDir)) {
    throw new Error(`Runtime DB generated assets directory does not exist: ${sourceDir}`);
  }

  mkdirSync(dirname(targetDir), { recursive: true });
  cpSync(sourceDir, targetDir, { recursive: true, force: true });

  if (existsSync(sharedSourceDir)) {
    rmSync(sharedTargetDir, { recursive: true, force: true });
    mkdirSync(dirname(sharedTargetDir), { recursive: true });
    cpSync(sharedSourceDir, sharedTargetDir, {
      recursive: true,
      force: true,
      filter: (sourcePath) => shouldCopySharedArtifact(sourcePath),
    });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  copyRuntimeDbGeneratedAssets();
}
