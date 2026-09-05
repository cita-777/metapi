import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('docker and release workflows', () => {
  it('uses Node 25 and only publishes amd64 and arm64 images', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');
    const ciWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const releaseWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');
    const ghcrWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/publish-ghcr.yml'), 'utf8');

    expect(dockerfile).toContain('FROM node:25-bookworm-slim AS builder');
    expect(dockerfile).toContain('FROM node:25-bookworm-slim');
    for (const workflow of [ciWorkflow, releaseWorkflow, ghcrWorkflow]) {
      expect(workflow).toContain('arch: amd64');
      expect(workflow).toContain('arch: arm64');
      expect(workflow).not.toContain('armv7');
      expect(workflow).not.toContain('linux/arm/v7');
    }
  });

  it('keeps the runtime volume and stable runner in the Compose image', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');
    const compose = readFileSync(resolve(process.cwd(), 'docker/docker-compose.yml'), 'utf8');
    expect(dockerfile).toContain('docker-runner.mjs');
    expect(dockerfile).toContain('VOLUME ["/app/data", "/app/runtime"]');
    expect(dockerfile).toContain('TARGETARCH="${TARGETARCH}" node -e');
    expect(dockerfile).toContain('npm rebuild better-sqlite3 --no-audit --no-fund');
    expect(dockerfile).toContain("find node_modules -type f -name 'test_extension.node' -delete");
    expect(dockerfile).toContain('find /tmp/metapi-bootstrap -type l -delete');
    expect(dockerfile).not.toContain('COPY --from=builder /app/node_modules ./node_modules');
    expect(dockerfile).not.toContain('COPY --from=builder /app/package.json ./package.json');
    expect(dockerfile).not.toMatch(/helm|kubectl|deploy-helper/i);
    expect(compose).toContain('./runtime:/app/runtime');
    expect(compose).toContain('UPDATE_CENTER_RUNTIME_PERSISTENT: "true"');
  });

  it('smoke-tests each native server bundle before publishing it', () => {
    const releaseWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');
    expect(releaseWorkflow).toContain('Smoke-test server bundle and stable runner');
    expect(releaseWorkflow).toContain('better-sqlite3');
    expect(releaseWorkflow).toContain('docker-runner.mjs');
    expect(releaseWorkflow).toContain('state.schemaVersion !== 1');
    expect(releaseWorkflow).toContain('server-assets/checksums.txt');
  });

  it('does not install cluster tooling in the server image', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');
    expect(dockerfile).not.toMatch(/KUBECTL_VERSION|HELM_VERSION|dl\.k8s\.io|get\.helm\.sh/i);
    expect(dockerfile).toContain('npm prune --omit=dev');
  });

  it('derives image names from the configured Docker Hub secret', () => {
    const ciWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const releaseWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');
    expect(ciWorkflow).toContain('DOCKERHUB_IMAGE: ${{ secrets.DOCKERHUB_USERNAME }}/metapi');
    expect(releaseWorkflow).toContain('DOCKERHUB_IMAGE: ${{ secrets.DOCKERHUB_USERNAME }}/metapi');
  });
});
