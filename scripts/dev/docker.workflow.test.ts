import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('docker workflows', () => {
  it('publishes armv7 docker images in ci and release workflows', () => {
    const ciWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const releaseWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');

    expect(ciWorkflow).toContain('arch: armv7');
    expect(ciWorkflow).toContain('platform: linux/arm/v7');
    expect(ciWorkflow).toContain('"${tag}-armv7"');

    expect(releaseWorkflow).toContain('arch: armv7');
    expect(releaseWorkflow).toContain('platform: linux/arm/v7');
    expect(releaseWorkflow).toContain('"${tag}-armv7"');
  });

  it('derives Docker Hub image names from the configured username secret', () => {
    const ciWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8');
    const releaseWorkflow = readFileSync(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8');

    expect(ciWorkflow).toContain('DOCKERHUB_IMAGE: ${{ secrets.DOCKERHUB_USERNAME }}/metapi');
    expect(ciWorkflow).not.toContain('images: 1467078763/metapi');

    expect(releaseWorkflow).toContain('DOCKERHUB_IMAGE: ${{ secrets.DOCKERHUB_USERNAME }}/metapi');
    expect(releaseWorkflow).not.toContain('1467078763/metapi');
  });

  it('uses an armv7-capable node base image in the Dockerfile', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');

    expect(dockerfile).toContain('FROM node:22-bookworm-slim AS builder');
    expect(dockerfile).toContain('FROM node:22-bookworm-slim');
  });

  it('avoids buildkit-only frontend syntax so managed docker builders can parse it reliably', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');

    expect(dockerfile).not.toContain('# syntax=docker/dockerfile:');
    expect(dockerfile).not.toContain('RUN --mount=type=cache');
  });

  it('keeps server docker builds isolated from desktop packaging dependencies', () => {
    const dockerfile = readFileSync(resolve(process.cwd(), 'docker/Dockerfile'), 'utf8');

    expect(dockerfile).toContain('npm ci --ignore-scripts --no-audit --no-fund');
    expect(dockerfile).toContain('npm rebuild esbuild sharp better-sqlite3 --no-audit --no-fund');
    expect(dockerfile).not.toContain('npm ci --no-audit --no-fund');
    expect(dockerfile).toContain('RUN npm run build:web && npm run build:server');
    expect(dockerfile).toContain('npm prune --omit=dev --no-audit --no-fund');
  });

  it('validates manual GHCR tags before using them in publish commands', () => {
    const workflow = readFileSync(resolve(process.cwd(), '.github/workflows/publish-ghcr.yml'), 'utf8');

    expect(workflow).toContain('validate_tag:');
    expect(workflow).toContain('INPUT_TAG: ${{ inputs.tag }}');
    expect(workflow).toContain('^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$');
    expect(workflow).toContain('tag: ${{ steps.validate.outputs.tag }}');
    expect(workflow).toContain('type=raw,value=${{ needs.validate_tag.outputs.tag }}');
    expect(workflow).toContain('tag="${GHCR_IMAGE}:${IMAGE_TAG}"');
    expect(workflow).not.toContain('tag="${GHCR_IMAGE}:${{ inputs.tag }}"');
  });
});
