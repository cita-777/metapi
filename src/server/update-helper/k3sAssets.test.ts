import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function readRepoFile(relativePath: string) {
  return readFileSync(resolve(process.cwd(), relativePath), 'utf8').replace(/\r\n/g, '\n');
}

describe('k3s deploy assets', () => {
  it('ships a digest-aware example chart for update-center users', () => {
    const requiredFiles = [
      'deploy/k3s/chart/Chart.yaml',
      'deploy/k3s/chart/values.yaml',
      'deploy/k3s/chart/templates/_helpers.tpl',
      'deploy/k3s/chart/templates/deployment.yaml',
      'deploy/k3s/chart/templates/secret.yaml',
      'deploy/k3s/chart/templates/service.yaml',
    ];

    for (const filePath of requiredFiles) {
      expect(existsSync(resolve(process.cwd(), filePath)), filePath).toBe(true);
    }

    const values = readRepoFile('deploy/k3s/chart/values.yaml');
    const deploymentTemplate = readRepoFile('deploy/k3s/chart/templates/deployment.yaml');

    expect(values).toContain('digest:');
    expect(values).toContain('pullPolicy: Always');
    expect(deploymentTemplate).toContain('.Values.image.digest');
    expect(deploymentTemplate).toContain('{{ if .Values.image.digest }}@{{ .Values.image.digest }}');
    expect(deploymentTemplate).toContain('metapi/image-digest: {{ .Values.image.digest | quote }}');
  });

  it('keeps the helper manifest on a pull policy that can pick up fresh latest tags', () => {
    const helperManifest = readRepoFile('deploy/k3s/metapi-deploy-helper.yaml');

    expect(helperManifest).toContain('imagePullPolicy: Always');
  });

  it('documents the local chart path and digest requirement for new k3s users', () => {
    const docs = readRepoFile('docs/k3s-update-center.md');

    expect(docs).toContain('deploy/k3s/chart');
    expect(docs).toContain('/opt/metapi-k3s/chart');
    expect(docs).toContain('image.digest');
    expect(docs).toContain('imagePullPolicy: Always');
    expect(docs).toContain('repository@digest');
  });
});
