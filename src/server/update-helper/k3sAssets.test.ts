import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function readRepoFile(relativePath: string) {
  return readFileSync(resolve(process.cwd(), relativePath), 'utf8').replace(/\r\n/g, '\n');
}

function normalizeWhitespace(value: string) {
  return value.replace(/\s+/g, ' ').trim();
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
    const serviceTemplate = readRepoFile('deploy/k3s/chart/templates/service.yaml');
    const helpersTemplate = readRepoFile('deploy/k3s/chart/templates/_helpers.tpl');
    const normalizedDeploymentTemplate = normalizeWhitespace(deploymentTemplate);
    const normalizedServiceTemplate = normalizeWhitespace(serviceTemplate);

    expect(values).toContain('digest:');
    expect(values).toContain('pullPolicy: Always');
    expect(deploymentTemplate).toMatch(/\.Values\.image\.digest/);
    expect(normalizedDeploymentTemplate).toContain('{{ if .Values.image.digest }}@{{ .Values.image.digest }}{{ else }}:{{ .Values.image.tag }}{{ end }}');
    expect(deploymentTemplate).toMatch(/metapi\/image-digest:\s*\{\{\s*\.Values\.image\.digest\s*\|\s*quote\s*\}\}/);
    expect(deploymentTemplate).toMatch(/checksum\/env-secret:/);
    expect(deploymentTemplate).toMatch(/replicaCount at 1 or switch persistence\.hostPath to shared storage before scaling/);
    expect(normalizedServiceTemplate).toContain('{{- if and (or (eq .Values.service.type "NodePort") (eq .Values.service.type "LoadBalancer")) .Values.service.nodePort }}');
    expect(helpersTemplate).toContain('define "metapi.envSecretName"');
    expect(helpersTemplate).toContain('printf "%s-env"');
    expect(deploymentTemplate).toContain('include "metapi.envSecretName"');
    expect(readRepoFile('deploy/k3s/chart/templates/secret.yaml')).toContain('include "metapi.envSecretName"');
  });

  it('keeps the helper manifest on a pull policy that can pick up fresh latest tags', () => {
    const helperManifest = readRepoFile('deploy/k3s/metapi-deploy-helper.yaml');

    expect(helperManifest).toContain('imagePullPolicy: Always');
    expect(helperManifest).toContain('mountPath: /opt/metapi-k3s/chart');
    expect(helperManifest).toContain('readOnly: true');
    expect(helperManifest).toContain('path: /opt/metapi-k3s/chart');
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
