import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('account verification diagnostics architecture boundary', () => {
  it('keeps response probing and classification in the neutral service owner', () => {
    const routeSource = readSource('./accounts.ts');
    const serviceSource = readSource('../../services/accountVerificationDiagnostics.ts');

    expect(routeSource).toContain('diagnoseAccountVerificationFailure');
    expect(routeSource).toContain('requireSiteApiBaseUrl(site)');
    expect(routeSource).toContain('baseUrl: diagnosticBaseUrl');
    expect(routeSource).toContain('requestInit: (headers, signal) => withSiteRecordProxyRequestInit(site');
    expect(routeSource).not.toContain('const detectVerifyFailureReason');
    expect(routeSource).not.toMatch(/from\s+["']undici["']/);
    expect(routeSource).not.toContain('var\\s+arg1\\s*=');
    expect(routeSource).not.toContain('missing new-api-user');
    expect(routeSource).not.toContain('new-api-user required');

    expect(serviceSource).not.toMatch(/from\s+["'][^"']*routes\//);
    expect(serviceSource).not.toMatch(/from\s+["'][^"']*db\//);
    expect(serviceSource).not.toContain("from 'fastify'");
    expect(serviceSource).toContain('parseAccountVerificationFailureReason');
    expect(serviceSource).toContain('buildAccountVerificationHeaderVariants');
  });
});
