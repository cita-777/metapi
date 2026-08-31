import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('proxy-core shared helper boundaries', () => {
  it('keeps policy and multipart owners out of routes/proxy', () => {
    const coreSources = [
      readSource('./chatSurface.ts'),
      readSource('./filesSurface.ts'),
      readSource('./geminiSurface.ts'),
      readSource('./openAiResponsesSurface.ts'),
      readSource('./sharedSurface.ts'),
    ];

    for (const source of coreSources) {
      expect(source).not.toMatch(/from\s+["'][^"']*routes\/proxy\//);
    }

    expect(readSource('../../services/downstreamPolicyService.ts')).toContain(
      'getDownstreamRoutingPolicy',
    );
    expect(readSource('../../services/multipart.ts')).toContain(
      'parseMultipartFormData',
    );
    expect(readSource('../../routes/proxy/downstreamPolicy.ts')).toContain(
      "../../services/downstreamPolicyService.js",
    );
    expect(readSource('../../routes/proxy/multipart.ts')).toContain(
      "../../services/multipart.js",
    );
  });
});
