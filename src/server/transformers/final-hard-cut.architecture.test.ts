import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

function readWorkspaceFile(relativePath: string): string {
  return readFileSync(path.resolve(process.cwd(), relativePath), 'utf8');
}

function listTransformerFiles(directory: string): string[] {
  const entries = readdirSync(directory);
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      files.push(...listTransformerFiles(fullPath));
      continue;
    }
    if (entry.endsWith('.ts') && !entry.endsWith('.test.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('final transformer hard-cut architecture', () => {
  it('keeps shared normalized helpers independent from route chatFormats', () => {
    const sharedNormalized = readWorkspaceFile('src/server/transformers/shared/normalized.ts');

    expect(sharedNormalized).not.toContain("../../routes/proxy/chatFormats.js");
    expect(sharedNormalized).not.toContain("from '../../routes/proxy/chatFormats.js'");
  });

  it('removes normalizeContentText from upstream endpoint compatibility path', () => {
    const upstreamEndpoint = readWorkspaceFile('src/server/routes/proxy/upstreamEndpoint.ts');

    expect(upstreamEndpoint).not.toContain('function normalizeContentText(');
    expect(upstreamEndpoint).not.toContain('normalizeContentText(');
  });

  it('keeps responses protocol shaping out of route-local helpers', () => {
    const responsesRoute = readWorkspaceFile('src/server/routes/proxy/responses.ts');

    expect(responsesRoute).not.toContain('function toResponsesPayload(');
    expect(responsesRoute).not.toContain('function createResponsesStreamState(');
  });

  it('replaces gemini passthrough placeholders with protocol-aware helpers', () => {
    const geminiInbound = readWorkspaceFile('src/server/transformers/gemini/generate-content/inbound.ts');
    const geminiStream = readWorkspaceFile('src/server/transformers/gemini/generate-content/stream.ts');
    const geminiAggregator = readWorkspaceFile('src/server/transformers/gemini/generate-content/aggregator.ts');

    expect(geminiInbound).not.toContain('passthrough');
    expect(geminiStream).not.toContain('passthrough');
    expect(geminiAggregator).not.toContain('parts: unknown[]');
  });

  it('forbids transformer imports from routes, oauth, token router, runtime executor, and fastify', () => {
    const transformerRoot = path.resolve(process.cwd(), 'src/server/transformers');
    const files = listTransformerFiles(transformerRoot);

    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      expect(source).not.toContain("from '../../routes/proxy/");
      expect(source).not.toContain("from '../routes/proxy/");
      expect(source).not.toContain("from '../../services/oauth/");
      expect(source).not.toContain("from '../services/oauth/");
      expect(source).not.toContain("from '../../services/tokenRouter.js'");
      expect(source).not.toContain("from '../services/tokenRouter.js'");
      expect(source).not.toContain("from '../../routes/proxy/runtimeExecutor.js'");
      expect(source).not.toContain("from '../routes/proxy/runtimeExecutor.js'");
      expect(source).not.toContain("from 'fastify'");
    }
  });
});
