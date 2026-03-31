import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('ModelTester forced channel architecture', () => {
  it('wires a fixed-channel selector through route decisions and tester envelopes', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/ModelTester.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain('固定通道');
    expect(source).toContain('api.getRouteDecision(inputs.model)');
    expect(source).toContain('forcedChannelId');
    expect(source).toContain('attachForcedChannelToEnvelope');
  });
});
