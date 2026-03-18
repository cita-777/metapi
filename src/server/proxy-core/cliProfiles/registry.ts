import { claudeCodeCliProfile } from './claudeCodeProfile.js';
import { codexCliProfile } from './codexProfile.js';
import { geminiCliProfile } from './geminiCliProfile.js';
import { genericCliProfile } from './genericProfile.js';
import type { CliProfileDefinition, CliProfileId, DetectCliProfileInput, DetectedCliProfile } from './types.js';

const orderedProfiles: CliProfileDefinition[] = [
  claudeCodeCliProfile,
  codexCliProfile,
  geminiCliProfile,
];

export const cliProfileRegistry: Record<CliProfileId, CliProfileDefinition> = {
  generic: genericCliProfile,
  codex: codexCliProfile,
  claude_code: claudeCodeCliProfile,
  gemini_cli: geminiCliProfile,
};

export function getCliProfileDefinition(id: CliProfileId): CliProfileDefinition {
  return cliProfileRegistry[id];
}

export function detectCliProfile(input: DetectCliProfileInput): DetectedCliProfile {
  for (const profile of orderedProfiles) {
    const detected = profile.detect(input);
    if (!detected) continue;
    return {
      ...detected,
      capabilities: profile.capabilities,
    };
  }

  return {
    id: genericCliProfile.id,
    capabilities: genericCliProfile.capabilities,
  };
}
