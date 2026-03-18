import type { CliProfileDefinition } from './types.js';

export const genericCliProfile: CliProfileDefinition = {
  id: 'generic',
  capabilities: {
    supportsResponsesCompact: false,
    supportsResponsesWebsocketIncremental: false,
    preservesContinuation: false,
    supportsCountTokens: false,
    echoesTurnState: false,
  },
  detect() {
    return {
      id: 'generic',
    };
  },
};
