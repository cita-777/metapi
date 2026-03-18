import { antigravityExecutor } from '../../proxy-core/executors/antigravityExecutor.js';
import { claudeExecutor } from '../../proxy-core/executors/claudeExecutor.js';
import { codexExecutor } from '../../proxy-core/executors/codexExecutor.js';
import { geminiCliExecutor } from '../../proxy-core/executors/geminiCliExecutor.js';
import type { RuntimeDispatchInput } from '../../proxy-core/executors/types.js';

export async function dispatchRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<Response> {
  const executor = input.request.runtime?.executor || 'default';
  if (executor === 'codex') {
    return codexExecutor.dispatch(input) as Promise<Response>;
  }
  if (executor === 'claude') {
    return claudeExecutor.dispatch(input) as Promise<Response>;
  }
  if (executor === 'gemini-cli') {
    return geminiCliExecutor.dispatch(input) as Promise<Response>;
  }
  if (executor === 'antigravity') {
    return antigravityExecutor.dispatch(input) as Promise<Response>;
  }
  return codexExecutor.dispatch(input) as Promise<Response>;
}
