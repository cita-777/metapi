import { antigravityExecutor } from '../../proxy-core/executors/antigravityExecutor.js';
import { claudeExecutor } from '../../proxy-core/executors/claudeExecutor.js';
import { codexExecutor } from '../../proxy-core/executors/codexExecutor.js';
import { geminiCliExecutor } from '../../proxy-core/executors/geminiCliExecutor.js';
import type { RuntimeDispatchInput, RuntimeResponse } from '../../proxy-core/executors/types.js';

export async function dispatchRuntimeRequest(
  input: RuntimeDispatchInput,
): Promise<RuntimeResponse> {
  const executor = input.request.runtime?.executor || 'default';
  if (executor === 'codex') {
    return codexExecutor.dispatch(input);
  }
  if (executor === 'claude') {
    return claudeExecutor.dispatch(input);
  }
  if (executor === 'gemini-cli') {
    return geminiCliExecutor.dispatch(input);
  }
  if (executor === 'antigravity') {
    return antigravityExecutor.dispatch(input);
  }
  return codexExecutor.dispatch(input);
}
