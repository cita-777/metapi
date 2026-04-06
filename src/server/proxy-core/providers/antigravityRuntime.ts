import type { ProviderAction } from './types.js';

export function shouldUseAntigravityStreamAction(modelName: string): boolean {
  const normalizedModel = modelName.toLowerCase();
  return normalizedModel.includes('claude')
    || normalizedModel.includes('gemini-3-pro')
    || normalizedModel.includes('gemini-3.1-flash-image');
}

export function resolveAntigravityProviderAction(
  action: ProviderAction | undefined,
  stream: boolean,
  modelName: string,
): ProviderAction {
  if (action === 'countTokens') return action;
  if (action === 'streamGenerateContent') return action;
  if (stream || shouldUseAntigravityStreamAction(modelName)) {
    return 'streamGenerateContent';
  }
  return action || 'generateContent';
}
