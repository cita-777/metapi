import {
  buildAccountModelContextLengthScope,
  getModelContextLength,
} from '../../services/modelContextLengthCache.js';

function isSearchPseudoModel(modelName: string): boolean {
  const normalized = (modelName || '').trim().toLowerCase();
  if (!normalized) return false;
  return normalized === '__search' || /^__.+_search$/.test(normalized);
}

type ModelsSurfaceInput = {
  downstreamPolicy: unknown;
  responseFormat: 'openai' | 'claude';
  tokenRouter: {
    getAvailableModels(): Promise<string[]>;
    explainSelection(modelName: string, excludeChannelIds: number[], downstreamPolicy: unknown): Promise<{
      selectedChannelId?: number | null;
      selectedAccountId?: number | null;
    }>;
  };
  refreshModelsAndRebuildRoutes(): Promise<unknown>;
  isModelAllowed(modelName: string, downstreamPolicy: unknown): Promise<boolean>;
  now?: () => Date;
};

function resolveModelContextLength(modelName: string, selectedAccountId?: number | null): number {
  if (typeof selectedAccountId === 'number' && selectedAccountId > 0) {
    return getModelContextLength(
      modelName,
      buildAccountModelContextLengthScope(selectedAccountId),
    );
  }
  return getModelContextLength(modelName);
}

async function readVisibleModels(
  input: ModelsSurfaceInput,
): Promise<Array<{ id: string; selectedAccountId?: number | null }>> {
  const deduped = Array.from(new Set(await input.tokenRouter.getAvailableModels()))
    .filter((modelName) => !isSearchPseudoModel(modelName))
    .sort();
  const allowed: Array<{ id: string; selectedAccountId?: number | null }> = [];
  for (const modelName of deduped) {
    if (!await input.isModelAllowed(modelName, input.downstreamPolicy)) {
      continue;
    }
    const decision = await input.tokenRouter.explainSelection(modelName, [], input.downstreamPolicy);
    if (typeof decision.selectedChannelId === 'number') {
      allowed.push({
        id: modelName,
        selectedAccountId: decision.selectedAccountId,
      });
    }
  }
  return allowed;
}

export async function listModelsSurface(input: ModelsSurfaceInput) {
  let models = await readVisibleModels(input);
  if (models.length === 0) {
    await input.refreshModelsAndRebuildRoutes();
    models = await readVisibleModels(input);
  }

  const now = input.now?.() ?? new Date();
  if (input.responseFormat === 'claude') {
    const data: Array<{
      id: string;
      type: 'model';
      display_name: string;
      created_at: string;
      context_length: number;
    }> = [];
    for (const model of models) {
      data.push({
        id: model.id,
        type: 'model' as const,
        display_name: model.id,
        created_at: now.toISOString(),
        context_length: resolveModelContextLength(model.id, model.selectedAccountId),
      });
    }
    return {
      data,
      first_id: data[0]?.id || null,
      last_id: data[data.length - 1]?.id || null,
      has_more: false,
    };
  }

  return {
    object: 'list' as const,
    data: models.map((model) => ({
      id: model.id,
      object: 'model' as const,
      created: Math.floor(now.getTime() / 1000),
      owned_by: 'metapi',
      context_length: resolveModelContextLength(model.id, model.selectedAccountId),
    })),
  };
}
