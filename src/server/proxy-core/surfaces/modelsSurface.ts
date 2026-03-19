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
    }>;
  };
  refreshModelsAndRebuildRoutes(): Promise<unknown>;
  isModelAllowed(modelName: string, downstreamPolicy: unknown): Promise<boolean>;
  now?: () => Date;
};

async function readVisibleModels(input: ModelsSurfaceInput): Promise<string[]> {
  const deduped = Array.from(new Set(await input.tokenRouter.getAvailableModels()))
    .filter((modelName) => !isSearchPseudoModel(modelName))
    .sort();
  const allowed: string[] = [];
  for (const modelName of deduped) {
    if (!await input.isModelAllowed(modelName, input.downstreamPolicy)) {
      continue;
    }
    const decision = await input.tokenRouter.explainSelection(modelName, [], input.downstreamPolicy);
    if (typeof decision.selectedChannelId === 'number') {
      allowed.push(modelName);
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
    const data = models.map((id) => ({
      id,
      type: 'model' as const,
      display_name: id,
      created_at: now.toISOString(),
    }));
    return {
      data,
      first_id: data[0]?.id || null,
      last_id: data[data.length - 1]?.id || null,
      has_more: false,
    };
  }

  return {
    object: 'list' as const,
    data: models.map((id) => ({
      id,
      object: 'model' as const,
      created: Math.floor(now.getTime() / 1000),
      owned_by: 'metapi',
    })),
  };
}
