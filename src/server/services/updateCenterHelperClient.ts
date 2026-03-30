import { fetch, type RequestInit as UndiciRequestInit } from 'undici';

import type { UpdateCenterConfig } from './updateCenterConfigService.js';
import type { UpdateCenterVersionSource } from './updateCenterVersionService.js';

const UPDATE_CENTER_HELPER_STATUS_TIMEOUT_MS = 5_000;

export type UpdateCenterHelperStatus = {
  ok: boolean;
  releaseName: string | null;
  namespace: string | null;
  revision: string | null;
  imageRepository: string | null;
  imageTag: string | null;
  imageDigest: string | null;
  healthy: boolean;
  history?: Array<{
    revision: string;
    updatedAt: string | null;
    status: string | null;
    description: string | null;
    imageRepository: string | null;
    imageTag: string | null;
    imageDigest: string | null;
  }>;
  error?: string;
};

export type UpdateCenterDeploySummary = {
  success: boolean;
  targetSource: UpdateCenterVersionSource;
  targetTag: string;
  targetDigest: string | null;
  previousRevision: string | null;
  finalRevision: string | null;
  rolledBack: boolean;
  logLines: string[];
};

export type UpdateCenterRollbackSummary = {
  success: boolean;
  targetRevision: string;
  finalRevision: string | null;
  logLines: string[];
};

type HelperDeployLogEvent = {
  message: string;
};

async function fetchHelperJsonWithTimeout(url: string, init: UndiciRequestInit): Promise<unknown> {
  const controller = new AbortController();
  let timeoutHandle: ReturnType<typeof setTimeout> | null = setTimeout(() => {
    controller.abort();
  }, UPDATE_CENTER_HELPER_STATUS_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`helper status failed with HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error: any) {
    if (error?.name === 'AbortError') {
      throw new Error(`deploy helper status timeout (${Math.round(UPDATE_CENTER_HELPER_STATUS_TIMEOUT_MS / 1000)}s)`);
    }
    throw error;
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = null;
    }
  }
}

function buildHelperHeaders(token: string, accept = 'application/json') {
  return {
    authorization: `Bearer ${token}`,
    accept,
  };
}

function encodeSseEvent(event: string, data: unknown) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

type SseChunkHandler = (event: string, data: unknown) => void;

function parseSseBuffer(buffer: string, onChunk: SseChunkHandler) {
  const events = buffer.split('\n\n');
  const remainder = events.pop() || '';

  for (const block of events) {
    const lines = block.split('\n');
    let eventName = 'message';
    const dataLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim() || 'message';
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trim());
      }
    }

    if (dataLines.length <= 0) continue;
    const rawData = dataLines.join('\n');
    try {
      onChunk(eventName, JSON.parse(rawData));
    } catch {
      onChunk(eventName, rawData);
    }
  }

  return remainder;
}

export async function getUpdateCenterHelperStatus(
  config: UpdateCenterConfig,
  helperToken: string,
): Promise<UpdateCenterHelperStatus> {
  const query = new URLSearchParams({
    namespace: config.namespace,
    releaseName: config.releaseName,
  });
  return await fetchHelperJsonWithTimeout(`${config.helperBaseUrl.replace(/\/$/, '')}/status?${query.toString()}`, {
    headers: buildHelperHeaders(helperToken),
  }) as UpdateCenterHelperStatus;
}

export async function streamUpdateCenterDeploy(
  input: {
    config: UpdateCenterConfig;
    helperToken: string;
    source: UpdateCenterVersionSource;
    targetTag: string;
    targetDigest?: string | null;
  },
  onLog?: (message: string) => void,
): Promise<UpdateCenterDeploySummary> {
  const response = await fetch(`${input.config.helperBaseUrl.replace(/\/$/, '')}/deploy`, {
    method: 'POST',
    headers: {
      ...buildHelperHeaders(input.helperToken, 'text/event-stream'),
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      namespace: input.config.namespace,
      releaseName: input.config.releaseName,
      chartRef: input.config.chartRef,
      imageRepository: input.config.imageRepository,
      source: input.source,
      targetTag: input.targetTag,
      targetDigest: input.targetDigest || null,
    }),
  });

  if (!response.ok) {
    throw new Error(`helper deploy failed with HTTP ${response.status}`);
  }

  if (!response.body) {
    throw new Error('helper deploy response did not include a stream body');
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = '';
  let finalResult: UpdateCenterDeploySummary | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    buffer = parseSseBuffer(buffer, (event, data) => {
      if (event === 'log' && data && typeof data === 'object') {
        const message = String((data as HelperDeployLogEvent).message || '').trim();
        if (message) onLog?.(message);
        return;
      }
      if (event === 'result') {
        finalResult = data as UpdateCenterDeploySummary;
      }
    });
  }

  if (buffer.trim()) {
    parseSseBuffer(`${buffer}\n\n`, (event, data) => {
      if (event === 'log' && data && typeof data === 'object') {
        const message = String((data as HelperDeployLogEvent).message || '').trim();
        if (message) onLog?.(message);
        return;
      }
      if (event === 'result') {
        finalResult = data as UpdateCenterDeploySummary;
      }
    });
  }

  if (!finalResult) {
    throw new Error('helper deploy stream ended without a result event');
  }

  return finalResult;
}

export async function streamUpdateCenterRollback(
  input: {
    config: UpdateCenterConfig;
    helperToken: string;
    targetRevision: string;
  },
  onLog?: (message: string) => void,
): Promise<UpdateCenterRollbackSummary> {
  const response = await fetch(`${input.config.helperBaseUrl.replace(/\/$/, '')}/rollback`, {
    method: 'POST',
    headers: {
      ...buildHelperHeaders(input.helperToken, 'text/event-stream'),
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      namespace: input.config.namespace,
      releaseName: input.config.releaseName,
      targetRevision: input.targetRevision,
    }),
  });

  if (!response.ok) {
    throw new Error(`helper rollback failed with HTTP ${response.status}`);
  }

  if (!response.body) {
    throw new Error('helper rollback response did not include a stream body');
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = '';
  let finalResult: UpdateCenterRollbackSummary | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    buffer = parseSseBuffer(buffer, (event, data) => {
      if (event === 'log' && data && typeof data === 'object') {
        const message = String((data as HelperDeployLogEvent).message || '').trim();
        if (message) onLog?.(message);
        return;
      }
      if (event === 'result') {
        finalResult = data as UpdateCenterRollbackSummary;
      }
    });
  }

  if (buffer.trim()) {
    parseSseBuffer(`${buffer}\n\n`, (event, data) => {
      if (event === 'log' && data && typeof data === 'object') {
        const message = String((data as HelperDeployLogEvent).message || '').trim();
        if (message) onLog?.(message);
        return;
      }
      if (event === 'result') {
        finalResult = data as UpdateCenterRollbackSummary;
      }
    });
  }

  if (!finalResult) {
    throw new Error('helper rollback stream ended without a result event');
  }

  return finalResult;
}

export const __updateCenterHelperClientTestUtils = {
  encodeSseEvent,
};
