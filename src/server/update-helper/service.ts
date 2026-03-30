import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import type { UpdateCenterVersionSource } from '../services/updateCenterVersionService.js';

type RunCommandInput = {
  command: string;
  args: string[];
  onLine?: (line: string) => void;
};

type RunCommandResult = {
  stdout: string;
};

type RunCommand = (input: RunCommandInput) => Promise<RunCommandResult>;

export type UpdateHelperDeployInput = {
  namespace: string;
  releaseName: string;
  chartRef: string;
  imageRepository: string;
  targetSource: UpdateCenterVersionSource;
  targetTag: string;
  targetDigest?: string | null;
};

export type UpdateHelperRollbackInput = {
  namespace: string;
  releaseName: string;
  targetRevision: string;
};

export type UpdateHelperStatusInput = {
  namespace: string;
  releaseName: string;
};

export type UpdateHelperDeploySummary = {
  success: boolean;
  targetSource: UpdateCenterVersionSource;
  targetTag: string;
  targetDigest: string | null;
  previousRevision: string | null;
  finalRevision: string | null;
  rolledBack: boolean;
  logLines: string[];
};

export type UpdateHelperRollbackSummary = {
  success: boolean;
  targetRevision: string;
  finalRevision: string | null;
  logLines: string[];
};

export type UpdateHelperHistoryEntry = {
  revision: string;
  updatedAt: string | null;
  status: string | null;
  description: string | null;
  imageRepository: string | null;
  imageTag: string | null;
  imageDigest: string | null;
};

export type UpdateHelperStatus = {
  ok: boolean;
  releaseName: string;
  namespace: string;
  revision: string | null;
  imageRepository: string | null;
  imageTag: string | null;
  imageDigest: string | null;
  healthy: boolean;
  history: UpdateHelperHistoryEntry[];
};

type ParsedReleaseValues = {
  imageRepository: string | null;
  imageTag: string | null;
  imageDigest: string | null;
};

async function runCommand(input: RunCommandInput): Promise<RunCommandResult> {
  return await new Promise<RunCommandResult>((resolve, reject) => {
    const child = spawn(input.command, input.args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    const handleLine = (line: string) => {
      const normalized = line.trim();
      if (!normalized) return;
      input.onLine?.(normalized);
    };

    if (child.stdout) {
      const stdoutReader = createInterface({ input: child.stdout });
      stdoutReader.on('line', (line) => {
        stdout += `${line}\n`;
        handleLine(line);
      });
    }

    if (child.stderr) {
      const stderrReader = createInterface({ input: child.stderr });
      stderrReader.on('line', (line) => {
        stderr += `${line}\n`;
        handleLine(line);
      });
    }

    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0) {
        resolve({ stdout: stdout.trim() });
        return;
      }
      reject(new Error(stderr.trim() || stdout.trim() || `${input.command} exited with code ${code}`));
    });
  });
}

function parseLatestRevision(stdout: string): string | null {
  try {
    const rows = JSON.parse(stdout) as Array<{ revision?: string | number }>;
    const revisions = rows
      .map((row) => String(row?.revision || '').trim())
      .filter(Boolean)
      .map((value) => Number.parseInt(value, 10))
      .filter(Number.isFinite);
    if (revisions.length <= 0) return null;
    return String(Math.max(...revisions));
  } catch {
    return null;
  }
}

function parseStatusRevision(stdout: string): string | null {
  try {
    const payload = JSON.parse(stdout) as { version?: string | number };
    if (payload?.version === undefined || payload?.version === null) return null;
    return String(payload.version);
  } catch {
    return null;
  }
}

function parseReleaseValues(stdout: string): ParsedReleaseValues {
  try {
    const payload = JSON.parse(stdout || '{}') as {
      image?: {
        repository?: string;
        tag?: string;
        digest?: string;
      };
    };
    return {
      imageRepository: payload.image?.repository || null,
      imageTag: payload.image?.tag || null,
      imageDigest: payload.image?.digest || null,
    };
  } catch {
    return {
      imageRepository: null,
      imageTag: null,
      imageDigest: null,
    };
  }
}

function parseRuntimeImageDigest(stdout: string): string | null {
  try {
    const payload = JSON.parse(stdout || '{}') as {
      items?: Array<{
        status?: {
          containerStatuses?: Array<{
            imageID?: string | null;
            image?: string | null;
          }>;
        };
      }>;
    };

    for (const item of payload.items || []) {
      for (const status of item.status?.containerStatuses || []) {
        const candidate = `${status.imageID || ''} ${status.image || ''}`;
        const match = candidate.match(/(sha256:[a-f0-9]{64})/i);
        if (match?.[1]) {
          return match[1].toLowerCase();
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

function parseHistoryRows(stdout: string): Array<{
  revision: string;
  updatedAt: string | null;
  status: string | null;
  description: string | null;
}> {
  try {
    const rows = JSON.parse(stdout || '[]') as Array<{
      revision?: string | number;
      updated?: string | null;
      status?: string | null;
      description?: string | null;
    }>;
    return rows
      .map((row) => ({
        revision: String(row?.revision || '').trim(),
        updatedAt: String(row?.updated || '').trim() || null,
        status: String(row?.status || '').trim() || null,
        description: String(row?.description || '').trim() || null,
      }))
      .filter((row) => row.revision);
  } catch {
    return [];
  }
}

function buildRolloutStatusArgs(input: { namespace: string; releaseName: string }): string[] {
  return [
    'rollout',
    'status',
    'deployment',
    '-n',
    input.namespace,
    '-l',
    `app.kubernetes.io/instance=${input.releaseName}`,
    '--timeout=300s',
  ];
}

function buildHelmUpgradeArgs(input: UpdateHelperDeployInput): string[] {
  return [
    'upgrade',
    input.releaseName,
    input.chartRef,
    '--namespace',
    input.namespace,
    '--reuse-values',
    '--set',
    `image.repository=${input.imageRepository}`,
    '--set',
    `image.tag=${input.targetTag}`,
    '--set-string',
    `image.digest=${input.targetDigest || ''}`,
  ];
}

export async function executeUpdateHelperDeploy(
  input: UpdateHelperDeployInput,
  deps: {
    runCommand?: RunCommand;
  } = {},
  onLog?: (line: string) => void,
): Promise<UpdateHelperDeploySummary> {
  const commandRunner = deps.runCommand || runCommand;
  const logLines: string[] = [];
  const captureLine = (line: string) => {
    logLines.push(line);
    onLog?.(line);
  };

  const history = await commandRunner({
    command: 'helm',
    args: ['history', input.releaseName, '-n', input.namespace, '-o', 'json'],
  });
  const previousRevision = parseLatestRevision(history.stdout);

  await commandRunner({
    command: 'helm',
    args: buildHelmUpgradeArgs(input),
    onLine: captureLine,
  });

  try {
    await commandRunner({
      command: 'kubectl',
      args: buildRolloutStatusArgs(input),
      onLine: captureLine,
    });
  } catch (error) {
    if (previousRevision) {
      await commandRunner({
        command: 'helm',
        args: ['rollback', input.releaseName, previousRevision, '-n', input.namespace],
        onLine: captureLine,
      });
    }
    throw error;
  }

  const status = await commandRunner({
    command: 'helm',
    args: ['status', input.releaseName, '-n', input.namespace, '-o', 'json'],
  });

  return {
    success: true,
    targetSource: input.targetSource,
    targetTag: input.targetTag,
    targetDigest: input.targetDigest || null,
    previousRevision,
    finalRevision: parseStatusRevision(status.stdout),
    rolledBack: false,
    logLines,
  };
}

export async function executeUpdateHelperRollback(
  input: UpdateHelperRollbackInput,
  deps: {
    runCommand?: RunCommand;
  } = {},
  onLog?: (line: string) => void,
): Promise<UpdateHelperRollbackSummary> {
  const commandRunner = deps.runCommand || runCommand;
  const logLines: string[] = [];
  const captureLine = (line: string) => {
    logLines.push(line);
    onLog?.(line);
  };

  await commandRunner({
    command: 'helm',
    args: ['rollback', input.releaseName, input.targetRevision, '-n', input.namespace],
    onLine: captureLine,
  });

  await commandRunner({
    command: 'kubectl',
    args: buildRolloutStatusArgs(input),
    onLine: captureLine,
  });

  const status = await commandRunner({
    command: 'helm',
    args: ['status', input.releaseName, '-n', input.namespace, '-o', 'json'],
  });

  return {
    success: true,
    targetRevision: input.targetRevision,
    finalRevision: parseStatusRevision(status.stdout),
    logLines,
  };
}

export async function getUpdateHelperStatus(
  input: UpdateHelperStatusInput,
  deps: {
    runCommand?: RunCommand;
  } = {},
): Promise<UpdateHelperStatus> {
  const commandRunner = deps.runCommand || runCommand;
  const [status, values, history, pods] = await Promise.all([
    commandRunner({
      command: 'helm',
      args: ['status', input.releaseName, '-n', input.namespace, '-o', 'json'],
    }),
    commandRunner({
      command: 'helm',
      args: ['get', 'values', input.releaseName, '-n', input.namespace, '--all', '-o', 'json'],
    }),
    commandRunner({
      command: 'helm',
      args: ['history', input.releaseName, '-n', input.namespace, '-o', 'json'],
    }),
    commandRunner({
      command: 'kubectl',
      args: ['get', 'pods', '-n', input.namespace, '-l', `app.kubernetes.io/instance=${input.releaseName}`, '-o', 'json'],
    }),
  ]);

  const statusPayload = JSON.parse(status.stdout || '{}') as {
    version?: string | number;
    info?: {
      status?: string;
    };
  };
  const currentValues = parseReleaseValues(values.stdout);
  const runtimeDigest = parseRuntimeImageDigest(pods.stdout);
  const historyRows = parseHistoryRows(history.stdout).slice(0, 5);

  const historyEntries: UpdateHelperHistoryEntry[] = [];
  for (const row of historyRows) {
    let releaseValues: ParsedReleaseValues = {
      imageRepository: null,
      imageTag: null,
      imageDigest: null,
    };
    try {
      const result = await commandRunner({
        command: 'helm',
        args: ['get', 'values', input.releaseName, '-n', input.namespace, '--revision', row.revision, '--all', '-o', 'json'],
      });
      releaseValues = parseReleaseValues(result.stdout);
    } catch {
      // Best effort: history should still render even if a revision payload cannot be read.
    }

    historyEntries.push({
      revision: row.revision,
      updatedAt: row.updatedAt,
      status: row.status,
      description: row.description,
      imageRepository: releaseValues.imageRepository,
      imageTag: releaseValues.imageTag,
      imageDigest: releaseValues.imageDigest,
    });
  }

  return {
    ok: true,
    releaseName: input.releaseName,
    namespace: input.namespace,
    revision: statusPayload.version === undefined || statusPayload.version === null ? null : String(statusPayload.version),
    imageRepository: currentValues.imageRepository,
    imageTag: currentValues.imageTag,
    imageDigest: runtimeDigest || currentValues.imageDigest,
    healthy: String(statusPayload.info?.status || '').toLowerCase() === 'deployed',
    history: historyEntries,
  };
}
