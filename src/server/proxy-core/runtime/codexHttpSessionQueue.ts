const codexHttpSessionQueues = new Map<string, Promise<void>>();

export async function runCodexHttpSessionTask<T>(
  sessionId: string,
  task: () => Promise<T>,
): Promise<T> {
  const normalizedSessionId = sessionId.trim();
  if (!normalizedSessionId) {
    return task();
  }

  const previous = codexHttpSessionQueues.get(normalizedSessionId) || Promise.resolve();
  const run = previous
    .catch(() => undefined)
    .then(() => task());
  const tail = run.then(() => undefined, () => undefined);
  codexHttpSessionQueues.set(normalizedSessionId, tail);

  try {
    return await run;
  } finally {
    if (codexHttpSessionQueues.get(normalizedSessionId) === tail) {
      codexHttpSessionQueues.delete(normalizedSessionId);
    }
  }
}

export function resetCodexHttpSessionQueue(): void {
  codexHttpSessionQueues.clear();
}
