function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function sanitizeCompactResponsesRequestBody(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const next = { ...body };
  delete next.stream;
  delete next.stream_options;
  return next;
}

export function shouldFallbackCompactResponsesToResponses(input: {
  status?: number;
  rawErrText?: string;
}): boolean {
  const status = Number.isFinite(Number(input.status)) ? Number(input.status) : 0;
  const compact = asTrimmedString(input.rawErrText).toLowerCase();
  const hasCompactHint = (
    compact.includes('/responses/compact')
    || compact.includes('responses/compact')
    || compact.includes('compact endpoint')
    || /(^|[^a-z])compact([^a-z]|$)/.test(compact)
  );

  if (status === 404 || status === 405 || status === 501) return true;

  return (
    compact.includes("unknown parameter: 'stream'")
    || compact.includes('invalid url')
    || (
      hasCompactHint
      && (
        compact.includes('not supported')
        || compact.includes('unsupported')
      )
    )
  );
}
