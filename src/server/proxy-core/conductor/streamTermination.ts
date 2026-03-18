export function terminalStreamFailure(input: {
  status?: number;
  rawErrorText?: string;
}) {
  return {
    action: 'terminal' as const,
    ...(input.status !== undefined ? { status: input.status } : {}),
    ...(input.rawErrorText ? { rawErrorText: input.rawErrorText } : {}),
  };
}
