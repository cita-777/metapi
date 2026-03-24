export type CanonicalFunctionTool = {
  name: string;
  description?: string;
  strict?: boolean;
  inputSchema?: Record<string, unknown> | null;
};

export type CanonicalRawTool = {
  type: string;
  raw: Record<string, unknown>;
};

export type CanonicalTool =
  | CanonicalFunctionTool
  | CanonicalRawTool;

export type CanonicalToolChoice =
  | 'auto'
  | 'none'
  | 'required'
  | {
    type: 'tool';
    name: string;
  }
  | {
    type: 'raw';
    value: string | Record<string, unknown>;
  };

export function isCanonicalFunctionTool(tool: CanonicalTool): tool is CanonicalFunctionTool {
  return 'name' in tool;
}

export function isCanonicalNamedToolChoice(
  toolChoice: CanonicalToolChoice | undefined,
): toolChoice is { type: 'tool'; name: string } {
  return !!toolChoice && typeof toolChoice === 'object' && toolChoice.type === 'tool';
}
