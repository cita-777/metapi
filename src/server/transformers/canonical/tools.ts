export type CanonicalTool = {
  name: string;
  description?: string;
  strict?: boolean;
  inputSchema?: Record<string, unknown> | null;
};

export type CanonicalToolChoice =
  | 'auto'
  | 'none'
  | 'required'
  | {
    type: 'tool';
    name: string;
  };
