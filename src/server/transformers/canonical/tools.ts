export type CanonicalTool = {
  name: string;
  description?: string;
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
