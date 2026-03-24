function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function cloneJsonValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item)) as T;
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]),
    ) as T;
  }
  return value;
}

const RESPONSES_MCP_COMPAT_MARKER = 'responses_mcp_item';
const RESPONSES_MCP_COMPAT_PREFIX = 'metapi_mcp_item__';

type ResponsesMcpCompatEnvelope = {
  metapi_compat: typeof RESPONSES_MCP_COMPAT_MARKER;
  itemType: string;
  item: Record<string, unknown>;
};

export function isResponsesMcpItem(item: unknown): item is Record<string, unknown> {
  return isRecord(item) && asTrimmedString(item.type).toLowerCase().startsWith('mcp_');
}

function createResponsesMcpCompatEnvelope(
  item: Record<string, unknown>,
): ResponsesMcpCompatEnvelope | null {
  const itemType = asTrimmedString(item.type).toLowerCase();
  if (!itemType.startsWith('mcp_')) return null;

  return {
    metapi_compat: RESPONSES_MCP_COMPAT_MARKER,
    itemType,
    item: cloneJsonValue(item),
  };
}

export function toResponsesMcpCompatToolName(itemType: string): string {
  const normalizedType = asTrimmedString(itemType).toLowerCase();
  return `${RESPONSES_MCP_COMPAT_PREFIX}${normalizedType || 'item'}`;
}

export function toResponsesMcpCompatToolCall(
  item: Record<string, unknown>,
  fallbackId: string,
): Record<string, unknown> | null {
  const envelope = createResponsesMcpCompatEnvelope(item);
  if (!envelope) return null;

  const id = (
    asTrimmedString(item.call_id)
    || asTrimmedString(item.id)
    || asTrimmedString(item.approval_request_id)
    || fallbackId
  );

  return {
    id,
    type: 'function',
    function: {
      name: toResponsesMcpCompatToolName(envelope.itemType),
      arguments: JSON.stringify(envelope),
    },
  };
}

function parseCompatEnvelope(rawArguments: unknown): ResponsesMcpCompatEnvelope | null {
  if (typeof rawArguments !== 'string') return null;
  const trimmed = rawArguments.trim();
  if (!trimmed) return null;

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!isRecord(parsed)) return null;
    if (asTrimmedString(parsed.metapi_compat) !== RESPONSES_MCP_COMPAT_MARKER) return null;

    const itemType = asTrimmedString(parsed.itemType).toLowerCase();
    if (!itemType.startsWith('mcp_')) return null;
    if (!isRecord(parsed.item)) return null;

    return {
      metapi_compat: RESPONSES_MCP_COMPAT_MARKER,
      itemType,
      item: cloneJsonValue(parsed.item),
    };
  } catch {
    return null;
  }
}

export function decodeResponsesMcpCompatToolCall(
  toolName: unknown,
  rawArguments: unknown,
): Record<string, unknown> | null {
  const normalizedName = asTrimmedString(toolName).toLowerCase();
  if (!normalizedName.startsWith(RESPONSES_MCP_COMPAT_PREFIX)) return null;

  const envelope = parseCompatEnvelope(rawArguments);
  if (!envelope) return null;
  return envelope.item;
}
