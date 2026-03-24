export type LogicalColumnType =
  | 'integer'
  | 'real'
  | 'text'
  | 'boolean'
  | 'datetime'
  | 'json';

export type SchemaMetadataDialect = 'sqlite' | 'mysql' | 'postgres';

function isBooleanLikeColumn(columnName: string, defaultValue: string | null): boolean {
  const normalizedColumn = columnName.toLowerCase();
  const normalizedDefault = (defaultValue || '').trim().toLowerCase();
  if (normalizedDefault === 'true' || normalizedDefault === 'false') {
    return true;
  }
  return normalizedColumn.startsWith('is_')
    || normalizedColumn.startsWith('use_')
    || normalizedColumn.startsWith('has_')
    || normalizedColumn.endsWith('_enabled')
    || normalizedColumn.endsWith('_available')
    || normalizedColumn === 'read'
    || normalizedColumn === 'enabled'
    || normalizedColumn === 'available'
    || normalizedColumn === 'manual_override';
}

function isDateTimeLikeColumn(columnName: string, defaultValue: string | null): boolean {
  const normalizedColumn = columnName.toLowerCase();
  const normalizedDefault = (defaultValue || '').toLowerCase();
  return normalizedColumn.endsWith('_at')
    || normalizedColumn.endsWith('_until')
    || normalizedColumn.endsWith('_refresh')
    || normalizedDefault.includes('datetime(')
    || normalizedDefault.includes('current_timestamp')
    || normalizedDefault.includes('now()');
}

function isJsonLikeColumn(columnName: string): boolean {
  const normalizedColumn = columnName.toLowerCase();
  return normalizedColumn.endsWith('_json')
    || normalizedColumn.includes('snapshot')
    || normalizedColumn.includes('mapping')
    || normalizedColumn.includes('headers')
    || normalizedColumn.includes('config')
    || normalizedColumn.includes('details')
    || normalizedColumn.includes('meta')
    || normalizedColumn.includes('models')
    || normalizedColumn.includes('route_ids')
    || normalizedColumn.includes('multipliers');
}

export function normalizeSchemaMetadataDefaultValue(defaultValue: string | null | undefined): string | null {
  if (defaultValue == null) return null;
  return String(defaultValue).trim() || null;
}

export function normalizeLogicalColumnType(input: {
  declaredType: string;
  columnName: string;
  defaultValue?: string | null;
  dialect?: SchemaMetadataDialect;
}): LogicalColumnType {
  const normalizedType = input.declaredType.trim().toLowerCase();
  const normalizedDefault = normalizeSchemaMetadataDefaultValue(input.defaultValue);
  const dialect = input.dialect;

  if (dialect === 'mysql') {
    if (normalizedType.includes('tinyint(1)') || normalizedType.includes('boolean') || normalizedType.includes('bool')) {
      return 'boolean';
    }
    if (normalizedType.includes('json')) {
      return 'json';
    }
    if (normalizedType.includes('timestamp') || normalizedType.includes('datetime') || normalizedType === 'date') {
      return 'datetime';
    }
    if (normalizedType.includes('int')) {
      return isBooleanLikeColumn(input.columnName, normalizedDefault) ? 'boolean' : 'integer';
    }
    if (normalizedType.includes('double') || normalizedType.includes('float') || normalizedType.includes('real') || normalizedType.includes('decimal')) {
      return 'real';
    }
    if (normalizedType.includes('char') || normalizedType.includes('text')) {
      if (isDateTimeLikeColumn(input.columnName, normalizedDefault)) return 'datetime';
      if (isJsonLikeColumn(input.columnName)) return 'json';
      return 'text';
    }
  }

  if (dialect === 'postgres') {
    if (normalizedType.includes('bool')) {
      return 'boolean';
    }
    if (normalizedType.includes('json')) {
      return 'json';
    }
    if (normalizedType.includes('timestamp') || normalizedType === 'date') {
      return 'datetime';
    }
    if (normalizedType.includes('int')) {
      return isBooleanLikeColumn(input.columnName, normalizedDefault) ? 'boolean' : 'integer';
    }
    if (normalizedType.includes('double') || normalizedType.includes('real') || normalizedType.includes('numeric') || normalizedType.includes('decimal')) {
      return 'real';
    }
    if (normalizedType.includes('char') || normalizedType.includes('text')) {
      if (isDateTimeLikeColumn(input.columnName, normalizedDefault)) return 'datetime';
      if (isJsonLikeColumn(input.columnName)) return 'json';
      return 'text';
    }
  }

  if (normalizedType.includes('int')) {
    return isBooleanLikeColumn(input.columnName, normalizedDefault) ? 'boolean' : 'integer';
  }
  if (normalizedType.includes('real') || normalizedType.includes('double') || normalizedType.includes('float') || normalizedType.includes('decimal')) {
    return 'real';
  }
  if (normalizedType.includes('json')) {
    return 'json';
  }
  if (normalizedType.includes('timestamp') || normalizedType.includes('datetime') || normalizedType === 'date') {
    return 'datetime';
  }
  if (normalizedType.includes('text') || normalizedType.includes('char') || normalizedType.includes('clob')) {
    if (isDateTimeLikeColumn(input.columnName, normalizedDefault)) return 'datetime';
    if (isJsonLikeColumn(input.columnName)) return 'json';
    return 'text';
  }
  if (isDateTimeLikeColumn(input.columnName, normalizedDefault)) return 'datetime';
  return 'text';
}

export const __schemaMetadataTestUtils = {
  isBooleanLikeColumn,
  isDateTimeLikeColumn,
  isJsonLikeColumn,
};
