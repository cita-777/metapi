import { describe, expect, it } from 'vitest';
import { normalizeDefaultValue, normalizeSqlType, readMySqlField } from './schemaIntrospection.js';

describe('schema introspection normalization', () => {
  it('normalizes booleans consistently across dialects', () => {
    expect(normalizeSqlType('sqlite', 'INTEGER', 'use_system_proxy')).toBe('boolean');
    expect(normalizeSqlType('mysql', 'tinyint', 'use_system_proxy')).toBe('boolean');
    expect(normalizeSqlType('postgres', 'boolean', 'use_system_proxy')).toBe('boolean');
  });

  it('normalizes common default values', () => {
    expect(normalizeDefaultValue("DEFAULT 'active'")).toBe("'active'");
    expect(normalizeDefaultValue('DEFAULT FALSE')).toBe('false');
    expect(normalizeDefaultValue("datetime('now')")).toBe("datetime('now')");
  });

  it('reads mysql information_schema fields regardless of casing', () => {
    expect(readMySqlField({ COLUMN_TYPE: 'varchar(191)' }, 'column_type')).toBe('varchar(191)');
    expect(readMySqlField({ column_type: 'text' }, 'column_type')).toBe('text');
    expect(readMySqlField({ Table_Name: 'settings' }, 'table_name')).toBe('settings');
  });
});
