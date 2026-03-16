import { describe, expect, it } from 'vitest';
import { buildSchemaContractFromSqliteMigrations } from './schemaContract.js';

describe('schema contract generation', () => {
  it('captures the current schema shape from sqlite migrations', () => {
    const contract = buildSchemaContractFromSqliteMigrations();

    expect(contract.tables.sites.columns.status).toMatchObject({
      logicalType: 'text',
      notNull: true,
      primaryKey: false,
    });
    expect(contract.tables.account_tokens.columns.token_group).toBeDefined();
    expect(contract.tables.account_tokens.columns.value_status).toMatchObject({
      logicalType: 'text',
      notNull: true,
      defaultValue: "'ready'",
    });
    expect(contract.tables.site_disabled_models).toBeDefined();
    expect(contract.tables.downstream_api_keys).toBeDefined();
    expect(contract.tables.proxy_files).toBeDefined();
    expect(contract.tables.proxy_video_tasks).toBeDefined();
    expect(contract.tables.route_channels.columns.source_model).toBeDefined();
    expect(contract.tables.route_channels.columns.last_selected_at).toBeDefined();
    expect(contract.tables.route_channels.columns.consecutive_fail_count).toMatchObject({
      logicalType: 'integer',
      notNull: true,
      defaultValue: '0',
    });
    expect(contract.tables.sites.columns.use_system_proxy).toMatchObject({
      logicalType: 'boolean',
      defaultValue: 'false',
    });
    expect(contract.tables.token_routes.columns.routing_strategy).toMatchObject({
      logicalType: 'text',
      defaultValue: "'weighted'",
    });
    expect(contract.indexes).toContainEqual(
      expect.objectContaining({ name: 'sites_status_idx', table: 'sites', unique: false }),
    );
    expect(contract.uniques).toContainEqual(
      expect.objectContaining({
        name: 'site_disabled_models_site_model_unique',
        table: 'site_disabled_models',
        columns: ['site_id', 'model_name'],
      }),
    );
    expect(contract.uniques).toContainEqual(
      expect.objectContaining({
        name: 'model_availability_account_model_unique',
        table: 'model_availability',
        columns: ['account_id', 'model_name'],
      }),
    );
    expect(contract.foreignKeys).toContainEqual(
      expect.objectContaining({
        table: 'site_disabled_models',
        columns: ['site_id'],
        referencedTable: 'sites',
        referencedColumns: ['id'],
      }),
    );
    expect(contract.foreignKeys).toContainEqual(
      expect.objectContaining({
        table: 'route_channels',
        columns: ['token_id'],
        referencedTable: 'account_tokens',
        referencedColumns: ['id'],
      }),
    );
  });
});
