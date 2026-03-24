export type RouteGroupingSchemaDialect = 'sqlite' | 'mysql' | 'postgres';

export interface RouteGroupingSchemaInspector {
  dialect: RouteGroupingSchemaDialect;
  tableExists(table: string): Promise<boolean>;
  columnExists(table: string, column: string): Promise<boolean>;
  execute(sqlText: string): Promise<void>;
}

export type RouteGroupingColumnCompatibilitySpec = {
  table: 'token_routes' | 'route_channels';
  column: string;
  addSql: Record<RouteGroupingSchemaDialect, string>;
};

export type RouteGroupingTableCompatibilitySpec = {
  table: 'route_group_sources';
  createSql: Record<RouteGroupingSchemaDialect, string[]>;
};

export const ROUTE_GROUPING_COLUMN_COMPATIBILITY_SPECS: RouteGroupingColumnCompatibilitySpec[] = [
  {
    table: 'token_routes',
    column: 'display_name',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN display_name text;',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `display_name` TEXT NULL',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "display_name" TEXT',
    },
  },
  {
    table: 'token_routes',
    column: 'display_icon',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN display_icon text;',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `display_icon` TEXT NULL',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "display_icon" TEXT',
    },
  },
  {
    table: 'token_routes',
    column: 'route_mode',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN route_mode text DEFAULT \'pattern\';',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `route_mode` VARCHAR(32) NULL DEFAULT \'pattern\'',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "route_mode" TEXT DEFAULT \'pattern\'',
    },
  },
  {
    table: 'token_routes',
    column: 'decision_snapshot',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN decision_snapshot text;',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `decision_snapshot` TEXT NULL',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "decision_snapshot" TEXT',
    },
  },
  {
    table: 'token_routes',
    column: 'decision_refreshed_at',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN decision_refreshed_at text;',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `decision_refreshed_at` TEXT NULL',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "decision_refreshed_at" TEXT',
    },
  },
  {
    table: 'token_routes',
    column: 'routing_strategy',
    addSql: {
      sqlite: 'ALTER TABLE token_routes ADD COLUMN routing_strategy text DEFAULT \'weighted\';',
      mysql: 'ALTER TABLE `token_routes` ADD COLUMN `routing_strategy` VARCHAR(32) NULL DEFAULT \'weighted\'',
      postgres: 'ALTER TABLE "token_routes" ADD COLUMN "routing_strategy" TEXT DEFAULT \'weighted\'',
    },
  },
  {
    table: 'route_channels',
    column: 'source_model',
    addSql: {
      sqlite: 'ALTER TABLE route_channels ADD COLUMN source_model text;',
      mysql: 'ALTER TABLE `route_channels` ADD COLUMN `source_model` TEXT NULL',
      postgres: 'ALTER TABLE "route_channels" ADD COLUMN "source_model" TEXT',
    },
  },
  {
    table: 'route_channels',
    column: 'last_selected_at',
    addSql: {
      sqlite: 'ALTER TABLE route_channels ADD COLUMN last_selected_at text;',
      mysql: 'ALTER TABLE `route_channels` ADD COLUMN `last_selected_at` TEXT NULL',
      postgres: 'ALTER TABLE "route_channels" ADD COLUMN "last_selected_at" TEXT',
    },
  },
  {
    table: 'route_channels',
    column: 'consecutive_fail_count',
    addSql: {
      sqlite: 'ALTER TABLE route_channels ADD COLUMN consecutive_fail_count integer NOT NULL DEFAULT 0;',
      mysql: 'ALTER TABLE `route_channels` ADD COLUMN `consecutive_fail_count` INT NOT NULL DEFAULT 0',
      postgres: 'ALTER TABLE "route_channels" ADD COLUMN "consecutive_fail_count" INTEGER NOT NULL DEFAULT 0',
    },
  },
  {
    table: 'route_channels',
    column: 'cooldown_level',
    addSql: {
      sqlite: 'ALTER TABLE route_channels ADD COLUMN cooldown_level integer NOT NULL DEFAULT 0;',
      mysql: 'ALTER TABLE `route_channels` ADD COLUMN `cooldown_level` INT NOT NULL DEFAULT 0',
      postgres: 'ALTER TABLE "route_channels" ADD COLUMN "cooldown_level" INTEGER NOT NULL DEFAULT 0',
    },
  },
];

export const ROUTE_GROUPING_TABLE_COMPATIBILITY_SPECS: RouteGroupingTableCompatibilitySpec[] = [
  {
    table: 'route_group_sources',
    createSql: {
      sqlite: [
        'CREATE TABLE IF NOT EXISTS route_group_sources (id integer PRIMARY KEY AUTOINCREMENT NOT NULL, group_route_id integer NOT NULL REFERENCES token_routes(id) ON DELETE cascade, source_route_id integer NOT NULL REFERENCES token_routes(id) ON DELETE cascade);',
        'CREATE UNIQUE INDEX IF NOT EXISTS route_group_sources_group_source_unique ON route_group_sources(group_route_id, source_route_id);',
        'CREATE INDEX IF NOT EXISTS route_group_sources_source_route_id_idx ON route_group_sources(source_route_id);',
      ],
      mysql: [
        'CREATE TABLE IF NOT EXISTS `route_group_sources` (`id` int AUTO_INCREMENT NOT NULL PRIMARY KEY, `group_route_id` int NOT NULL, `source_route_id` int NOT NULL, CONSTRAINT `route_group_sources_group_route_id_token_routes_id_fk` FOREIGN KEY (`group_route_id`) REFERENCES `token_routes`(`id`) ON DELETE cascade, CONSTRAINT `route_group_sources_source_route_id_token_routes_id_fk` FOREIGN KEY (`source_route_id`) REFERENCES `token_routes`(`id`) ON DELETE cascade)',
        'CREATE UNIQUE INDEX IF NOT EXISTS `route_group_sources_group_source_unique` ON `route_group_sources` (`group_route_id`,`source_route_id`)',
        'CREATE INDEX IF NOT EXISTS `route_group_sources_source_route_id_idx` ON `route_group_sources` (`source_route_id`)',
      ],
      postgres: [
        'CREATE TABLE IF NOT EXISTS "route_group_sources" ("id" INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL PRIMARY KEY, "group_route_id" INTEGER NOT NULL, "source_route_id" INTEGER NOT NULL, CONSTRAINT "route_group_sources_group_route_id_token_routes_id_fk" FOREIGN KEY ("group_route_id") REFERENCES "token_routes"("id") ON DELETE CASCADE, CONSTRAINT "route_group_sources_source_route_id_token_routes_id_fk" FOREIGN KEY ("source_route_id") REFERENCES "token_routes"("id") ON DELETE CASCADE)',
        'CREATE UNIQUE INDEX IF NOT EXISTS "route_group_sources_group_source_unique" ON "route_group_sources" ("group_route_id", "source_route_id")',
        'CREATE INDEX IF NOT EXISTS "route_group_sources_source_route_id_idx" ON "route_group_sources" ("source_route_id")',
      ],
    },
  },
];

function normalizeSchemaErrorMessage(error: unknown): string {
  if (typeof error === 'object' && error && 'message' in error) {
    return String((error as { message?: unknown }).message || '');
  }
  return String(error || '');
}

function isDuplicateColumnError(error: unknown): boolean {
  const lowered = normalizeSchemaErrorMessage(error).toLowerCase();
  return lowered.includes('duplicate column')
    || lowered.includes('already exists')
    || lowered.includes('duplicate column name');
}

async function executeAddColumn(inspector: RouteGroupingSchemaInspector, sqlText: string): Promise<void> {
  try {
    await inspector.execute(sqlText);
  } catch (error) {
    if (!isDuplicateColumnError(error)) {
      throw error;
    }
  }
}

export async function ensureRouteGroupingSchemaCompatibility(inspector: RouteGroupingSchemaInspector): Promise<void> {
  const tableExistsCache = new Map<string, boolean>();

  for (const spec of ROUTE_GROUPING_TABLE_COMPATIBILITY_SPECS) {
    const hasTable = await inspector.tableExists(spec.table);
    tableExistsCache.set(spec.table, hasTable);
    if (hasTable) {
      continue;
    }
    for (const sqlText of spec.createSql[inspector.dialect]) {
      await executeAddColumn(inspector, sqlText);
    }
    tableExistsCache.set(spec.table, true);
  }

  for (const spec of ROUTE_GROUPING_COLUMN_COMPATIBILITY_SPECS) {
    let hasTable = tableExistsCache.get(spec.table);
    if (hasTable === undefined) {
      hasTable = await inspector.tableExists(spec.table);
      tableExistsCache.set(spec.table, hasTable);
    }
    if (!hasTable) {
      continue;
    }

    const hasColumn = await inspector.columnExists(spec.table, spec.column);
    if (!hasColumn) {
      await executeAddColumn(inspector, spec.addSql[inspector.dialect]);
    }
  }
}
