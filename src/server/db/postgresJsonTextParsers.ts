import pg from 'pg';

export type PgTypesLike = {
  builtins: {
    JSON: number;
    JSONB: number;
  };
  setTypeParser(oid: number, format: 'text', parser: (value: string) => string): void;
};

let postgresJsonTextParsersInstalled = false;

export function installPostgresJsonTextParsers(typesRegistry: PgTypesLike = pg.types as PgTypesLike): void {
  if (postgresJsonTextParsersInstalled) return;
  const identity = (value: string) => value;
  typesRegistry.setTypeParser(typesRegistry.builtins.JSON, 'text', identity);
  typesRegistry.setTypeParser(typesRegistry.builtins.JSONB, 'text', identity);
  postgresJsonTextParsersInstalled = true;
}

export function resetPostgresJsonTextParsersInstallStateForTests(): void {
  postgresJsonTextParsersInstalled = false;
}
