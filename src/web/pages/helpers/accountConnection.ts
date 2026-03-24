export function resolveAccountCredentialMode(account: any): 'session' | 'apikey' {
  const rawMode = String(account?.credentialMode || '').trim().toLowerCase();
  if (rawMode === 'apikey') return 'apikey';
  if (rawMode === 'session') return 'session';
  if (typeof account?.capabilities?.proxyOnly === 'boolean') {
    return account.capabilities.proxyOnly ? 'apikey' : 'session';
  }
  return typeof account?.accessToken === 'string' && account.accessToken.trim()
    ? 'session'
    : 'apikey';
}

export function parsePositiveInt(input: string | null): number {
  const normalized = String(input || '').trim();
  if (!/^\d+$/.test(normalized)) return 0;
  const value = Number.parseInt(normalized, 10);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return value;
}

export function isTruthyFlag(input: string | null): boolean {
  if (!input) return false;
  const normalized = input.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}
