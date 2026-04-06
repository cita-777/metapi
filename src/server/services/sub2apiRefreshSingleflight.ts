import type { schema } from '../db/index.js';
import { refreshSub2ApiManagedSession } from './sub2apiManagedAuth.js';

type RefreshParams = {
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
  currentAccessToken: string;
  currentExtraConfig: string | null;
};

const refreshInFlight = new Map<number, Promise<Awaited<ReturnType<typeof refreshSub2ApiManagedSession>>>>();

export async function refreshSub2ApiManagedSessionSingleflight(params: RefreshParams) {
  const existing = refreshInFlight.get(params.account.id);
  if (existing) {
    return existing;
  }

  const promise = refreshSub2ApiManagedSession(params).finally(() => {
    refreshInFlight.delete(params.account.id);
  });
  refreshInFlight.set(params.account.id, promise);
  return promise;
}

export function __resetSub2ApiManagedRefreshSingleflightForTests() {
  refreshInFlight.clear();
}
