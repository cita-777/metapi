import { refreshOauthAccessToken } from './service.js';

const refreshInFlight = new Map<number, Promise<Awaited<ReturnType<typeof refreshOauthAccessToken>>>>();

export async function refreshOauthAccessTokenSingleflight(accountId: number) {
  const existing = refreshInFlight.get(accountId);
  if (existing) {
    return existing;
  }

  const promise = refreshOauthAccessToken(accountId).finally(() => {
    refreshInFlight.delete(accountId);
  });
  refreshInFlight.set(accountId, promise);
  return promise;
}
