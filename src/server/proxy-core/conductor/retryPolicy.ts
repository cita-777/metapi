import type { AttemptFailure, AttemptFailureAction } from './types.js';

export function failureActionOf(result: AttemptFailure): AttemptFailureAction {
  return result.action;
}

export function shouldRetrySameChannel(action: AttemptFailureAction): boolean {
  return action === 'retry_same_channel';
}

export function shouldRefreshAuth(action: AttemptFailureAction): boolean {
  return action === 'refresh_auth';
}

export function shouldFailover(action: AttemptFailureAction): boolean {
  return action === 'failover' || action === 'refresh_auth';
}

export function isTerminalFailure(action: AttemptFailureAction): boolean {
  return action === 'terminal';
}
