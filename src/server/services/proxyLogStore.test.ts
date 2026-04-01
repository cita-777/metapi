import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  hasProxyLogBillingDetailsColumnMock,
  hasProxyLogClientColumnsMock,
  hasProxyLogDownstreamApiKeyIdColumnMock,
  dbInsertMock,
  dbInsertValuesMock,
  dbInsertRunMock,
  proxyLogsSchema,
} = vi.hoisted(() => ({
  hasProxyLogBillingDetailsColumnMock: vi.fn(),
  hasProxyLogClientColumnsMock: vi.fn(),
  hasProxyLogDownstreamApiKeyIdColumnMock: vi.fn(),
  dbInsertMock: vi.fn(),
  dbInsertValuesMock: vi.fn(),
  dbInsertRunMock: vi.fn(),
  proxyLogsSchema: {
    id: 'id',
    routeId: 'route_id',
    channelId: 'channel_id',
    accountId: 'account_id',
    modelRequested: 'model_requested',
    modelActual: 'model_actual',
    status: 'status',
    httpStatus: 'http_status',
    latencyMs: 'latency_ms',
    promptTokens: 'prompt_tokens',
    completionTokens: 'completion_tokens',
    totalTokens: 'total_tokens',
    estimatedCost: 'estimated_cost',
    billingDetails: 'billing_details',
    clientFamily: 'client_family',
    clientAppId: 'client_app_id',
    clientAppName: 'client_app_name',
    clientConfidence: 'client_confidence',
    errorMessage: 'error_message',
    retryCount: 'retry_count',
    createdAt: 'created_at',
  },
}));

vi.mock('../db/index.js', () => ({
  db: {
    insert: (...args: unknown[]) => dbInsertMock(...args),
  },
  schema: {
    proxyLogs: proxyLogsSchema,
  },
  hasProxyLogBillingDetailsColumn: (...args: unknown[]) => hasProxyLogBillingDetailsColumnMock(...args),
  hasProxyLogClientColumns: (...args: unknown[]) => hasProxyLogClientColumnsMock(...args),
  hasProxyLogDownstreamApiKeyIdColumn: (...args: unknown[]) => hasProxyLogDownstreamApiKeyIdColumnMock(...args),
}));

import { insertProxyLog, parseProxyLogBillingDetails, withProxyLogSelectFields } from './proxyLogStore.js';

describe('proxyLogStore', () => {
  beforeEach(() => {
    hasProxyLogBillingDetailsColumnMock.mockReset();
    hasProxyLogClientColumnsMock.mockReset();
    hasProxyLogDownstreamApiKeyIdColumnMock.mockReset();
    dbInsertMock.mockReset();
    dbInsertValuesMock.mockReset();
    dbInsertRunMock.mockReset();
    hasProxyLogBillingDetailsColumnMock.mockResolvedValue(false);
    hasProxyLogClientColumnsMock.mockResolvedValue(false);
    hasProxyLogDownstreamApiKeyIdColumnMock.mockResolvedValue(false);

    dbInsertMock.mockReturnValue({
      values: (...args: unknown[]) => dbInsertValuesMock(...args),
    });
    dbInsertValuesMock.mockReturnValue({
      run: (...args: unknown[]) => dbInsertRunMock(...args),
    });
  });

  it('retries proxy log selects without billing details when the column is missing', async () => {
    hasProxyLogBillingDetailsColumnMock.mockResolvedValue(true);
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('column proxy_logs.billing_details does not exist'))
      .mockResolvedValueOnce([{ id: 1 }]);

    await expect(withProxyLogSelectFields(runner, { includeBillingDetails: true })).resolves.toEqual([{ id: 1 }]);

    expect(runner).toHaveBeenCalledTimes(2);
    expect(runner.mock.calls[0][0].includeBillingDetails).toBe(true);
    expect(runner.mock.calls[0][0].fields.billingDetails).toBe('billing_details');
    expect(runner.mock.calls[1][0].includeBillingDetails).toBe(false);
    expect(runner.mock.calls[1][0].fields.billingDetails).toBeUndefined();
  });

  it('accepts parsed billing details objects for helper-level callers', () => {
    expect(parseProxyLogBillingDetails({
      source: 'pricing',
      usd: 1.25,
    })).toEqual({
      source: 'pricing',
      usd: 1.25,
    });
  });

  it('retries proxy log inserts without billing details when the column is missing', async () => {
    hasProxyLogBillingDetailsColumnMock.mockResolvedValue(true);
    dbInsertRunMock
      .mockRejectedValueOnce(new Error('column proxy_logs.billing_details does not exist'))
      .mockResolvedValueOnce(undefined);

    await insertProxyLog({
      modelRequested: 'gpt-5',
      billingDetails: { total: 1 },
    });

    expect(dbInsertValuesMock).toHaveBeenCalledTimes(2);
    expect(dbInsertValuesMock.mock.calls[0][0]).toMatchObject({
      modelRequested: 'gpt-5',
      billingDetails: JSON.stringify({ total: 1 }),
    });
    expect(dbInsertValuesMock.mock.calls[1][0]).toMatchObject({
      modelRequested: 'gpt-5',
    });
    expect(dbInsertValuesMock.mock.calls[1][0].billingDetails).toBeUndefined();
  });

  it('falls back to base values when both billing details and downstream key columns are missing', async () => {
    hasProxyLogBillingDetailsColumnMock.mockResolvedValue(true);
    hasProxyLogDownstreamApiKeyIdColumnMock.mockResolvedValue(true);
    dbInsertRunMock
      .mockRejectedValueOnce(new Error('column proxy_logs.billing_details does not exist'))
      .mockRejectedValueOnce(new Error('column proxy_logs.downstream_api_key_id does not exist'))
      .mockResolvedValueOnce(undefined);

    await insertProxyLog({
      modelRequested: 'gpt-5',
      billingDetails: { total: 1 },
      downstreamApiKeyId: 12,
    });

    expect(dbInsertValuesMock).toHaveBeenCalledTimes(3);
    expect(dbInsertValuesMock.mock.calls[0][0]).toMatchObject({
      modelRequested: 'gpt-5',
      billingDetails: JSON.stringify({ total: 1 }),
      downstreamApiKeyId: 12,
    });
    expect(dbInsertValuesMock.mock.calls[1][0]).toMatchObject({
      modelRequested: 'gpt-5',
      downstreamApiKeyId: 12,
    });
    expect(dbInsertValuesMock.mock.calls[2][0]).toMatchObject({
      modelRequested: 'gpt-5',
    });
    expect(dbInsertValuesMock.mock.calls[2][0].billingDetails).toBeUndefined();
    expect(dbInsertValuesMock.mock.calls[2][0].downstreamApiKeyId).toBeUndefined();
  });

  it('writes structured client fields when the schema supports them', async () => {
    hasProxyLogClientColumnsMock.mockResolvedValue(true);

    await insertProxyLog({
      modelRequested: 'gpt-5',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });

    expect(dbInsertValuesMock).toHaveBeenCalledTimes(1);
    expect(dbInsertValuesMock.mock.calls[0][0]).toMatchObject({
      modelRequested: 'gpt-5',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });
  });

  it('preserves null token fields instead of coercing unknown usage to zero', async () => {
    await insertProxyLog({
      modelRequested: 'gpt-5',
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
    });

    expect(dbInsertValuesMock).toHaveBeenCalledTimes(1);
    expect(dbInsertValuesMock.mock.calls[0][0]).toMatchObject({
      modelRequested: 'gpt-5',
      promptTokens: null,
      completionTokens: null,
      totalTokens: null,
    });
  });

  it('retries proxy log inserts without structured client fields when those columns are missing', async () => {
    hasProxyLogClientColumnsMock.mockResolvedValue(true);
    dbInsertRunMock
      .mockRejectedValueOnce(new Error('column proxy_logs.client_app_id does not exist'))
      .mockResolvedValueOnce(undefined);

    await insertProxyLog({
      modelRequested: 'gpt-5',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });

    expect(dbInsertValuesMock).toHaveBeenCalledTimes(2);
    expect(dbInsertValuesMock.mock.calls[0][0]).toMatchObject({
      modelRequested: 'gpt-5',
      clientFamily: 'codex',
      clientAppId: 'cherry_studio',
      clientAppName: 'Cherry Studio',
      clientConfidence: 'exact',
    });
    expect(dbInsertValuesMock.mock.calls[1][0]).toMatchObject({
      modelRequested: 'gpt-5',
    });
    expect(dbInsertValuesMock.mock.calls[1][0].clientFamily).toBeUndefined();
    expect(dbInsertValuesMock.mock.calls[1][0].clientAppId).toBeUndefined();
    expect(dbInsertValuesMock.mock.calls[1][0].clientAppName).toBeUndefined();
    expect(dbInsertValuesMock.mock.calls[1][0].clientConfidence).toBeUndefined();
  });
});
