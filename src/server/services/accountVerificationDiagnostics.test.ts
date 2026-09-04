import { describe, expect, it } from 'vitest';
import {
  buildAccountVerificationHeaderVariants,
  diagnoseAccountVerificationFailure,
  parseAccountVerificationFailureReason,
  type AccountVerificationDiagnosticResponse,
} from './accountVerificationDiagnostics.js';

function response(
  body: string,
  contentType = 'application/json; charset=utf-8',
  status = 401,
): AccountVerificationDiagnosticResponse {
  return {
    status,
    text: async () => body,
    headers: {
      get: (name: string) => name.toLowerCase() === 'content-type' ? contentType : null,
    },
  };
}

describe('account verification diagnostics parser', () => {
  const cases: Array<{
    name: string;
    body: string;
    contentType: string;
    hasProvidedUserId: boolean;
    skipRawShieldDetection?: boolean;
    expected: ReturnType<typeof parseAccountVerificationFailureReason>;
  }> = [
    {
      name: 'classifies a missing user id message',
      body: JSON.stringify({ success: false, message: 'missing New-Api-User' }),
      contentType: 'application/json',
      hasProvidedUserId: false,
      expected: 'needs-user-id',
    },
    {
      name: 'classifies a mismatch before generic user-id wording',
      body: JSON.stringify({ success: false, message: 'user id mismatch' }),
      contentType: 'application/json',
      hasProvidedUserId: true,
      expected: 'invalid-user-id',
    },
    {
      name: 'classifies challenge html as shielded',
      body: '<html><script>var arg1="challenge";</script></html>',
      contentType: 'text/html; charset=utf-8',
      hasProvidedUserId: false,
      expected: 'shield-blocked',
    },
    {
      name: 'does not classify raw challenge html when explicitly skipped',
      body: '<html><script>var arg1="challenge";</script></html>',
      contentType: 'text/html; charset=utf-8',
      hasProvidedUserId: false,
      skipRawShieldDetection: true,
      expected: null,
    },
    {
      name: 'classifies a shield keyword in a JSON message',
      body: JSON.stringify({ success: false, message: 'captcha required' }),
      contentType: 'application/json',
      hasProvidedUserId: false,
      expected: 'shield-blocked',
    },
    {
      name: 'keeps unrelated or malformed payloads unknown',
      body: '{not-json}',
      contentType: 'application/json',
      hasProvidedUserId: false,
      expected: null,
    },
  ];

  for (const testCase of cases) {
    it(testCase.name, () => {
      expect(parseAccountVerificationFailureReason(
        testCase.body,
        testCase.contentType,
        {
          hasProvidedUserId: testCase.hasProvidedUserId,
          skipRawShieldDetection: testCase.skipRawShieldDetection,
        },
      )).toBe(testCase.expected);
    });
  }
});

describe('account verification diagnostics candidates', () => {
  it('preserves Bearer-first ordering and cookie variants without a user id', () => {
    const variants = buildAccountVerificationHeaderVariants('session=abc');

    expect(variants).toHaveLength(4);
    expect(variants[0]).toEqual({
      Authorization: 'Bearer session=abc',
      'Content-Type': 'application/json',
      'New-Api-User': '0',
    });
    expect(variants.slice(1)).toEqual([
      {
        Cookie: 'session=abc',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      {
        Cookie: 'session=session=abc',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      {
        Cookie: 'token=session=abc',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
    ]);
  });

  it('adds the normalized user id to every candidate when supplied', () => {
    const variants = buildAccountVerificationHeaderVariants('session-token', 42);

    expect(variants).toHaveLength(3);
    for (const variant of variants) {
      expect(variant['New-Api-User']).toBe('42');
    }
  });
});

describe('diagnoseAccountVerificationFailure', () => {
  it('normalizes the panel URL and returns response status with the reason', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const result = await diagnoseAccountVerificationFailure({
      baseUrl: 'https://panel.example.com///',
      accessToken: 'session-token',
      fetchImpl: async (url, init) => {
        calls.push({ url, init: init as RequestInit });
        return response(JSON.stringify({ message: 'missing New-Api-User' }));
      },
    });

    expect(result).toMatchObject({
      reason: 'needs-user-id',
      sawResponse: true,
      sawNetworkError: false,
      status: 401,
      endpoint: 'https://panel.example.com///',
      timedOut: false,
      retryable: false,
    });
    expect(calls[0]?.url).toBe('https://panel.example.com/api/user/self');
  });

  it('distinguishes all-network failure from a response that has no diagnosis', async () => {
    const failed = await diagnoseAccountVerificationFailure({
      baseUrl: 'https://panel.example.com',
      accessToken: 'session-token',
      fetchImpl: async () => {
        throw new Error('connect timeout');
      },
    });
    expect(failed).toMatchObject({
      reason: null,
      sawResponse: false,
      sawNetworkError: true,
      timedOut: true,
      retryable: true,
    });

    let mixedAttempts = 0;
    const mixed = await diagnoseAccountVerificationFailure({
      baseUrl: 'https://panel.example.com',
      accessToken: 'session-token',
      fetchImpl: async () => {
        mixedAttempts += 1;
        if (mixedAttempts === 1) throw new Error('socket hang up');
        return response(JSON.stringify({ message: 'unrelated failure' }));
      },
    });
    expect(mixed).toMatchObject({
      reason: null,
      sawResponse: true,
      sawNetworkError: true,
      timedOut: false,
      retryable: false,
    });
  });
});
