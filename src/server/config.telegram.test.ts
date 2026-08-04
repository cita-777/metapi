import { describe, expect, it } from 'vitest';
import { buildConfig } from './config.js';

describe('buildConfig telegram api base url', () => {
  it('falls back to the official Bot API endpoint', () => {
    expect(buildConfig({}).telegramApiBaseUrl).toBe('https://api.telegram.org');
  });

  it('accepts TELEGRAM_API_BASE_URL override', () => {
    const config = buildConfig({ TELEGRAM_API_BASE_URL: 'https://tg.example.com/api' });

    expect(config.telegramApiBaseUrl).toBe('https://tg.example.com/api');
  });

  it('strips trailing slashes and surrounding whitespace from the override', () => {
    const config = buildConfig({ TELEGRAM_API_BASE_URL: '  https://tg.example.com/api//  ' });

    expect(config.telegramApiBaseUrl).toBe('https://tg.example.com/api');
  });

  it('falls back to the default when the override is blank', () => {
    expect(buildConfig({ TELEGRAM_API_BASE_URL: '' }).telegramApiBaseUrl).toBe(
      'https://api.telegram.org',
    );
  });
});
