import { GeminiAdapter } from './gemini.js';

export class GeminiCliAdapter extends GeminiAdapter {
  override readonly platformName = 'gemini-cli';

  override async detect(url: string): Promise<boolean> {
    const normalized = (url || '').toLowerCase();
    return normalized.includes('cloudcode-pa.googleapis.com');
  }
}
