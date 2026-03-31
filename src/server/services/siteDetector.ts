import { detectPlatform } from './platforms/index.js';
import { detectSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';

export async function detectSite(url: string) {
  const normalizedUrl = url.replace(/\/+$/, '');
  const preset = detectSiteInitializationPreset(normalizedUrl);
  if (preset) {
    return {
      url: normalizedUrl,
      platform: preset.platform,
      initializationPresetId: preset.id,
    };
  }
  const adapter = await detectPlatform(normalizedUrl);
  if (!adapter) return null;
  return { url: normalizedUrl, platform: adapter.platformName };
}
