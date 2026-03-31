import { detectPlatform } from './platforms/index.js';
import { detectSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';
import { stripTrailingSlashes } from './urlNormalization.js';

export async function detectSite(url: string) {
  const normalizedUrl = stripTrailingSlashes(url);
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
