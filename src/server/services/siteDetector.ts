import { detectPlatform } from './platforms/index.js';
import { detectSiteInitializationPreset } from '../../shared/siteInitializationPresets.js';
import { analyzePrimarySiteUrl } from '../../shared/sitePrimaryUrl.js';

export async function detectSite(url: string) {
  const analyzed = analyzePrimarySiteUrl(url);
  const detectionUrl = analyzed.canonicalUrl;
  const persistedUrl = analyzed.persistedUrl || detectionUrl;
  const preset = detectSiteInitializationPreset(detectionUrl);
  if (preset) {
    return {
      url: persistedUrl,
      platform: preset.platform,
      initializationPresetId: preset.id,
    };
  }
  const adapter = await detectPlatform(detectionUrl);
  if (!adapter) return null;
  return { url: persistedUrl, platform: adapter.platformName };
}
