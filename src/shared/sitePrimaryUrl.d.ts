export type PrimarySiteUrlAction =
  | 'unchanged'
  | 'auto_strip_known_api_suffix'
  | 'preserve_api_path'
  | 'preserve_semantic_path'
  | 'preserve_unknown_path';

export type PrimarySiteUrlAnalysis = {
  canonicalUrl: string;
  persistedUrl: string;
  matchedPath: string;
  action: PrimarySiteUrlAction;
};

export declare function analyzePrimarySiteUrl(url: string | null | undefined): PrimarySiteUrlAnalysis;
