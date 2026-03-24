import React, { useEffect, useState, type CSSProperties } from 'react';
import {
  avatarLetters,
  getBrand,
  getBrandIconUrl,
  hashColor,
  normalizeBrandIconKey,
  type BrandInfo,
} from './brandRegistry.js';

export type { BrandInfo } from './brandRegistry.js';
export {
  getBrand,
  getBrandIconUrl,
  hashColor,
  normalizeBrandIconKey,
} from './brandRegistry.js';

const BRAND_ICON_VERSION = '1.83.0';
const ICON_CDN = `https://registry.npmmirror.com/@lobehub/icons-static-png/${BRAND_ICON_VERSION}/files/dark`;
const ICON_CDN_LIGHT = `https://registry.npmmirror.com/@lobehub/icons-static-png/${BRAND_ICON_VERSION}/files/light`;

export function useIconCdn() {
  const [isDark, setIsDark] = useState(() => {
    if (typeof document === 'undefined') return false;
    return document.documentElement.getAttribute('data-theme') === 'dark';
  });
  useEffect(() => {
    if (typeof document === 'undefined' || typeof MutationObserver === 'undefined') return undefined;
    const observer = new MutationObserver(() => {
      setIsDark(document.documentElement.getAttribute('data-theme') === 'dark');
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);
  return isDark ? ICON_CDN : ICON_CDN_LIGHT;
}

type BrandGlyphProps = {
  brand?: Pick<BrandInfo, 'name' | 'icon'> | null;
  model?: string | null;
  icon?: string | null;
  alt?: string;
  size?: number;
  fallbackText?: string | null;
  style?: CSSProperties;
};

export function BrandGlyph({ brand, model, icon, alt, size = 16, fallbackText, style }: BrandGlyphProps) {
  const cdn = useIconCdn();
  const resolvedBrand = brand || (model ? getBrand(model) : null);
  const resolvedIcon = normalizeBrandIconKey(icon || resolvedBrand?.icon || null);
  const [imgError, setImgError] = useState(false);

  useEffect(() => {
    setImgError(false);
  }, [resolvedIcon]);

  if (resolvedIcon && !imgError) {
    const src = getBrandIconUrl(resolvedIcon, cdn);
    if (src) {
      return (
        <img
          src={src}
          alt={alt || resolvedBrand?.name || model || 'brand'}
          style={{
            width: size,
            height: size,
            objectFit: 'contain',
            flexShrink: 0,
            verticalAlign: 'middle',
            ...style,
          }}
          onError={() => setImgError(true)}
          loading="lazy"
        />
      );
    }
  }

  const fallback = (fallbackText ?? resolvedBrand?.name ?? model ?? '').trim();
  if (!fallback) return null;

  return (
    <span
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        borderRadius: Math.max(4, Math.round(size * 0.33)),
        background: hashColor(fallback),
        color: 'white',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: Math.max(9, Math.round(size * 0.5)),
        fontWeight: 700,
        lineHeight: 1,
        flexShrink: 0,
        overflow: 'hidden',
        ...style,
      }}
    >
      {avatarLetters(fallback)}
    </span>
  );
}

export function BrandIcon({ model, size = 44 }: { model: string; size?: number }) {
  const brand = getBrand(model);

  if (brand) {
    return (
      <div style={{
        width: size,
        height: size,
        borderRadius: 10,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
        background: 'transparent',
      }}
      >
        <BrandGlyph brand={brand} size={size} fallbackText={brand.name} />
      </div>
    );
  }

  return (
    <div className="model-card-avatar" style={{ width: size, height: size, background: hashColor(model), fontSize: size > 32 ? 16 : 10 }}>
      {avatarLetters(model)}
    </div>
  );
}

export function InlineBrandIcon({ model, size = 16 }: { model: string; size?: number }) {
  const brand = getBrand(model);
  if (!brand) return null;
  return <BrandGlyph brand={brand} size={size} fallbackText={brand.name} />;
}

export function ModelBadge({ model, style }: { model: string; style?: CSSProperties }) {
  const brand = getBrand(model);

  const badgeColors: Record<string, { bg: string; border: string; text: string }> = {
    OpenAI: { bg: 'rgba(16,163,127,0.08)', border: 'rgba(16,163,127,0.2)', text: '#0d9668' },
    Anthropic: { bg: 'rgba(212,165,116,0.1)', border: 'rgba(212,165,116,0.25)', text: '#9a6e3a' },
    Google: { bg: 'rgba(66,133,244,0.08)', border: 'rgba(66,133,244,0.2)', text: '#2563eb' },
    DeepSeek: { bg: 'rgba(77,108,254,0.08)', border: 'rgba(77,108,254,0.2)', text: '#4d6bfe' },
    'Jina AI': { bg: 'rgba(17,24,39,0.08)', border: 'rgba(17,24,39,0.16)', text: '#111827' },
    Microsoft: { bg: 'rgba(0,164,239,0.08)', border: 'rgba(0,164,239,0.18)', text: '#0f62fe' },
    NVIDIA: { bg: 'rgba(118,185,0,0.10)', border: 'rgba(118,185,0,0.18)', text: '#4a8c0b' },
    xAI: { bg: 'rgba(0,0,0,0.06)', border: 'rgba(0,0,0,0.12)', text: '#333' },
  };

  const brandName = brand?.name || '';
  const colors = badgeColors[brandName] || {
    bg: 'var(--color-primary-light)',
    border: 'rgba(79,70,229,0.15)',
    text: 'var(--color-primary)',
  };

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 5,
      padding: '2px 10px 2px 6px',
      borderRadius: 6,
      fontSize: 12,
      fontWeight: 500,
      background: colors.bg,
      color: colors.text,
      border: `1px solid ${colors.border}`,
      whiteSpace: 'nowrap',
      ...style,
    }}
    >
      <InlineBrandIcon model={model} size={14} />
      {model}
    </span>
  );
}
