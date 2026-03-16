import React from 'react';
import { Link } from 'react-router-dom';

type SiteBadgeLinkProps = {
  siteId?: number | null;
  siteName?: string | null;
  className?: string;
  badgeClassName?: string;
  badgeStyle?: React.CSSProperties;
};

export default function SiteBadgeLink({
  siteId,
  siteName,
  className = 'badge-link',
  badgeClassName = 'badge badge-muted',
  badgeStyle,
}: SiteBadgeLinkProps) {
  const label = String(siteName || '').trim() || '-';
  const normalizedSiteId = Number(siteId);

  if (!Number.isFinite(normalizedSiteId) || normalizedSiteId <= 0) {
    return (
      <span className={badgeClassName} style={badgeStyle}>
        {label}
      </span>
    );
  }

  return (
    <Link to={`/sites?focusSiteId=${Math.trunc(normalizedSiteId)}`} className={className}>
      <span className={badgeClassName} style={badgeStyle}>
        {label}
      </span>
    </Link>
  );
}
