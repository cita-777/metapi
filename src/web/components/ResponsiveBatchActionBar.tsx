import React from 'react';
import MobileBatchBar from './MobileBatchBar.js';

type ResponsiveBatchActionBarProps = {
  isMobile: boolean;
  info: React.ReactNode;
  children: React.ReactNode;
  desktopStyle?: React.CSSProperties;
  infoStyle?: React.CSSProperties;
};

const DEFAULT_DESKTOP_STYLE: React.CSSProperties = {
  padding: 12,
  display: 'flex',
  gap: 8,
  flexWrap: 'wrap',
  alignItems: 'center',
};

const DEFAULT_INFO_STYLE: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 600,
};

export default function ResponsiveBatchActionBar({
  isMobile,
  info,
  children,
  desktopStyle,
  infoStyle,
}: ResponsiveBatchActionBarProps) {
  if (isMobile) {
    return <MobileBatchBar info={info}>{children}</MobileBatchBar>;
  }

  return (
    <div className="card" style={{ ...DEFAULT_DESKTOP_STYLE, ...desktopStyle }}>
      <span style={{ ...DEFAULT_INFO_STYLE, ...infoStyle }}>{info}</span>
      {children}
    </div>
  );
}
