import { Navigate, useLocation } from 'react-router-dom';

// Keep the legacy route entrypoint small. The actual token-management surface
// lives in the tokens domain so other pages can embed it without importing a
// top-level route page.
export { TokensPanel } from './tokens/TokensPanel.js';
export type { TokensPanelProps } from './tokens/TokensPanel.js';

export default function Tokens() {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  params.set('segment', 'tokens');
  const nextSearch = params.toString();
  return <Navigate to={`/accounts${nextSearch ? `?${nextSearch}` : ''}`} replace />;
}
