const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

export function assertLoopbackUrl(value, message) {
  const url = new URL(value);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(message);
  }
  return url;
}
