/** 32 字节随机数的 64 位十六进制字符串（置于 `sk-` 之后）。 */
export function generateSkSecretHexSuffix(): string {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Secure random generator is unavailable');
  }
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** 读取与后端一致的 `PROXY_TOKEN_PREFIX`（Vite 客户端需能注入到 import.meta.env，见各构建配置）。 */
function readProxyTokenPrefix(): string {
  const metaEnv = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env;
  const fromMeta = metaEnv?.PROXY_TOKEN_PREFIX;
  const fromProcess = typeof process !== 'undefined' ? process.env.PROXY_TOKEN_PREFIX : undefined;
  const raw = (fromMeta ?? fromProcess ?? 'sk-').trim();
  return raw.length > 0 ? raw : 'sk-';
}

/** 完整令牌：`PROXY_TOKEN_PREFIX`（默认 sk-）+ 64 位十六进制。 */
export function generateSkRandomToken(): string {
  return `${readProxyTokenPrefix()}${generateSkSecretHexSuffix()}`;
}
