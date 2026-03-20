/** 32 字节随机数的 64 位十六进制字符串（置于 `sk-` 之后）。 */
export function generateSkSecretHexSuffix(): string {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Secure random generator is unavailable');
  }
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** 完整下游风格令牌：`sk-` + 64 位十六进制。 */
export function generateSkRandomToken(): string {
  return `sk-${generateSkSecretHexSuffix()}`;
}
