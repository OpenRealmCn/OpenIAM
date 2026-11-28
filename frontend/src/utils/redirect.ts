// 登录后跳转只允许站内路径：拒绝 //evil.com、/\evil.com、javascript: 等可被浏览器解释为外站或脚本的写法。
export function safeInternalPath(raw: string | null | undefined, fallback = '/'): string {
  if (!raw || typeof raw !== 'string') return fallback;
  const value = raw.trim();
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\') || /[\u0000-\u001f]/.test(value)) {
    return fallback;
  }
  try {
    const url = new URL(value, window.location.origin);
    if (url.origin !== window.location.origin) return fallback;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return fallback;
  }
}

const BLOCKED_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:', 'filesystem:']);

// OAuth 回调地址：与服务端校验一致，只放行 https、本机 http 与带点号的原生应用自定义协议。
export function isSafeClientRedirect(raw: string | null | undefined): boolean {
  if (!raw || typeof raw !== 'string') return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  const protocol = url.protocol.toLowerCase();
  if (BLOCKED_SCHEMES.has(protocol)) return false;
  if (protocol === 'https:') return true;
  if (protocol === 'http:') {
    return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
  }
  return protocol.slice(0, -1).includes('.');
}
