const FP_KEY = 'openiam_device_fp';

// 生成并持久化稳定的浏览器设备指纹（非隐私追踪，仅用于会话管理与异常登录风险评估）。
export function getDeviceFingerprint(): string {
  try {
    const existing = localStorage.getItem(FP_KEY);
    if (existing) return existing;

    const raw = [
      navigator.userAgent,
      navigator.language,
      `${screen.width}x${screen.height}x${screen.colorDepth}`,
      Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      String(navigator.hardwareConcurrency || ''),
    ].join('|');

    let hash = 2166136261;
    for (let i = 0; i < raw.length; i++) {
      hash ^= raw.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    const randSuffix = Math.random().toString(36).slice(2, 8);
    const fp = `dev_${(hash >>> 0).toString(16)}_${randSuffix}`;
    localStorage.setItem(FP_KEY, fp);
    return fp;
  } catch {
    return 'dev_browser';
  }
}
