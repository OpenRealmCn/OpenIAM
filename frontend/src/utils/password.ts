import { SiteInfo } from '../types/api';

export interface PasswordPolicy {
  minLength: number;
  requireComplexity: boolean;
}

// 初始管理员改密沿用的固定策略，与后端 security.ValidateInitialPassword 保持一致。
export const INITIAL_PASSWORD_POLICY: PasswordPolicy = { minLength: 12, requireComplexity: true };

const MAX_PASSWORD_BYTES = 72;

export function policyFromSite(site?: Partial<SiteInfo> | null): PasswordPolicy {
  return {
    minLength: Math.max(8, Number(site?.password_min_length) || 8),
    requireComplexity: Boolean(site?.password_require_complexity),
  };
}

export function passwordHint(policy: PasswordPolicy): string {
  return policy.requireComplexity
    ? `至少 ${policy.minLength} 位，需同时包含大写字母、小写字母和数字`
    : `至少 ${policy.minLength} 位`;
}

// 返回 null 表示通过；长度上限按 UTF-8 字节计算，与后端 bcrypt 的 72 字节限制一致。
export function validatePassword(password: string, policy: PasswordPolicy): string | null {
  if ([...password].length < policy.minLength) {
    return `密码至少需要 ${policy.minLength} 位`;
  }
  if (new TextEncoder().encode(password).length > MAX_PASSWORD_BYTES) {
    return '密码过长，请缩短后重试';
  }
  if (policy.requireComplexity && !(/[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password))) {
    return '密码需同时包含大写字母、小写字母和数字';
  }
  return null;
}

const POST_CHANGE_REDIRECT_KEY = 'openiam_post_change_redirect';

export function rememberPostChangeRedirect(target: string) {
  try {
    sessionStorage.setItem(POST_CHANGE_REDIRECT_KEY, target);
  } catch {
    // 存储不可用时改密后回到首页
  }
}

export function takePostChangeRedirect(): string | null {
  try {
    const v = sessionStorage.getItem(POST_CHANGE_REDIRECT_KEY);
    sessionStorage.removeItem(POST_CHANGE_REDIRECT_KEY);
    return v;
  } catch {
    return null;
  }
}
