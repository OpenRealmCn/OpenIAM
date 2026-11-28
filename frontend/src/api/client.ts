import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

const DOMAIN_KEY = 'openiam_current_domain';
const LEGACY_TOKEN_KEYS = ['openiam_access_token', 'openiam_refresh_token'];

// Access Token 仅保存在内存中；Refresh Token 由服务端以 HttpOnly Cookie 下发，脚本无法读取，可降低 XSS 窃取风险。
let accessToken: string | null = null;

// 清理旧版本遗留在 localStorage 中的令牌
try {
  LEGACY_TOKEN_KEYS.forEach((k) => localStorage.removeItem(k));
} catch {
  // 忽略存储不可用的情况
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setTokens(access: string) {
  accessToken = access;
}

export function clearTokens() {
  accessToken = null;
}

export function getCurrentDomain(): string {
  return localStorage.getItem(DOMAIN_KEY) || 'openiam';
}

export function setCurrentDomain(domain: string) {
  localStorage.setItem(DOMAIN_KEY, domain);
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '');

export const http = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  withCredentials: true,
});

http.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  config.headers['X-OpenIAM-Domain'] = getCurrentDomain();
  return config;
});

let refreshingPromise: Promise<string | null> | null = null;

// 凭 HttpOnly Cookie 中的 Refresh Token 换取新的 Access Token（并发请求共用同一次刷新）。
export function refreshAccessToken(): Promise<string | null> {
  if (!refreshingPromise) {
    refreshingPromise = axios
      .post(`${API_BASE_URL}/auth/refresh`, {}, { timeout: 15000, withCredentials: true })
      .then((res) => {
        const token = res.data.data.access_token as string;
        setTokens(token);
        return token;
      })
      .catch(() => {
        clearTokens();
        return null;
      })
      .finally(() => {
        refreshingPromise = null;
      });
  }
  return refreshingPromise;
}

http.interceptors.response.use(
  (resp) => resp,
  async (error: AxiosError<{ message?: string }>) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
    if (error.response?.status === 401 && original && !original._retry && !original.url?.includes('/auth/refresh') && !original.url?.includes('/auth/login')) {
      original._retry = true;
      const newToken = await refreshAccessToken();
      if (newToken) {
        original.headers.Authorization = `Bearer ${newToken}`;
        return http(original);
      }
    }
    const msg = error.response?.data?.message || error.message || '请求失败';
    return Promise.reject(new Error(msg));
  },
);

export const api = {
  site: {
    info: () => http.get('/site/info').then((r) => r.data.data),
  },
  auth: {
    login: (username: string, password: string) =>
      http.post('/auth/login', { username, password }).then((r) => r.data.data),
    register: (payload: { username: string; email: string; password: string; display_name?: string }) =>
      http.post('/auth/register', payload).then((r) => r.data.data),
    logout: () =>
      http.post('/auth/logout', {}).then((r) => r.data.data),
    me: () => http.get('/auth/me').then((r) => r.data.data),
    updateProfile: (payload: { display_name: string; avatar_url: string }) =>
      http.put('/auth/me', payload).then((r) => r.data.data),
    changePassword: (old_password: string, new_password: string) =>
      http.post('/auth/change-password', { old_password, new_password }).then((r) => r.data.data),
    requestPasswordReset: (email: string) =>
      http.post('/auth/password-reset/request', { email }).then((r) => r.data.data),
    confirmPasswordReset: (payload: { email: string; code: string; new_password: string }) =>
      http.post('/auth/password-reset/confirm', payload).then((r) => r.data.data),
    listIdentities: () => http.get('/auth/me/identities').then((r) => r.data.data),
    linkIdentity: (provider: string, redirect_uri?: string) =>
      http.post(`/auth/me/identities/${provider}/link`, null, { params: { redirect_uri } }).then((r) => r.data.data),
    unbindIdentity: (id: number) => http.delete(`/auth/me/identities/${id}`).then((r) => r.data.data),
    listPasskeys: () => http.get('/auth/passkeys').then((r) => r.data.data),
    passkeyRegisterBegin: () => http.post('/auth/passkeys/register/begin').then((r) => r.data.data),
    passkeyRegisterFinish: (session_id: string, name: string, credential: unknown) =>
      http.post('/auth/passkeys/register/finish', credential, { params: { session_id, name } }).then((r) => r.data.data),
    deletePasskey: (id: number) => http.delete(`/auth/passkeys/${id}`).then((r) => r.data.data),
    passkeyLoginBegin: (username?: string) =>
      http.post('/auth/passkeys/login/begin', { username: username || '' }).then((r) => r.data.data),
    passkeyLoginFinish: (session_id: string, credential: unknown) =>
      http.post('/auth/passkeys/login/finish', credential, { params: { session_id } }).then((r) => r.data.data),
    publicProviders: () => http.get('/auth/oauth/providers').then((r) => r.data.data),
    oauthAuthorize: (provider: string, redirect_uri?: string) =>
      http.get(`/auth/oauth/${provider}/authorize`, { params: { redirect_uri } }).then((r) => r.data.data),
    oauthCallback: (provider: string, payload: { code: string; state: string; redirect_uri?: string }) =>
      http.post(`/auth/oauth/${provider}/callback`, payload).then((r) => r.data.data),
  },
  domains: {
    list: () => http.get('/domains').then((r) => r.data.data),
    create: (data: { code: string; name: string; description?: string; status?: string }) =>
      http.post('/domains', data).then((r) => r.data.data),
    update: (id: number, data: { name?: string; description?: string; status?: string }) =>
      http.put(`/domains/${id}`, data).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/domains/${id}`).then((r) => r.data.data),
  },
  users: {
    list: (params?: { page?: number; page_size?: number; keyword?: string; status?: string }) =>
      http.get('/users', { params }).then((r) => r.data.data),
    create: (data: {
      username: string;
      email: string;
      display_name?: string;
      password: string;
      status?: string;
      domain_code?: string;
      role_codes?: string[];
    }) => http.post('/users', data).then((r) => r.data.data),
    update: (id: number, data: { email?: string; display_name?: string; status?: string }) =>
      http.put(`/users/${id}`, data).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/users/${id}`).then((r) => r.data.data),
    resetPassword: (id: number, new_password: string) =>
      http.post(`/users/${id}/reset-password`, { new_password }).then((r) => r.data.data),
    assignRoles: (id: number, data: { domain_code: string; role_codes: string[]; replace?: boolean }) =>
      http.post(`/users/${id}/roles`, data).then((r) => r.data.data),
  },
  roles: {
    list: (domain?: string) => http.get('/roles', { params: { domain } }).then((r) => r.data.data),
    create: (data: { domain_code: string; code: string; name: string; description?: string }) =>
      http.post('/roles', data).then((r) => r.data.data),
    update: (id: number, data: { name?: string; description?: string }) =>
      http.put(`/roles/${id}`, data).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/roles/${id}`).then((r) => r.data.data),
    setPermissions: (id: number, policies: { resource: string; action: string }[]) =>
      http.put(`/roles/${id}/permissions`, { policies }).then((r) => r.data.data),
  },
  permissions: {
    list: (domain?: string) => http.get('/permissions', { params: { domain } }).then((r) => r.data.data),
    create: (data: { domain_code: string; code: string; name: string; resource: string; action: string; description?: string }) =>
      http.post('/permissions', data).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/permissions/${id}`).then((r) => r.data.data),
    listPolicies: (params?: { domain?: string; role?: string }) =>
      http.get('/policies', { params }).then((r) => r.data.data),
    addPolicy: (data: { role: string; domain: string; resource: string; action: string }) =>
      http.post('/policies', data).then((r) => r.data.data),
    removePolicy: (data: { role: string; domain: string; resource: string; action: string }) =>
      http.delete('/policies', { data }).then((r) => r.data.data),
    checkPolicy: (data: { user_id: number; domain: string; resource: string; action: string }) =>
      http.post('/policies/check', data).then((r) => r.data.data),
  },
  oauthClients: {
    list: (domain?: string) => http.get('/oauth-clients', { params: { domain } }).then((r) => r.data.data),
    create: (data: {
      name: string;
      description?: string;
      domain_code: string;
      redirect_uris: string[];
      grant_types: string[];
      scopes: string[];
      require_pkce: boolean;
      is_confidential: boolean;
    }) => http.post('/oauth-clients', data).then((r) => r.data.data),
    update: (id: number, data: Record<string, unknown>) =>
      http.put(`/oauth-clients/${id}`, data).then((r) => r.data.data),
    rotateSecret: (id: number) =>
      http.post(`/oauth-clients/${id}/rotate-secret`).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/oauth-clients/${id}`).then((r) => r.data.data),
  },
  myOAuthClients: {
    list: () => http.get('/my/oauth-clients').then((r) => r.data.data),
    create: (data: {
      name: string;
      description?: string;
      domain_code: string;
      redirect_uris: string[];
      grant_types: string[];
      scopes: string[];
      require_pkce: boolean;
      is_confidential: boolean;
    }) => http.post('/my/oauth-clients', data).then((r) => r.data.data),
    rotateSecret: (id: number) =>
      http.post(`/my/oauth-clients/${id}/rotate-secret`).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/my/oauth-clients/${id}`).then((r) => r.data.data),
  },
  oauthProviders: {
    listPlugins: () => http.get('/oauth-providers/plugins').then((r) => r.data.data),
    list: () => http.get('/oauth-providers').then((r) => r.data.data),
    create: (data: Record<string, unknown>) => http.post('/oauth-providers', data).then((r) => r.data.data),
    update: (id: number, data: Record<string, unknown>) =>
      http.put(`/oauth-providers/${id}`, data).then((r) => r.data.data),
    delete: (id: number) => http.delete(`/oauth-providers/${id}`).then((r) => r.data.data),
  },
  oauth2Server: {
    getConsent: (id: string) => http.get(`/oauth2/consent/${id}`).then((r) => r.data.data),
    submitConsent: (id: string, approved: boolean) =>
      http.post(`/oauth2/consent/${id}`, { approved }).then((r) => r.data.data),
    createCode: (data: {
      client_id: string;
      redirect_uri?: string;
      scopes?: string[];
      state?: string;
    }) => http.post('/oauth2/codes', data).then((r) => r.data.data),
  },
  audit: {
    list: (params: Record<string, unknown>) => http.get('/audit-logs', { params }).then((r) => r.data.data),
    stats: () => http.get('/audit-logs/stats').then((r) => r.data.data),
  },
  system: {
    health: () => http.get('/health').then((r) => r.data.data),
    version: () => http.get('/system/version').then((r) => r.data.data),
    dashboard: () => http.get('/system/dashboard').then((r) => r.data.data),
    getSettings: () => http.get('/system/settings').then((r) => r.data.data),
    updateSettings: (settings: Record<string, string>) =>
      http.put('/system/settings', { settings }).then((r) => r.data.data),
    testSMTP: (to: string) =>
      http.post('/system/settings/test-smtp', { to }).then((r) => r.data.data),
  },
};
