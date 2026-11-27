import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

const TOKEN_KEY = 'openiam_access_token';
const REFRESH_KEY = 'openiam_refresh_token';
const DOMAIN_KEY = 'openiam_current_domain';

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem(TOKEN_KEY, access);
  if (refresh) {
    localStorage.setItem(REFRESH_KEY, refresh);
  }
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export function getCurrentDomain(): string {
  return localStorage.getItem(DOMAIN_KEY) || 'openiam';
}

export function setCurrentDomain(domain: string) {
  localStorage.setItem(DOMAIN_KEY, domain);
}

export const http = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
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

http.interceptors.response.use(
  (resp) => resp,
  async (error: AxiosError<{ message?: string }>) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
    if (error.response?.status === 401 && original && !original._retry && !original.url?.includes('/auth/refresh')) {
      original._retry = true;
      const refresh = getRefreshToken();
      if (refresh) {
        if (!refreshingPromise) {
          refreshingPromise = axios
            .post('/api/v1/auth/refresh', { refresh_token: refresh })
            .then((res) => {
              const { access_token, refresh_token } = res.data.data;
              setTokens(access_token, refresh_token);
              return access_token as string;
            })
            .catch(() => {
              clearTokens();
              return null;
            })
            .finally(() => {
              refreshingPromise = null;
            });
        }
        const newToken = await refreshingPromise;
        if (newToken) {
          original.headers.Authorization = `Bearer ${newToken}`;
          return http(original);
        }
      }
    }
    const msg = error.response?.data?.message || error.message || '请求失败';
    return Promise.reject(new Error(msg));
  },
);

export const api = {
  auth: {
    login: (username: string, password: string) =>
      http.post('/auth/login', { username, password }).then((r) => r.data.data),
    register: (payload: { username: string; email: string; password: string; display_name?: string }) =>
      http.post('/auth/register', payload).then((r) => r.data.data),
    logout: (refresh_token: string | null) =>
      http.post('/auth/logout', { refresh_token }).then((r) => r.data.data),
    me: () => http.get('/auth/me').then((r) => r.data.data),
    changePassword: (old_password: string, new_password: string) =>
      http.post('/auth/change-password', { old_password, new_password }).then((r) => r.data.data),
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
  },
};
