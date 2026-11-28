import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  api,
  clearTokens,
  getAccessToken,
  getCurrentDomain,
  refreshAccessToken,
  setCurrentDomain,
  setTokens,
} from '../api/client';
import { AdminTier, Domain, User, UserIdentity } from '../types/api';

export interface LoginStepResult {
  mustChangePassword?: boolean;
  mfaRequired?: boolean;
  mfaToken?: string;
  methods?: string[];
  riskLevel?: string;
  riskReasons?: string[];
  emailHint?: string;
  phoneHint?: string;
}

interface AuthContextValue {
  user: User | null;
  roles: Record<string, string[]>;
  identities: UserIdentity[];
  hasPassword: boolean;
  passkeyCount: number;
  totpEnabled: boolean;
  isAdmin: boolean;
  adminTier: AdminTier;
  capabilities: string[];
  hasCap: (cap: string) => boolean;
  sessionId: string;
  unreadNotifications: number;
  refreshUnreadCount: () => Promise<void>;
  domains: Domain[];
  currentDomain: string;
  loading: boolean;
  mustChangePassword: boolean;
  switchDomain: (domainCode: string) => void;
  refreshProfile: () => Promise<void>;
  refreshDomains: () => Promise<void>;
  loginWithCredentials: (username: string, password: string, captchaToken?: string) => Promise<LoginStepResult>;
  completeOAuthLogin: (accessToken: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [roles, setRoles] = useState<Record<string, string[]>>({});
  const [identities, setIdentities] = useState<UserIdentity[]>([]);
  const [hasPassword, setHasPassword] = useState<boolean>(true);
  const [passkeyCount, setPasskeyCount] = useState<number>(0);
  const [totpEnabled, setTotpEnabled] = useState<boolean>(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [adminTier, setAdminTier] = useState<AdminTier>('user');
  const [capabilities, setCapabilities] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState<string>('');
  const [unreadNotifications, setUnreadNotifications] = useState<number>(0);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [currentDomain, setDomainState] = useState<string>(getCurrentDomain());
  const [loading, setLoading] = useState<boolean>(true);
  const [mustChangePassword, setMustChangePassword] = useState<boolean>(false);

  const resetAuthState = useCallback(() => {
    setUser(null);
    setRoles({});
    setIdentities([]);
    setHasPassword(true);
    setPasskeyCount(0);
    setTotpEnabled(false);
    setIsAdmin(false);
    setAdminTier('user');
    setCapabilities([]);
    setSessionId('');
    setUnreadNotifications(0);
    setDomains([]);
    setMustChangePassword(false);
  }, []);

  const refreshDomains = useCallback(async () => {
    try {
      const list = await api.domains.list();
      setDomains(list || []);
    } catch {
      // ignore if unauthorized
    }
  }, []);

  const refreshUnreadCount = useCallback(async () => {
    if (!getAccessToken()) return;
    try {
      const res = await api.notifications.unreadCount();
      setUnreadNotifications(Number(res?.total || 0));
    } catch {
      // ignore
    }
  }, []);

  const refreshProfile = useCallback(async () => {
    const token = getAccessToken() ?? (await refreshAccessToken());
    if (!token) {
      resetAuthState();
      setLoading(false);
      return;
    }
    try {
      const data = await api.auth.me();
      setUser(data.user);
      setRoles(data.roles || {});
      setMustChangePassword(!!data.user?.must_change_password);
      setIdentities(data.identities || []);
      setHasPassword(Boolean(data.has_password));
      setPasskeyCount(Number(data.passkey_count || 0));
      setTotpEnabled(Boolean(data.totp_enabled));
      setIsAdmin(Boolean(data.is_admin));
      setAdminTier((data.admin_tier as AdminTier) || (data.is_admin ? 'domain_admin' : 'user'));
      setCapabilities(Array.isArray(data.capabilities) ? data.capabilities : []);
      setSessionId(data.session_id || '');
      setUnreadNotifications(Number(data.unread_notifications || 0));
      if (!data.user?.must_change_password) {
        await refreshDomains();
      }
    } catch {
      clearTokens();
      resetAuthState();
    } finally {
      setLoading(false);
    }
  }, [refreshDomains, resetAuthState]);

  useEffect(() => {
    refreshProfile();
  }, [refreshProfile]);

  const switchDomain = useCallback(
    (domainCode: string) => {
      setCurrentDomain(domainCode);
      setDomainState(domainCode);
      // 切换业务域后重新计算当前域的管理员等级与精细化权限集合
      void refreshProfile();
    },
    [refreshProfile],
  );

  const loginWithCredentials = async (
    username: string,
    password: string,
    captchaToken?: string,
  ): Promise<LoginStepResult> => {
    const data = await api.auth.login(username, password, captchaToken);
    if (data.mfa_required) {
      return {
        mfaRequired: true,
        mfaToken: data.mfa_token,
        methods: data.methods || [],
        riskLevel: data.risk_level,
        riskReasons: data.risk_reasons || [],
        emailHint: data.email_hint,
        phoneHint: data.phone_hint,
      };
    }
    setTokens(data.access_token);
    setUser(data.user);
    setRoles(data.roles || {});
    const forced = !!data.must_change_password;
    setMustChangePassword(forced);
    if (!forced) {
      await refreshProfile();
    }
    return { mustChangePassword: forced };
  };

  const completeOAuthLogin = useCallback(
    async (accessToken: string) => {
      setTokens(accessToken);
      await refreshProfile();
    },
    [refreshProfile],
  );

  const logout = async () => {
    try {
      await api.auth.logout();
    } catch {
      // ignore
    } finally {
      clearTokens();
      resetAuthState();
    }
  };

  const hasCap = useCallback(
    (cap: string) => {
      if (adminTier === 'platform_admin') return true;
      return capabilities.includes(cap);
    },
    [adminTier, capabilities],
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        roles,
        identities,
        hasPassword,
        passkeyCount,
        totpEnabled,
        isAdmin,
        adminTier,
        capabilities,
        hasCap,
        sessionId,
        unreadNotifications,
        refreshUnreadCount,
        domains,
        currentDomain,
        loading,
        mustChangePassword,
        switchDomain,
        refreshProfile,
        refreshDomains,
        loginWithCredentials,
        completeOAuthLogin,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return ctx;
}
