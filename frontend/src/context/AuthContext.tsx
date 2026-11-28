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
import { Domain, User, UserIdentity } from '../types/api';

interface AuthContextValue {
  user: User | null;
  roles: Record<string, string[]>;
  identities: UserIdentity[];
  hasPassword: boolean;
  passkeyCount: number;
  isAdmin: boolean;
  domains: Domain[];
  currentDomain: string;
  loading: boolean;
  mustChangePassword: boolean;
  switchDomain: (domainCode: string) => void;
  refreshProfile: () => Promise<void>;
  refreshDomains: () => Promise<void>;
  loginWithCredentials: (username: string, password: string) => Promise<boolean>;
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
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
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
    setIsAdmin(false);
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
      setIsAdmin(Boolean(data.is_admin));
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

  const switchDomain = (domainCode: string) => {
    setCurrentDomain(domainCode);
    setDomainState(domainCode);
  };

  // 返回是否处于强制改密状态，交给调用方决定跳改密页还是进控制台。
  const loginWithCredentials = async (username: string, password: string): Promise<boolean> => {
    const data = await api.auth.login(username, password);
    setTokens(data.access_token);
    setUser(data.user);
    setRoles(data.roles || {});
    const forced = !!data.must_change_password;
    setMustChangePassword(forced);
    if (!forced) {
      await refreshProfile();
    }
    return forced;
  };

  const completeOAuthLogin = async (accessToken: string) => {
    setTokens(accessToken);
    await refreshProfile();
  };

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

  return (
    <AuthContext.Provider
      value={{
        user,
        roles,
        identities,
        hasPassword,
        passkeyCount,
        isAdmin,
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
