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
import { Domain, User } from '../types/api';

interface AuthContextValue {
  user: User | null;
  roles: Record<string, string[]>;
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
  const [domains, setDomains] = useState<Domain[]>([]);
  const [currentDomain, setDomainState] = useState<string>(getCurrentDomain());
  const [loading, setLoading] = useState<boolean>(true);
  const [mustChangePassword, setMustChangePassword] = useState<boolean>(false);

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
      setUser(null);
      setRoles({});
      setMustChangePassword(false);
      setLoading(false);
      return;
    }
    try {
      const data = await api.auth.me();
      setUser(data.user);
      setRoles(data.roles || {});
      setMustChangePassword(!!data.user?.must_change_password);
      await refreshDomains();
    } catch {
      clearTokens();
      setUser(null);
      setRoles({});
      setMustChangePassword(false);
    } finally {
      setLoading(false);
    }
  }, [refreshDomains]);

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
      await refreshDomains();
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
      setUser(null);
      setRoles({});
      setMustChangePassword(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        roles,
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
