import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  api,
  clearTokens,
  getAccessToken,
  getCurrentDomain,
  getRefreshToken,
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
  switchDomain: (domainCode: string) => void;
  refreshProfile: () => Promise<void>;
  refreshDomains: () => Promise<void>;
  loginWithCredentials: (username: string, password: string) => Promise<void>;
  completeOAuthLogin: (accessToken: string, refreshToken: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [roles, setRoles] = useState<Record<string, string[]>>({});
  const [domains, setDomains] = useState<Domain[]>([]);
  const [currentDomain, setDomainState] = useState<string>(getCurrentDomain());
  const [loading, setLoading] = useState<boolean>(true);

  const refreshDomains = useCallback(async () => {
    try {
      const list = await api.domains.list();
      setDomains(list || []);
    } catch {
      // ignore if unauthorized
    }
  }, []);

  const refreshProfile = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setUser(null);
      setRoles({});
      setLoading(false);
      return;
    }
    try {
      const data = await api.auth.me();
      setUser(data.user);
      setRoles(data.roles || {});
      await refreshDomains();
    } catch {
      clearTokens();
      setUser(null);
      setRoles({});
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

  const loginWithCredentials = async (username: string, password: string) => {
    const data = await api.auth.login(username, password);
    setTokens(data.access_token, data.refresh_token);
    setUser(data.user);
    setRoles(data.roles || {});
    await refreshDomains();
  };

  const completeOAuthLogin = async (accessToken: string, refreshToken: string) => {
    setTokens(accessToken, refreshToken);
    await refreshProfile();
  };

  const logout = async () => {
    try {
      await api.auth.logout(getRefreshToken());
    } catch {
      // ignore
    } finally {
      clearTokens();
      setUser(null);
      setRoles({});
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
