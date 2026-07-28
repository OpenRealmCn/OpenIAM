"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  previewRoles,
  previewUsers,
  type PreviewRole,
  type PreviewUser,
} from "@/lib/preview-data";

export type Density = "comfortable" | "compact";

export interface SecuritySettings {
  passwordMinLength: number;
  loginAttemptLimit: number;
  lockDurationMinutes: number;
}

export interface FeatureFlags {
  enforcePkce: boolean;
  auditLogin: boolean;
  mfaPreview: boolean;
}

export interface ConsoleSettings {
  accent: string;
  density: Density;
  security: SecuritySettings;
  sessionTtlHours: number;
  flags: FeatureFlags;
}

export interface ConsoleState {
  users: PreviewUser[];
  roles: PreviewRole[];
  settings: ConsoleSettings;
}

export interface NewUserInput {
  username: string;
  email: string;
  displayName: string;
  department: string;
  roles: string[];
}

export interface NewRoleInput {
  code: string;
  name: string;
  description: string;
  permissions: string[];
}

const STORAGE_KEY = "openiam-console-v1";

export const defaultSettings: ConsoleSettings = {
  accent: "#ffffff",
  density: "comfortable",
  security: {
    passwordMinLength: 12,
    loginAttemptLimit: 5,
    lockDurationMinutes: 15,
  },
  sessionTtlHours: 12,
  flags: {
    enforcePkce: true,
    auditLogin: true,
    mfaPreview: false,
  },
};

function seedState(): ConsoleState {
  return {
    users: [...previewUsers],
    roles: [...previewRoles],
    settings: defaultSettings,
  };
}

function loadState(): ConsoleState {
  if (typeof window === "undefined") return seedState();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return seedState();
    const parsed = JSON.parse(raw) as Partial<ConsoleState>;
    const seed = seedState();
    return {
      users:
        Array.isArray(parsed.users) && parsed.users.length > 0
          ? parsed.users
          : seed.users,
      roles:
        Array.isArray(parsed.roles) && parsed.roles.length > 0
          ? parsed.roles
          : seed.roles,
      settings: {
        ...seed.settings,
        ...(parsed.settings ?? {}),
        security: {
          ...seed.settings.security,
          ...(parsed.settings?.security ?? {}),
        },
        flags: {
          ...seed.settings.flags,
          ...(parsed.settings?.flags ?? {}),
        },
      },
    };
  } catch {
    return seedState();
  }
}

function hexToRgba(hex: string, alpha: number): string {
  const raw = hex.replace("#", "");
  const full =
    raw.length === 3
      ? raw
          .split("")
          .map((c) => c + c)
          .join("")
      : raw;
  const value = parseInt(full, 16);
  const r = (value >> 16) & 255;
  const g = (value >> 8) & 255;
  const b = value & 255;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

interface ConsoleContextValue {
  state: ConsoleState;
  addUser: (input: NewUserInput) => PreviewUser;
  addRole: (input: NewRoleInput) => PreviewRole;
  setAccent: (accent: string) => void;
  setDensity: (density: Density) => void;
  setSecurity: (patch: Partial<SecuritySettings>) => void;
  setFlag: (key: keyof FeatureFlags, value: boolean) => void;
  setSessionTtlHours: (hours: number) => void;
  resetPreview: () => void;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ConsoleState>(loadState);

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--accent-ui", state.settings.accent);
    root.style.setProperty(
      "--accent-ui-dim",
      hexToRgba(state.settings.accent, 0.22),
    );
  }, [state.settings.accent]);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      // storage unavailable; keep in-memory state
    }
  }, [state]);

  const addUser = useCallback((input: NewUserInput): PreviewUser => {
    const user: PreviewUser = {
      id: `u-${Math.random().toString(36).slice(2, 8)}`,
      name: input.displayName.trim() || input.username.trim(),
      email: input.email.trim(),
      department: input.department.trim() || "待分配",
      roles: input.roles,
      status: "active",
      lastLogin: "—",
    };
    setState((s) => ({ ...s, users: [user, ...s.users] }));
    return user;
  }, []);

  const addRole = useCallback((input: NewRoleInput): PreviewRole => {
    const role: PreviewRole = {
      code: input.code.trim(),
      name: input.name.trim(),
      description: input.description.trim() || "自定义角色。",
      isSystem: false,
      members: 0,
      permissions: input.permissions,
    };
    setState((s) => ({ ...s, roles: [role, ...s.roles] }));
    return role;
  }, []);

  const setAccent = useCallback((accent: string) => {
    setState((s) => ({ ...s, settings: { ...s.settings, accent } }));
  }, []);

  const setDensity = useCallback((density: Density) => {
    setState((s) => ({ ...s, settings: { ...s.settings, density } }));
  }, []);

  const setSecurity = useCallback((patch: Partial<SecuritySettings>) => {
    setState((s) => ({
      ...s,
      settings: {
        ...s.settings,
        security: { ...s.settings.security, ...patch },
      },
    }));
  }, []);

  const setFlag = useCallback((key: keyof FeatureFlags, value: boolean) => {
    setState((s) => ({
      ...s,
      settings: {
        ...s.settings,
        flags: { ...s.settings.flags, [key]: value },
      },
    }));
  }, []);

  const setSessionTtlHours = useCallback((hours: number) => {
    setState((s) => ({
      ...s,
      settings: { ...s.settings, sessionTtlHours: hours },
    }));
  }, []);

  const resetPreview = useCallback(() => {
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
    setState(seedState());
  }, []);

  const value = useMemo(
    () => ({
      state,
      addUser,
      addRole,
      setAccent,
      setDensity,
      setSecurity,
      setFlag,
      setSessionTtlHours,
      resetPreview,
    }),
    [
      state,
      addUser,
      addRole,
      setAccent,
      setDensity,
      setSecurity,
      setFlag,
      setSessionTtlHours,
      resetPreview,
    ],
  );

  return (
    <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>
  );
}

export function useConsole(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) {
    throw new Error("useConsole must be used within a ConsoleProvider");
  }
  return ctx;
}
