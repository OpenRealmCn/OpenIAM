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
import {
  applyTokens,
  CUSTOM_THEME_ID,
  resolveTokens,
  type ThemeMode,
  type ThemeTokens,
} from "@/lib/themes";

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

export interface FeishuSettings {
  enabled: boolean;
  appId: string;
  redirectUri: string;
}

export interface CustomTheme {
  light: Partial<ThemeTokens>;
  dark: Partial<ThemeTokens>;
}

export interface ConsoleSettings {
  themeMode: ThemeMode;
  themeId: string;
  customTheme: CustomTheme;
  density: Density;
  security: SecuritySettings;
  sessionTtlHours: number;
  flags: FeatureFlags;
  feishu: FeishuSettings;
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

const STORAGE_KEY = "openiam-console-v2";

export const defaultSettings: ConsoleSettings = {
  themeMode: "dark",
  themeId: "vercel",
  customTheme: { light: {}, dark: {} },
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
  feishu: {
    enabled: false,
    appId: "",
    redirectUri: "http://localhost:8080/api/v1/auth/feishu/callback",
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
    const s: Partial<ConsoleSettings> = parsed.settings ?? {};
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
        ...s,
        customTheme: {
          light: { ...(s.customTheme?.light ?? {}) },
          dark: { ...(s.customTheme?.dark ?? {}) },
        },
        security: { ...seed.settings.security, ...(s.security ?? {}) },
        flags: { ...seed.settings.flags, ...(s.flags ?? {}) },
        feishu: { ...seed.settings.feishu, ...(s.feishu ?? {}) },
      },
    };
  } catch {
    return seedState();
  }
}

interface ConsoleContextValue {
  state: ConsoleState;
  addUser: (input: NewUserInput) => PreviewUser;
  addRole: (input: NewRoleInput) => PreviewRole;
  updateRole: (code: string, patch: Partial<PreviewRole>) => void;
  deleteRole: (code: string) => void;
  setThemeMode: (mode: ThemeMode) => void;
  setThemeId: (id: string) => void;
  setCustomTokens: (
    mode: "light" | "dark",
    patch: Partial<ThemeTokens>,
  ) => void;
  setDensity: (density: Density) => void;
  setSecurity: (patch: Partial<SecuritySettings>) => void;
  setFlag: (key: keyof FeatureFlags, value: boolean) => void;
  setSessionTtlHours: (hours: number) => void;
  setFeishu: (patch: Partial<FeishuSettings>) => void;
  resetPreview: () => void;
}

const ConsoleContext = createContext<ConsoleContextValue | null>(null);

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ConsoleState>(loadState);
  const [systemDark, setSystemDark] = useState(
    () =>
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches,
  );

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    const { themeMode, themeId, customTheme } = state.settings;
    const { tokens, effective } = resolveTokens(
      themeId,
      themeMode,
      systemDark,
      customTheme,
    );
    applyTokens(tokens, effective);
  }, [state.settings, systemDark]);

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

  const updateRole = useCallback(
    (code: string, patch: Partial<PreviewRole>) => {
      setState((s) => ({
        ...s,
        roles: s.roles.map((r) => (r.code === code ? { ...r, ...patch } : r)),
      }));
    },
    [],
  );

  const deleteRole = useCallback((code: string) => {
    setState((s) => ({
      ...s,
      roles: s.roles.filter((r) => r.code !== code),
      users: s.users.map((u) => ({
        ...u,
        roles: u.roles.filter((rc) => rc !== code),
      })),
    }));
  }, []);

  const setThemeMode = useCallback((mode: ThemeMode) => {
    setState((s) => ({ ...s, settings: { ...s.settings, themeMode: mode } }));
  }, []);

  const setThemeId = useCallback((id: string) => {
    setState((s) => ({ ...s, settings: { ...s.settings, themeId: id } }));
  }, []);

  const setCustomTokens = useCallback(
    (mode: "light" | "dark", patch: Partial<ThemeTokens>) => {
      setState((s) => ({
        ...s,
        settings: {
          ...s.settings,
          themeId: CUSTOM_THEME_ID,
          customTheme: {
            ...s.settings.customTheme,
            [mode]: { ...s.settings.customTheme[mode], ...patch },
          },
        },
      }));
    },
    [],
  );

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

  const setFeishu = useCallback((patch: Partial<FeishuSettings>) => {
    setState((s) => ({
      ...s,
      settings: {
        ...s.settings,
        feishu: { ...s.settings.feishu, ...patch },
      },
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
      updateRole,
      deleteRole,
      setThemeMode,
      setThemeId,
      setCustomTokens,
      setDensity,
      setSecurity,
      setFlag,
      setSessionTtlHours,
      setFeishu,
      resetPreview,
    }),
    [
      state,
      addUser,
      addRole,
      updateRole,
      deleteRole,
      setThemeMode,
      setThemeId,
      setCustomTokens,
      setDensity,
      setSecurity,
      setFlag,
      setSessionTtlHours,
      setFeishu,
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

export function readFeishuEnabled(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return false;
    const parsed = JSON.parse(raw) as Partial<ConsoleState>;
    return parsed.settings?.feishu?.enabled ?? false;
  } catch {
    return false;
  }
}
