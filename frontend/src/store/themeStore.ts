import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ColorModeSetting = 'light' | 'dark' | 'system';
export type MotionSpeed = 'off' | 'fast' | 'normal' | 'slow';
export type ThemePresetKey = 'cloudBlue' | 'indigo' | 'emerald' | 'violet' | 'amber' | 'rose' | 'custom';

export interface ThemePreset {
  key: Exclude<ThemePresetKey, 'custom'>;
  label: string;
  lightMain: string;
  darkMain: string;
  accent: string;
}

export const THEME_PRESETS: ThemePreset[] = [
  { key: 'cloudBlue', label: '云澈蓝', lightMain: '#1976D2', darkMain: '#60A5FA', accent: '#0284C7' },
  { key: 'indigo', label: '深邃靛', lightMain: '#4F46E5', darkMain: '#818CF8', accent: '#6366F1' },
  { key: 'emerald', label: '松石绿', lightMain: '#059669', darkMain: '#34D399', accent: '#10B981' },
  { key: 'violet', label: '极光紫', lightMain: '#7C3AED', darkMain: '#A78BFA', accent: '#8B5CF6' },
  { key: 'amber', label: '琥珀金', lightMain: '#D97706', darkMain: '#FBBF24', accent: '#F59E0B' },
  { key: 'rose', label: '绯霞红', lightMain: '#E11D48', darkMain: '#FB7185', accent: '#F43F5E' },
];

export const MOTION_SPEED_SCALE: Record<MotionSpeed, number> = {
  off: 0,
  fast: 0.55,
  normal: 1,
  slow: 1.6,
};

// 默认圆角较原 12px 减少 5px，为 7px
export const DEFAULT_BORDER_RADIUS = 7;

export interface ThemePreferences {
  colorMode: ColorModeSetting;
  preset: ThemePresetKey;
  customColor: string;
  borderRadius: number;
  motionSpeed: MotionSpeed;
}

interface ThemeStoreState extends ThemePreferences {
  setColorMode: (mode: ColorModeSetting) => void;
  toggleColorMode: (resolvedMode: 'light' | 'dark') => void;
  setPreset: (preset: ThemePresetKey) => void;
  setCustomColor: (hex: string) => void;
  setBorderRadius: (radius: number) => void;
  setMotionSpeed: (speed: MotionSpeed) => void;
  resetDefaults: () => void;
}

const defaultPreferences: ThemePreferences = {
  colorMode: 'light',
  preset: 'cloudBlue',
  customColor: '#1976D2',
  borderRadius: DEFAULT_BORDER_RADIUS,
  motionSpeed: 'normal',
};

export const useThemeStore = create<ThemeStoreState>()(
  persist(
    (set) => ({
      ...defaultPreferences,
      setColorMode: (colorMode) => set({ colorMode }),
      toggleColorMode: (resolvedMode) => set({ colorMode: resolvedMode === 'light' ? 'dark' : 'light' }),
      setPreset: (preset) => set({ preset }),
      setCustomColor: (customColor) => set({ customColor, preset: 'custom' }),
      setBorderRadius: (borderRadius) =>
        set({ borderRadius: Math.max(0, Math.min(20, Math.round(borderRadius))) }),
      setMotionSpeed: (motionSpeed) => set({ motionSpeed }),
      resetDefaults: () => set({ ...defaultPreferences }),
    }),
    {
      name: 'openiam_theme_preferences_v1',
    },
  ),
);
