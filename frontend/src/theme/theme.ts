import { alpha, createTheme, PaletteMode } from '@mui/material';
import { zhCN as coreZhCN } from '@mui/material/locale';
import { zhCN as dataGridZhCN } from '@mui/x-data-grid/locales';
import { zhCN as pickersZhCN } from '@mui/x-date-pickers/locales';
import type {} from '@mui/x-data-grid/themeAugmentation';

export type ThemePresetKey = 'cloudBlue' | 'indigo' | 'emerald' | 'violet' | 'amber';

export interface ThemePreset {
  key: ThemePresetKey;
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
];

export function getThemePreset(key: ThemePresetKey): ThemePreset {
  return THEME_PRESETS.find((p) => p.key === key) || THEME_PRESETS[0];
}

export function buildOpenIAMTheme(mode: PaletteMode, presetKey: ThemePresetKey = 'cloudBlue') {
  const isDark = mode === 'dark';
  const preset = getThemePreset(presetKey);
  const primaryMain = isDark ? preset.darkMain : preset.lightMain;

  const surfaceBg = isDark ? '#0F1216' : '#F4F6F9';
  const paperBg = isDark ? '#161B22' : '#FFFFFF';
  const subtleBorder = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(15, 23, 42, 0.08)';

  return createTheme(
    {
      palette: {
        mode,
        primary: {
          main: primaryMain,
        },
        secondary: {
          main: preset.accent,
        },
        background: {
          default: surfaceBg,
          paper: paperBg,
        },
        divider: subtleBorder,
        success: { main: '#10B981' },
        warning: { main: '#F59E0B' },
        error: { main: '#EF4444' },
        info: { main: '#0EA5E9' },
      },
      shape: {
        borderRadius: 12,
      },
      typography: {
        fontFamily: '"Inter", "Noto Sans SC", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        h4: { fontWeight: 700, letterSpacing: '-0.025em' },
        h5: { fontWeight: 700, letterSpacing: '-0.02em' },
        h6: { fontWeight: 600, letterSpacing: '-0.01em' },
        subtitle1: { fontWeight: 600 },
        subtitle2: { fontWeight: 600 },
        button: { fontWeight: 600, textTransform: 'none' },
      },
      components: {
        MuiCssBaseline: {
          styleOverrides: {
            body: {
              backgroundColor: surfaceBg,
              WebkitFontSmoothing: 'antialiased',
              MozOsxFontSmoothing: 'grayscale',
            },
            '::-webkit-scrollbar': {
              width: 7,
              height: 7,
            },
            '::-webkit-scrollbar-thumb': {
              borderRadius: 999,
              backgroundColor: isDark ? 'rgba(255,255,255,0.16)' : 'rgba(15,23,42,0.16)',
            },
            '::-webkit-scrollbar-track': {
              backgroundColor: 'transparent',
            },
          },
        },
        MuiButton: {
          defaultProps: {
            disableElevation: true,
          },
          styleOverrides: {
            root: {
              borderRadius: 10,
              paddingLeft: 16,
              paddingRight: 16,
              transition: 'all 0.16s ease',
            },
            containedPrimary: {
              '&:hover': {
                boxShadow: `0 6px 18px ${alpha(primaryMain, 0.32)}`,
              },
            },
          },
        },
        MuiCard: {
          defaultProps: {
            elevation: 0,
          },
          styleOverrides: {
            root: {
              borderRadius: 16,
              border: `1px solid ${subtleBorder}`,
              backgroundColor: paperBg,
              boxShadow: isDark
                ? '0 1px 2px rgba(0, 0, 0, 0.28)'
                : '0 1px 3px rgba(15, 23, 42, 0.04)',
              transition: 'border-color 0.18s ease, box-shadow 0.18s ease',
            },
          },
        },
        MuiPaper: {
          styleOverrides: {
            root: {
              backgroundImage: 'none',
            },
          },
        },
        MuiDialog: {
          styleOverrides: {
            paper: {
              borderRadius: 18,
              border: `1px solid ${subtleBorder}`,
              boxShadow: isDark
                ? '0 24px 60px rgba(0,0,0,0.65)'
                : '0 20px 50px rgba(15,23,42,0.14)',
            },
          },
        },
        MuiOutlinedInput: {
          styleOverrides: {
            root: {
              borderRadius: 10,
              '&:hover .MuiOutlinedInput-notchedOutline': {
                borderColor: alpha(primaryMain, 0.5),
              },
            },
          },
        },
        MuiChip: {
          styleOverrides: {
            root: {
              borderRadius: 8,
              fontWeight: 500,
            },
          },
        },
        MuiTab: {
          styleOverrides: {
            root: {
              textTransform: 'none',
              fontWeight: 600,
              minHeight: 46,
            },
          },
        },
        MuiDataGrid: {
          styleOverrides: {
            root: {
              border: `1px solid ${subtleBorder}`,
              borderRadius: 16,
              backgroundColor: paperBg,
              overflow: 'hidden',
              '--DataGrid-containerBackground': isDark ? '#1B222C' : '#F8FAFC',
              '& .MuiDataGrid-columnHeaders': {
                borderBottom: `1px solid ${subtleBorder}`,
                fontWeight: 600,
              },
              '& .MuiDataGrid-columnHeaderTitle': {
                fontWeight: 600,
                fontSize: '0.82rem',
              },
              '& .MuiDataGrid-cell': {
                borderColor: subtleBorder,
                fontSize: '0.86rem',
                display: 'flex',
                alignItems: 'center',
              },
              '& .MuiDataGrid-cell:focus, & .MuiDataGrid-columnHeader:focus': {
                outline: 'none',
              },
              '& .MuiDataGrid-row:hover': {
                backgroundColor: alpha(primaryMain, isDark ? 0.08 : 0.04),
              },
              '& .MuiDataGrid-toolbarContainer': {
                padding: '10px 14px',
                borderBottom: `1px solid ${subtleBorder}`,
                gap: 8,
              },
              '& .MuiDataGrid-footerContainer': {
                borderTop: `1px solid ${subtleBorder}`,
              },
            },
          },
        },
      },
    },
    coreZhCN,
    dataGridZhCN,
    pickersZhCN,
  );
}
