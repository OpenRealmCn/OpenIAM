import { alpha, createTheme, PaletteMode } from '@mui/material';
import { zhCN as coreZhCN } from '@mui/material/locale';
import { zhCN as dataGridZhCN } from '@mui/x-data-grid/locales';
import { zhCN as pickersZhCN } from '@mui/x-date-pickers/locales';
import type {} from '@mui/x-data-grid/themeAugmentation';
import {
  DEFAULT_BORDER_RADIUS,
  MOTION_SPEED_SCALE,
  MotionSpeed,
  THEME_PRESETS,
  ThemePresetKey,
} from '../store/themeStore';

export interface BuildThemeOptions {
  mode: PaletteMode;
  preset: ThemePresetKey;
  customColor?: string;
  borderRadius?: number;
  motionSpeed?: MotionSpeed;
}

function resolvePrimaryColors(mode: PaletteMode, preset: ThemePresetKey, customColor?: string) {
  const isDark = mode === 'dark';
  if (preset === 'custom' && customColor && /^#[0-9a-fA-F]{6}$/.test(customColor)) {
    return { primaryMain: customColor, secondaryMain: customColor };
  }
  const found = THEME_PRESETS.find((p) => p.key === preset) || THEME_PRESETS[0];
  return {
    primaryMain: isDark ? found.darkMain : found.lightMain,
    secondaryMain: found.accent,
  };
}

export function buildOpenIAMTheme({
  mode,
  preset,
  customColor,
  borderRadius = DEFAULT_BORDER_RADIUS,
  motionSpeed = 'normal',
}: BuildThemeOptions) {
  const isDark = mode === 'dark';
  const { primaryMain, secondaryMain } = resolvePrimaryColors(mode, preset, customColor);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  const baseRadius = Math.max(0, Math.min(20, borderRadius));
  const controlRadius = Math.max(0, baseRadius - 2);
  const chipRadius = Math.max(0, baseRadius - 2);
  const cardRadius = Math.max(0, baseRadius + 4);
  const dialogRadius = Math.max(0, baseRadius + 6);

  const transitionMs = Math.round(160 * scale);
  const transitionCSS = scale === 0 ? 'none' : `all ${transitionMs}ms cubic-bezier(0.22, 1, 0.36, 1)`;

  const surfaceBg = isDark ? '#0F1216' : '#F4F6F9';
  const paperBg = isDark ? '#161B22' : '#FFFFFF';
  const subtleBorder = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(15, 23, 42, 0.08)';

  return createTheme(
    {
      palette: {
        mode,
        primary: { main: primaryMain },
        secondary: { main: secondaryMain },
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
        borderRadius: baseRadius,
      },
      transitions: {
        duration: {
          shortest: Math.round(150 * scale),
          shorter: Math.round(200 * scale),
          short: Math.round(250 * scale),
          standard: Math.round(300 * scale),
          complex: Math.round(375 * scale),
          enteringScreen: Math.round(225 * scale),
          leavingScreen: Math.round(195 * scale),
        },
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
              borderRadius: controlRadius,
              paddingLeft: 16,
              paddingRight: 16,
              transition: transitionCSS,
            },
            containedPrimary: {
              '&:hover': {
                boxShadow: `0 6px 18px ${alpha(primaryMain, 0.28)}`,
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
              borderRadius: cardRadius,
              border: `1px solid ${subtleBorder}`,
              backgroundColor: paperBg,
              boxShadow: isDark
                ? '0 1px 2px rgba(0, 0, 0, 0.28)'
                : '0 1px 3px rgba(15, 23, 42, 0.04)',
              transition: transitionCSS,
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
              borderRadius: dialogRadius,
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
              borderRadius: controlRadius,
              transition: transitionCSS,
              '&:hover .MuiOutlinedInput-notchedOutline': {
                borderColor: alpha(primaryMain, 0.5),
              },
            },
          },
        },
        MuiChip: {
          styleOverrides: {
            root: {
              borderRadius: chipRadius,
              fontWeight: 500,
            },
          },
        },
        MuiTab: {
          styleOverrides: {
            root: {
              textTransform: 'none',
              fontWeight: 600,
              minHeight: 44,
            },
          },
        },
        MuiDataGrid: {
          styleOverrides: {
            root: {
              border: `1px solid ${subtleBorder}`,
              borderRadius: cardRadius,
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
              '& .MuiDataGrid-row': {
                transition: transitionCSS,
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
