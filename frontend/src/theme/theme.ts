import { createTheme, PaletteMode } from '@mui/material';

export function buildOpenIAMTheme(mode: PaletteMode) {
  const isDark = mode === 'dark';
  return createTheme({
    palette: {
      mode,
      primary: {
        main: isDark ? '#5B8DEF' : '#1E40AF',
        light: '#60A5FA',
        dark: '#1E3A8A',
      },
      secondary: {
        main: isDark ? '#38BDF8' : '#0284C7',
      },
      background: {
        default: isDark ? '#0B1120' : '#F4F6FA',
        paper: isDark ? '#111827' : '#FFFFFF',
      },
      success: {
        main: '#10B981',
      },
      warning: {
        main: '#F59E0B',
      },
      error: {
        main: '#EF4444',
      },
    },
    shape: {
      borderRadius: 10,
    },
    typography: {
      fontFamily: '"Inter", "Noto Sans SC", -apple-system, BlinkMacSystemFont, sans-serif',
      h4: { fontWeight: 700, letterSpacing: '-0.02em' },
      h5: { fontWeight: 700, letterSpacing: '-0.01em' },
      h6: { fontWeight: 600 },
    },
    components: {
      MuiButton: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            fontWeight: 600,
            borderRadius: 8,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            border: isDark ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(15,23,42,0.08)',
            boxShadow: isDark
              ? '0 4px 20px rgba(0, 0, 0, 0.35)'
              : '0 2px 10px rgba(15, 23, 42, 0.04)',
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
      MuiChip: {
        styleOverrides: {
          root: {
            fontWeight: 500,
          },
        },
      },
    },
  });
}
