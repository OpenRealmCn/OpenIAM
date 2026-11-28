import React, { useMemo } from 'react';
import { CssBaseline, ThemeProvider, useMediaQuery } from '@mui/material';
import { MotionConfig } from 'framer-motion';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import { AuthProvider } from './context/AuthContext';
import { MOTION_SPEED_SCALE, useThemeStore } from './store/themeStore';
import { buildOpenIAMTheme } from './theme/theme';
import { AppLayout } from './components/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { OAuthConsentPage } from './pages/OAuthConsentPage';
import { DashboardPage } from './pages/DashboardPage';
import { UsersPage } from './pages/UsersPage';
import { DomainsPage } from './pages/DomainsPage';
import { RolesPage } from './pages/RolesPage';
import { PermissionsPage } from './pages/PermissionsPage';
import { OAuthAppsPage } from './pages/OAuthAppsPage';
import { IdentityProvidersPage } from './pages/IdentityProvidersPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { SystemSettingsPage } from './pages/SystemSettingsPage';
import { SystemVersionPage } from './pages/SystemVersionPage';

dayjs.locale('zh-cn');

export const App: React.FC = () => {
  const prefersDark = useMediaQuery('(prefers-color-scheme: dark)');
  const { colorMode, preset, customColor, borderRadius, motionSpeed } = useThemeStore();

  const resolvedMode = colorMode === 'system' ? (prefersDark ? 'dark' : 'light') : colorMode;
  const motionScale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  const theme = useMemo(
    () =>
      buildOpenIAMTheme({
        mode: resolvedMode,
        preset,
        customColor,
        borderRadius,
        motionSpeed,
      }),
    [resolvedMode, preset, customColor, borderRadius, motionSpeed],
  );

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <MotionConfig
        reducedMotion={motionSpeed === 'off' ? 'always' : 'user'}
        transition={{ duration: 0.22 * motionScale, ease: [0.22, 1, 0.36, 1] }}
      >
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route
                path="/change-password"
                element={
                  <ProtectedRoute>
                    <ChangePasswordPage />
                  </ProtectedRoute>
                }
              />
              <Route path="/oauth/callback/:provider" element={<OAuthCallbackPage />} />
              <Route
                path="/oauth2/consent"
                element={
                  <ProtectedRoute>
                    <OAuthConsentPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <AppLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="users" element={<UsersPage />} />
                <Route path="domains" element={<DomainsPage />} />
                <Route path="roles" element={<RolesPage />} />
                <Route path="permissions" element={<PermissionsPage />} />
                <Route path="oauth-apps" element={<OAuthAppsPage />} />
                <Route path="identity-providers" element={<IdentityProvidersPage />} />
                <Route path="audit-logs" element={<AuditLogsPage />} />
                <Route path="system-settings" element={<SystemSettingsPage />} />
                <Route path="system-version" element={<SystemVersionPage />} />
              </Route>
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </MotionConfig>
    </ThemeProvider>
  );
};

export default App;
