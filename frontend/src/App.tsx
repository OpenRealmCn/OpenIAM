import React, { useMemo } from 'react';
import { CssBaseline, ThemeProvider, useMediaQuery } from '@mui/material';
import { MotionConfig } from 'framer-motion';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SiteProvider } from './context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from './store/themeStore';
import { buildOpenIAMTheme } from './theme/theme';
import { AppLayout } from './components/AppLayout';
import { CapabilityGuard } from './components/CapabilityGuard';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { OAuthConsentPage } from './pages/OAuthConsentPage';
import { DashboardPage } from './pages/DashboardPage';
import { UserPortalPage } from './pages/UserPortalPage';
import { ProfilePage } from './pages/ProfilePage';
import { UsersPage } from './pages/UsersPage';
import { DomainsPage } from './pages/DomainsPage';
import { RolesPage } from './pages/RolesPage';
import { PermissionsPage } from './pages/PermissionsPage';
import { OAuthAppsPage } from './pages/OAuthAppsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { SystemSettingsPage } from './pages/SystemSettingsPage';
import { SystemVersionPage } from './pages/SystemVersionPage';
import { JitGrantsPage } from './pages/JitGrantsPage';
import { SessionsPage } from './pages/SessionsPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { PluginsPage } from './pages/PluginsPage';
import { RiskEventsPage } from './pages/RiskEventsPage';

dayjs.locale('zh-cn');

const HomeEntry: React.FC = () => {
  const { adminTier } = useAuth();
  if (adminTier === 'platform_admin' || adminTier === 'domain_admin') {
    return <DashboardPage />;
  }
  if (adminTier === 'auditor') {
    return <AuditLogsPage />;
  }
  return <UserPortalPage />;
};

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
        <SiteProvider>
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
                  <Route index element={<HomeEntry />} />
                  <Route path="portal" element={<UserPortalPage />} />
                  <Route path="profile" element={<ProfilePage />} />
                  <Route path="notifications" element={<NotificationsPage />} />
                  <Route path="oauth-apps" element={<OAuthAppsPage />} />
                  <Route
                    path="users"
                    element={
                      <CapabilityGuard cap="users:read">
                        <UsersPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="domains"
                    element={
                      <CapabilityGuard tiers={['platform_admin']}>
                        <DomainsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="roles"
                    element={
                      <CapabilityGuard cap="roles:read">
                        <RolesPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="permissions"
                    element={
                      <CapabilityGuard cap="permissions:read">
                        <PermissionsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="jit-grants"
                    element={
                      <CapabilityGuard cap="jit:read">
                        <JitGrantsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="sessions"
                    element={
                      <CapabilityGuard cap="sessions:read">
                        <SessionsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="risk-events"
                    element={
                      <CapabilityGuard cap="risk:read">
                        <RiskEventsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="identity-providers"
                    element={<Navigate to="/plugins?slot=oauth" replace />}
                  />
                  <Route
                    path="plugins"
                    element={
                      <CapabilityGuard tiers={['platform_admin']}>
                        <PluginsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="audit-logs"
                    element={
                      <CapabilityGuard cap="audit_logs:read">
                        <AuditLogsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="system-settings"
                    element={
                      <CapabilityGuard tiers={['platform_admin']}>
                        <SystemSettingsPage />
                      </CapabilityGuard>
                    }
                  />
                  <Route
                    path="system-version"
                    element={
                      <CapabilityGuard cap="system:read">
                        <SystemVersionPage />
                      </CapabilityGuard>
                    }
                  />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </BrowserRouter>
          </AuthProvider>
        </SiteProvider>
      </MotionConfig>
    </ThemeProvider>
  );
};

export default App;
