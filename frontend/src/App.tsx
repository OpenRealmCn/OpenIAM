import React, { lazy, Suspense, useMemo } from 'react';
import { Box, CircularProgress, CssBaseline, ThemeProvider, useMediaQuery } from '@mui/material';
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
import { ReauthDialog } from './components/ReauthDialog';
import { ConfirmProvider } from './components/ConfirmDialog';

dayjs.locale('zh-cn');

function lazyPage<T extends React.ComponentType>(loader: () => Promise<T>) {
  return lazy(() => loader().then((component) => ({ default: component })));
}

const LoginPage = lazyPage(() => import('./pages/LoginPage').then((m) => m.LoginPage));
const ChangePasswordPage = lazyPage(() => import('./pages/ChangePasswordPage').then((m) => m.ChangePasswordPage));
const OAuthCallbackPage = lazyPage(() => import('./pages/OAuthCallbackPage').then((m) => m.OAuthCallbackPage));
const OAuthConsentPage = lazyPage(() => import('./pages/OAuthConsentPage').then((m) => m.OAuthConsentPage));
const DashboardPage = lazyPage(() => import('./pages/DashboardPage').then((m) => m.DashboardPage));
const UserPortalPage = lazyPage(() => import('./pages/UserPortalPage').then((m) => m.UserPortalPage));
const ProfilePage = lazyPage(() => import('./pages/ProfilePage').then((m) => m.ProfilePage));
const UsersPage = lazyPage(() => import('./pages/UsersPage').then((m) => m.UsersPage));
const DomainsPage = lazyPage(() => import('./pages/DomainsPage').then((m) => m.DomainsPage));
const RolesPage = lazyPage(() => import('./pages/RolesPage').then((m) => m.RolesPage));
const PermissionsPage = lazyPage(() => import('./pages/PermissionsPage').then((m) => m.PermissionsPage));
const OAuthAppsPage = lazyPage(() => import('./pages/OAuthAppsPage').then((m) => m.OAuthAppsPage));
const AuditLogsPage = lazyPage(() => import('./pages/AuditLogsPage').then((m) => m.AuditLogsPage));
const SystemSettingsPage = lazyPage(() => import('./pages/SystemSettingsPage').then((m) => m.SystemSettingsPage));
const SystemVersionPage = lazyPage(() => import('./pages/SystemVersionPage').then((m) => m.SystemVersionPage));
const JitGrantsPage = lazyPage(() => import('./pages/JitGrantsPage').then((m) => m.JitGrantsPage));
const SessionsPage = lazyPage(() => import('./pages/SessionsPage').then((m) => m.SessionsPage));
const NotificationsPage = lazyPage(() => import('./pages/NotificationsPage').then((m) => m.NotificationsPage));
const PluginsPage = lazyPage(() => import('./pages/PluginsPage').then((m) => m.PluginsPage));
const RiskEventsPage = lazyPage(() => import('./pages/RiskEventsPage').then((m) => m.RiskEventsPage));

const RouteFallback: React.FC<{ fullPage?: boolean }> = ({ fullPage = false }) => (
  <Box
    sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: fullPage ? '100vh' : 280,
    }}
  >
    <CircularProgress size={28} />
  </Box>
);

function page(node: React.ReactNode, fullPage = false) {
  return <Suspense fallback={<RouteFallback fullPage={fullPage} />}>{node}</Suspense>;
}

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
            <ConfirmProvider>
            <ReauthDialog />
            <BrowserRouter>
              <Routes>
                <Route path="/login" element={page(<LoginPage />, true)} />
                <Route
                  path="/change-password"
                  element={page(
                    <ProtectedRoute>
                      <ChangePasswordPage />
                    </ProtectedRoute>,
                    true,
                  )}
                />
                <Route path="/oauth/callback/:provider" element={page(<OAuthCallbackPage />, true)} />
                <Route
                  path="/oauth2/consent"
                  element={page(
                    <ProtectedRoute>
                      <OAuthConsentPage />
                    </ProtectedRoute>,
                    true,
                  )}
                />
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <AppLayout />
                    </ProtectedRoute>
                  }
                >
                  <Route index element={page(<HomeEntry />)} />
                  <Route path="portal" element={page(<UserPortalPage />)} />
                  <Route path="profile" element={page(<ProfilePage />)} />
                  <Route path="notifications" element={page(<NotificationsPage />)} />
                  <Route path="oauth-apps" element={page(<OAuthAppsPage />)} />
                  <Route
                    path="users"
                    element={page(
                      <CapabilityGuard cap="users:read">
                        <UsersPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="domains"
                    element={page(
                      <CapabilityGuard tiers={['platform_admin']}>
                        <DomainsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="roles"
                    element={page(
                      <CapabilityGuard cap="roles:read">
                        <RolesPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="permissions"
                    element={page(
                      <CapabilityGuard cap="permissions:read">
                        <PermissionsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="jit-grants"
                    element={page(
                      <CapabilityGuard cap="jit:read">
                        <JitGrantsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="sessions"
                    element={page(
                      <CapabilityGuard cap="sessions:read">
                        <SessionsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="risk-events"
                    element={page(
                      <CapabilityGuard cap="risk:read">
                        <RiskEventsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="identity-providers"
                    element={<Navigate to="/plugins?slot=oauth" replace />}
                  />
                  <Route
                    path="plugins"
                    element={page(
                      <CapabilityGuard tiers={['platform_admin']}>
                        <PluginsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="audit-logs"
                    element={page(
                      <CapabilityGuard cap="audit_logs:read">
                        <AuditLogsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="system-settings"
                    element={page(
                      <CapabilityGuard tiers={['platform_admin']}>
                        <SystemSettingsPage />
                      </CapabilityGuard>,
                    )}
                  />
                  <Route
                    path="system-version"
                    element={page(
                      <CapabilityGuard cap="system:read">
                        <SystemVersionPage />
                      </CapabilityGuard>,
                    )}
                  />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </BrowserRouter>
            </ConfirmProvider>
          </AuthProvider>
        </SiteProvider>
      </MotionConfig>
    </ThemeProvider>
  );
};

export default App;
