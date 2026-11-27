import React, { useMemo, useState } from 'react';
import { CssBaseline, ThemeProvider } from '@mui/material';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import { AuthProvider } from './context/AuthContext';
import { buildOpenIAMTheme, ThemePresetKey } from './theme/theme';
import { AppLayout } from './components/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
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
  const [mode, setMode] = useState<'light' | 'dark'>(
    () => (localStorage.getItem('openiam_theme_mode') as 'light' | 'dark') || 'light',
  );
  const [preset, setPreset] = useState<ThemePresetKey>(
    () => (localStorage.getItem('openiam_theme_preset') as ThemePresetKey) || 'cloudBlue',
  );

  const theme = useMemo(() => buildOpenIAMTheme(mode, preset), [mode, preset]);

  const toggleMode = () => {
    setMode((prev) => {
      const next = prev === 'light' ? 'dark' : 'light';
      localStorage.setItem('openiam_theme_mode', next);
      return next;
    });
  };

  const changePreset = (next: ThemePresetKey) => {
    setPreset(next);
    localStorage.setItem('openiam_theme_preset', next);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
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
                  <AppLayout
                    mode={mode}
                    preset={preset}
                    onToggleMode={toggleMode}
                    onChangePreset={changePreset}
                  />
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
    </ThemeProvider>
  );
};

export default App;
