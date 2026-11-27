import React, { useEffect, useState } from 'react';
import {
  Alert,
  alpha,
  Box,
  Button,
  Card,
  CardContent,
  Divider,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import {
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Login as LoginIcon,
  VerifiedUser as ShieldIcon,
  VpnKey as OAuthIcon,
} from '@mui/icons-material';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { PublicProvider } from '../types/api';

export const LoginPage: React.FC = () => {
  const theme = useTheme();
  const [tab, setTab] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [providers, setProviders] = useState<PublicProvider[]>([]);

  const { loginWithCredentials } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirectTarget = searchParams.get('redirect') || '/';

  useEffect(() => {
    api.auth
      .publicProviders()
      .then((res) => setProviders(res || []))
      .catch(() => setProviders([]));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setSubmitting(true);
    try {
      if (tab === 'login') {
        await loginWithCredentials(username, password);
        navigate(redirectTarget, { replace: true });
      } else {
        await api.auth.register({ username, email, password, display_name: displayName });
        setSuccessMsg('注册成功，请使用账号密码登录');
        setTab('login');
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleOAuthLogin = async (providerName: string) => {
    setError('');
    try {
      const callbackUri = `${window.location.origin}/oauth/callback/${providerName}`;
      localStorage.setItem('openiam_post_login_redirect', redirectTarget);
      const data = await api.auth.oauthAuthorize(providerName, callbackUri);
      window.location.href = data.auth_url;
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const providerIcon = (pluginType: string) => {
    if (pluginType === 'github') return <GitHubIcon />;
    if (pluginType === 'google') return <GoogleIcon />;
    return <OAuthIcon />;
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2,
        bgcolor: 'background.default',
        backgroundImage: `radial-gradient(at 15% 20%, ${alpha(theme.palette.primary.main, 0.14)} 0px, transparent 50%), radial-gradient(at 85% 80%, ${alpha(theme.palette.secondary.main, 0.12)} 0px, transparent 50%)`,
      }}
    >
      <Card
        sx={{
          width: '100%',
          maxWidth: 430,
          bgcolor: alpha(theme.palette.background.paper, 0.92),
          backdropFilter: 'blur(16px)',
          boxShadow:
            theme.palette.mode === 'dark'
              ? '0 24px 64px rgba(0, 0, 0, 0.55)'
              : '0 20px 50px rgba(15, 23, 42, 0.08)',
        }}
      >
        <CardContent sx={{ p: 4 }}>
          <Stack spacing={1.5} alignItems="center" textAlign="center" mb={3}>
            <Box
              sx={{
                width: 52,
                height: 52,
                borderRadius: 3,
                background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: `0 8px 20px ${alpha(theme.palette.primary.main, 0.35)}`,
              }}
            >
              <ShieldIcon fontSize="medium" />
            </Box>
            <Box>
              <Typography variant="h5">OpenIAM</Typography>
              <Typography variant="body2" color="text.secondary" mt={0.3}>
                OpenRealm 统一身份与访问管理平台
              </Typography>
            </Box>
          </Stack>

          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            variant="fullWidth"
            sx={{
              mb: 2.5,
              borderRadius: 2.5,
              bgcolor: alpha(theme.palette.text.primary, 0.04),
              p: 0.4,
              '& .MuiTabs-indicator': { display: 'none' },
              '& .MuiTab-root': { borderRadius: 2, minHeight: 38 },
              '& .Mui-selected': {
                bgcolor: 'background.paper',
                boxShadow: '0 1px 4px rgba(15,23,42,0.08)',
              },
            }}
          >
            <Tab label="账号登录" value="login" />
            <Tab label="注册账号" value="register" />
          </Tabs>

          {error && (
            <Alert severity="error" sx={{ mb: 2, borderRadius: 2 }}>
              {error}
            </Alert>
          )}
          {successMsg && (
            <Alert severity="success" sx={{ mb: 2, borderRadius: 2 }}>
              {successMsg}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit}>
            <Stack spacing={2}>
              <TextField
                label={tab === 'login' ? '用户名或邮箱' : '用户名'}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                fullWidth
                size="small"
              />
              {tab === 'register' && (
                <>
                  <TextField
                    label="邮箱"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    fullWidth
                    size="small"
                  />
                  <TextField
                    label="显示名称"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    fullWidth
                    size="small"
                  />
                </>
              )}
              <TextField
                label="密码"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                fullWidth
                size="small"
              />
              <Button
                type="submit"
                variant="contained"
                size="large"
                disabled={submitting}
                startIcon={<LoginIcon />}
                fullWidth
                sx={{ py: 1.15 }}
              >
                {submitting ? '处理中...' : tab === 'login' ? '登 录' : '注 册'}
              </Button>
            </Stack>
          </Box>

          {providers.length > 0 && (
            <>
              <Divider sx={{ my: 2.5 }}>
                <Typography variant="caption" color="text.secondary">
                  第三方联合登录
                </Typography>
              </Divider>
              <Stack spacing={1.2}>
                {providers.map((p) => (
                  <Button
                    key={p.name}
                    variant="outlined"
                    fullWidth
                    startIcon={providerIcon(p.plugin_type)}
                    onClick={() => handleOAuthLogin(p.name)}
                  >
                    使用 {p.display_name} 登录
                  </Button>
                ))}
              </Stack>
            </>
          )}

          <Typography variant="caption" color="text.secondary" display="block" textAlign="center" mt={2.5}>
            © {new Date().getFullYear()} OpenRealm · OpenIAM
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};
