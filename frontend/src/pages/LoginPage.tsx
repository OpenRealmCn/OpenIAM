import React, { useEffect, useState } from 'react';
import {
  Alert,
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
        background: 'linear-gradient(135deg, #0F172A 0%, #1E3A8A 55%, #0284C7 100%)',
      }}
    >
      <Card sx={{ width: '100%', maxWidth: 440, p: 1 }}>
        <CardContent sx={{ p: 3 }}>
          <Stack direction="row" spacing={1.5} alignItems="center" mb={2.5}>
            <Box
              sx={{
                width: 44,
                height: 44,
                borderRadius: 2.5,
                bgcolor: 'primary.main',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <ShieldIcon />
            </Box>
            <Box>
              <Typography variant="h5">OpenIAM</Typography>
              <Typography variant="body2" color="text.secondary">
                OpenRealm 私有身份与访问管理平台
              </Typography>
            </Box>
          </Stack>

          <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="fullWidth" sx={{ mb: 2.5 }}>
            <Tab label="账号登录" value="login" />
            <Tab label="注册账号" value="register" />
          </Tabs>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          {successMsg && (
            <Alert severity="success" sx={{ mb: 2 }}>
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
            默认初始管理员: admin / Admin@123456
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};
