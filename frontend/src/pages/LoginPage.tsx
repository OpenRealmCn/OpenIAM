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
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import {
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Login as LoginIcon,
  PersonAdd as RegisterIcon,
  VerifiedUser as ShieldIcon,
  VpnKey as OAuthIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { PublicProvider } from '../types/api';

const MotionBox = motion.create(Box);

export const LoginPage: React.FC = () => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

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

  // 从改密页回来时给一条明确的成功提示，避免用户以为没保存成功。
  useEffect(() => {
    if (searchParams.get('changed')) {
      setSuccessMsg('密码已修改，请使用新密码重新登录');
    }
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setSubmitting(true);
    try {
      if (tab === 'login') {
        const forced = await loginWithCredentials(username, password);
        navigate(forced ? '/change-password' : redirectTarget, { replace: true });
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

  const radius = Number(theme.shape.borderRadius);
  const springTransition =
    scale === 0
      ? { duration: 0 }
      : { type: 'spring' as const, stiffness: 380 / scale, damping: 32, mass: 0.9 };

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
      <MotionBox
        layout
        initial={{ opacity: 0, y: 18, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={springTransition}
        sx={{ width: '100%', maxWidth: 430 }}
      >
        <Card
          sx={{
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
                  borderRadius: `${Math.max(6, radius)}px`,
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

            {/* 灵动弹性滑动胶囊 Tabs */}
            <Box
              sx={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                p: 0.5,
                mb: 2.5,
                borderRadius: `${Math.max(4, radius - 2)}px`,
                bgcolor: alpha(theme.palette.text.primary, 0.05),
                position: 'relative',
              }}
            >
              {(['login', 'register'] as const).map((item) => {
                const active = tab === item;
                return (
                  <Box
                    key={item}
                    onClick={() => {
                      setTab(item);
                      setError('');
                    }}
                    sx={{
                      position: 'relative',
                      py: 0.95,
                      textAlign: 'center',
                      cursor: 'pointer',
                      userSelect: 'none',
                      zIndex: 1,
                    }}
                  >
                    {active && (
                      <MotionBox
                        layoutId="auth-tab-pill"
                        transition={springTransition}
                        sx={{
                          position: 'absolute',
                          inset: 0,
                          borderRadius: `${Math.max(3, radius - 4)}px`,
                          bgcolor: 'background.paper',
                          boxShadow:
                            theme.palette.mode === 'dark'
                              ? '0 2px 8px rgba(0,0,0,0.45)'
                              : '0 2px 8px rgba(15,23,42,0.08)',
                          zIndex: -1,
                        }}
                      />
                    )}
                    <Typography
                      variant="body2"
                      fontWeight={active ? 600 : 500}
                      color={active ? 'primary.main' : 'text.secondary'}
                    >
                      {item === 'login' ? '账号登录' : '注册账号'}
                    </Typography>
                  </Box>
                );
              })}
            </Box>

            <AnimatePresence mode="popLayout">
              {error && (
                <MotionBox
                  key="error"
                  initial={{ opacity: 0, y: -6, height: 0 }}
                  animate={{ opacity: 1, y: 0, height: 'auto' }}
                  exit={{ opacity: 0, y: -6, height: 0 }}
                  transition={springTransition}
                  sx={{ mb: 2, overflow: 'hidden' }}
                >
                  <Alert severity="error">{error}</Alert>
                </MotionBox>
              )}
              {successMsg && (
                <MotionBox
                  key="success"
                  initial={{ opacity: 0, y: -6, height: 0 }}
                  animate={{ opacity: 1, y: 0, height: 'auto' }}
                  exit={{ opacity: 0, y: -6, height: 0 }}
                  transition={springTransition}
                  sx={{ mb: 2, overflow: 'hidden' }}
                >
                  <Alert severity="success">{successMsg}</Alert>
                </MotionBox>
              )}
            </AnimatePresence>

            <Box component="form" onSubmit={handleSubmit}>
              <Stack spacing={2}>
                <MotionBox layout transition={springTransition}>
                  <TextField
                    label={tab === 'login' ? '用户名或邮箱' : '用户名'}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    fullWidth
                    size="small"
                  />
                </MotionBox>

                <AnimatePresence initial={false}>
                  {tab === 'register' && (
                    <MotionBox
                      key="register-fields"
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={springTransition}
                      sx={{ overflow: 'hidden' }}
                    >
                      <Stack spacing={2} sx={{ pt: 0.5 }}>
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
                      </Stack>
                    </MotionBox>
                  )}
                </AnimatePresence>

                <MotionBox layout transition={springTransition}>
                  <TextField
                    label="密码"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    fullWidth
                    size="small"
                  />
                </MotionBox>

                <MotionBox
                  layout
                  transition={springTransition}
                  whileHover={scale === 0 ? undefined : { y: -1.5 }}
                  whileTap={scale === 0 ? undefined : { scale: 0.985 }}
                >
                  <Button
                    type="submit"
                    variant="contained"
                    size="large"
                    disabled={submitting}
                    startIcon={tab === 'login' ? <LoginIcon /> : <RegisterIcon />}
                    fullWidth
                    sx={{ py: 1.15 }}
                  >
                    {submitting ? '处理中...' : tab === 'login' ? '登 录' : '注 册'}
                  </Button>
                </MotionBox>
              </Stack>
            </Box>

            {providers.length > 0 && (
              <MotionBox layout transition={springTransition}>
                <Divider sx={{ my: 2.5 }}>
                  <Typography variant="caption" color="text.secondary">
                    第三方登录
                  </Typography>
                </Divider>
                <Stack spacing={1.2}>
                  {providers.map((p) => (
                    <MotionBox
                      key={p.name}
                      whileHover={scale === 0 ? undefined : { y: -1 }}
                      whileTap={scale === 0 ? undefined : { scale: 0.985 }}
                    >
                      <Button
                        variant="outlined"
                        fullWidth
                        startIcon={providerIcon(p.plugin_type)}
                        onClick={() => handleOAuthLogin(p.name)}
                      >
                        使用 {p.display_name} 登录
                      </Button>
                    </MotionBox>
                  ))}
                </Stack>
              </MotionBox>
            )}

            <Typography variant="caption" color="text.secondary" display="block" textAlign="center" mt={2.5}>
              © {new Date().getFullYear()} OpenRealm · OpenIAM
            </Typography>
          </CardContent>
        </Card>
      </MotionBox>
    </Box>
  );
};
