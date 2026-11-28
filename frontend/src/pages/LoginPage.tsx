import React, { useEffect, useState } from 'react';
import {
  Alert,
  AlertTitle,
  alpha,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Link,
  Stack,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Fingerprint as PasskeyIcon,
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
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { PublicProvider } from '../types/api';
import { getPasskeyAssertion, isWebAuthnSupported } from '../utils/webauthn';

const MotionBox = motion.create(Box);

export const LoginPage: React.FC = () => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const { siteInfo } = useSite();

  const [tab, setTab] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [providers, setProviders] = useState<PublicProvider[]>([]);
  const [logoError, setLogoError] = useState(false);

  // 忘记密码弹窗状态
  const [resetOpen, setResetOpen] = useState(false);
  const [resetStep, setResetStep] = useState<'email' | 'confirm'>('email');
  const [resetEmail, setResetEmail] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [resetPassword, setResetPassword] = useState('');
  const [resetBusy, setResetBusy] = useState(false);
  const [resetError, setResetError] = useState('');

  const { loginWithCredentials, completeOAuthLogin } = useAuth();
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

  useEffect(() => {
    if (!siteInfo.allow_public_register && tab === 'register') {
      setTab('login');
    }
  }, [siteInfo.allow_public_register, tab]);

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

  const handlePasskeyLogin = async () => {
    setError('');
    setSuccessMsg('');
    if (!isWebAuthnSupported()) {
      setError('当前浏览器不支持通行密钥登录');
      return;
    }
    setPasskeyLoading(true);
    try {
      const begin = await api.auth.passkeyLoginBegin(username.trim());
      const assertion = await getPasskeyAssertion(begin.options);
      const data = await api.auth.passkeyLoginFinish(begin.session_id, assertion);
      await completeOAuthLogin(data.access_token);
      navigate(redirectTarget, { replace: true });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPasskeyLoading(false);
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

  const handleSendResetCode = async () => {
    setResetError('');
    if (!resetEmail.trim()) {
      setResetError('请输入注册邮箱');
      return;
    }
    setResetBusy(true);
    try {
      await api.auth.requestPasswordReset(resetEmail.trim());
      setResetStep('confirm');
    } catch (err) {
      setResetError((err as Error).message);
    } finally {
      setResetBusy(false);
    }
  };

  const handleConfirmReset = async () => {
    setResetError('');
    if (resetCode.trim().length !== 6) {
      setResetError('请输入 6 位邮箱验证码');
      return;
    }
    if (resetPassword.length < 8 || resetPassword.length > 72) {
      setResetError('新密码长度需在 8 ~ 72 位之间');
      return;
    }
    setResetBusy(true);
    try {
      await api.auth.confirmPasswordReset({
        email: resetEmail.trim(),
        code: resetCode.trim(),
        new_password: resetPassword,
      });
      setResetOpen(false);
      setResetStep('email');
      setResetCode('');
      setResetPassword('');
      setSuccessMsg('密码已重置，请使用新密码登录');
    } catch (err) {
      setResetError((err as Error).message);
    } finally {
      setResetBusy(false);
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
        sx={{ width: '100%', maxWidth: 440 }}
      >
        {siteInfo.announcement_enabled && siteInfo.announcement_content && (
          <Alert severity={siteInfo.announcement_type || 'info'} sx={{ mb: 2 }}>
            {siteInfo.announcement_title && <AlertTitle>{siteInfo.announcement_title}</AlertTitle>}
            {siteInfo.announcement_content}
          </Alert>
        )}

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
          <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
            <Stack spacing={1.5} alignItems="center" textAlign="center" mb={3}>
              {siteInfo.logo_url && !logoError ? (
                <Box
                  component="img"
                  src={siteInfo.logo_url}
                  alt={siteInfo.name}
                  onError={() => setLogoError(true)}
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: `${Math.max(6, radius)}px`,
                    objectFit: 'contain',
                  }}
                />
              ) : (
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
              )}
              <Box>
                <Typography variant="h5" fontWeight={700}>
                  {siteInfo.name || 'OpenIAM'}
                </Typography>
                <Typography variant="body2" color="text.secondary" mt={0.3}>
                  {siteInfo.subtitle || '统一身份与访问管理平台'}
                </Typography>
              </Box>
            </Stack>

            {/* 灵动弹性滑动胶囊 Tabs */}
            {siteInfo.allow_public_register && (
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
            )}

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
                  {tab === 'login' && siteInfo.smtp_enabled && (
                    <Box sx={{ textAlign: 'right', mt: 0.5 }}>
                      <Link
                        component="button"
                        type="button"
                        variant="caption"
                        underline="hover"
                        onClick={() => {
                          setResetError('');
                          setResetStep('email');
                          setResetOpen(true);
                        }}
                      >
                        忘记密码？
                      </Link>
                    </Box>
                  )}
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

                {tab === 'login' && isWebAuthnSupported() && (
                  <MotionBox
                    layout
                    transition={springTransition}
                    whileHover={scale === 0 ? undefined : { y: -1 }}
                    whileTap={scale === 0 ? undefined : { scale: 0.985 }}
                  >
                    <Button
                      type="button"
                      variant="outlined"
                      fullWidth
                      disabled={passkeyLoading}
                      startIcon={<PasskeyIcon />}
                      onClick={handlePasskeyLogin}
                    >
                      {passkeyLoading ? '等待设备验证...' : '使用通行密钥登录'}
                    </Button>
                  </MotionBox>
                )}
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
              {siteInfo.footer_text || `© ${new Date().getFullYear()} OpenRealm · OpenIAM`}
            </Typography>
          </CardContent>
        </Card>
      </MotionBox>

      {/* 忘记密码弹窗 */}
      <Dialog open={resetOpen} onClose={() => !resetBusy && setResetOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>通过邮箱重置密码</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {resetError && <Alert severity="error">{resetError}</Alert>}
            {resetStep === 'email' ? (
              <>
                <Typography variant="body2" color="text.secondary">
                  请输入您的账号绑定邮箱，系统将发送 6 位一次性验证码。
                </Typography>
                <TextField
                  label="绑定邮箱"
                  type="email"
                  size="small"
                  fullWidth
                  autoFocus
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                />
              </>
            ) : (
              <>
                <Alert severity="info">
                  验证码已发送至 {resetEmail}，请在 10 分钟内完成验证。
                </Alert>
                <TextField
                  label="6 位验证码"
                  size="small"
                  fullWidth
                  value={resetCode}
                  onChange={(e) => setResetCode(e.target.value)}
                />
                <TextField
                  label="新密码（8 ~ 72 位）"
                  type="password"
                  size="small"
                  fullWidth
                  value={resetPassword}
                  onChange={(e) => setResetPassword(e.target.value)}
                />
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setResetOpen(false)} disabled={resetBusy}>
            取消
          </Button>
          {resetStep === 'email' ? (
            <Button variant="contained" onClick={handleSendResetCode} disabled={resetBusy}>
              {resetBusy ? '发送中...' : '发送验证码'}
            </Button>
          ) : (
            <Button variant="contained" onClick={handleConfirmReset} disabled={resetBusy}>
              {resetBusy ? '提交中...' : '确认重置密码'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};
