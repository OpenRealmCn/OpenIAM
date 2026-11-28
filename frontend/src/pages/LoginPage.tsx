import React, { useEffect, useState } from 'react';
import {
  Alert,
  AlertTitle,
  alpha,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  Link,
  Radio,
  RadioGroup,
  Stack,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Fingerprint as PasskeyIcon,
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Login as LoginIcon,
  PersonAdd as RegisterIcon,
  Send as SendIcon,
  Shield as RiskIcon,
  VerifiedUser as ShieldIcon,
  VpnKey as OAuthIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { CapWidget } from '../components/CapWidget';
import { LoginStepResult, useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { PublicProvider } from '../types/api';
import { getPasskeyAssertion, isWebAuthnSupported } from '../utils/webauthn';

const MotionBox = motion.create(Box);

const MFA_METHOD_LABELS: Record<string, string> = {
  totp: '验证器动态码（TOTP）',
  recovery_code: '备用一次性恢复码',
  email_otp: '邮箱安全验证码',
  sms_otp: '手机短信验证码',
};

export const LoginPage: React.FC = () => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const { siteInfo } = useSite();

  const [tab, setTab] = useState<'login' | 'otp' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [emailCode, setEmailCode] = useState('');
  const [smsCode, setSmsCode] = useState('');
  const [regEmailCooldown, setRegEmailCooldown] = useState(0);
  const [regSmsCooldown, setRegSmsCooldown] = useState(0);
  const [regSendingChannel, setRegSendingChannel] = useState<'email' | 'sms' | null>(null);
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaReset, setCaptchaReset] = useState(0);

  // OTP 验证码登录状态
  const [otpChannel, setOtpChannel] = useState<'email' | 'sms'>('email');
  const [otpTarget, setOtpTarget] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpCooldown, setOtpCooldown] = useState(0);
  const [otpSending, setOtpSending] = useState(false);

  // MFA 二步验证状态
  const [mfaChallenge, setMfaChallenge] = useState<LoginStepResult | null>(null);
  const [mfaMethod, setMfaMethod] = useState<string>('totp');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaSendCooldown, setMfaSendCooldown] = useState(0);

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

  useEffect(() => {
    if (otpCooldown <= 0) return;
    const t = setTimeout(() => setOtpCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [otpCooldown]);

  useEffect(() => {
    if (mfaSendCooldown <= 0) return;
    const t = setTimeout(() => setMfaSendCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [mfaSendCooldown]);

  useEffect(() => {
    if (regEmailCooldown <= 0) return;
    const t = setTimeout(() => setRegEmailCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [regEmailCooldown]);

  useEffect(() => {
    if (regSmsCooldown <= 0) return;
    const t = setTimeout(() => setRegSmsCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [regSmsCooldown]);

  const registerVerifyMode = siteInfo.register_verify_mode || 'none';
  const showRegisterEmail =
    (siteInfo.register_email_mode || 'required') !== 'disabled' ||
    registerVerifyMode === 'email' ||
    registerVerifyMode === 'both' ||
    registerVerifyMode === 'either';
  const requireRegisterEmail =
    siteInfo.register_email_mode === 'required' ||
    registerVerifyMode === 'email' ||
    registerVerifyMode === 'both';
  const showRegisterPhone =
    (siteInfo.register_phone_mode || 'disabled') !== 'disabled' ||
    registerVerifyMode === 'sms' ||
    registerVerifyMode === 'both' ||
    registerVerifyMode === 'either';
  const requireRegisterPhone =
    siteInfo.register_phone_mode === 'required' ||
    registerVerifyMode === 'sms' ||
    registerVerifyMode === 'both';
  const needEmailVerify =
    registerVerifyMode === 'email' || registerVerifyMode === 'both' || registerVerifyMode === 'either';
  const needSmsVerify =
    registerVerifyMode === 'sms' || registerVerifyMode === 'both' || registerVerifyMode === 'either';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setSubmitting(true);
    try {
      if (tab === 'login') {
        const res = await loginWithCredentials(username, password, captchaToken);
        if (res.mfaRequired && res.mfaToken) {
          setMfaChallenge(res);
          setMfaMethod(res.methods?.[0] || 'totp');
          setMfaCode('');
          return;
        }
        navigate(res.mustChangePassword ? '/change-password' : redirectTarget, { replace: true });
      } else if (tab === 'otp') {
        const data = await api.auth.otpLogin({ target: otpTarget.trim(), code: otpCode.trim(), captcha_token: captchaToken });
        await completeOAuthLogin(data.access_token);
        navigate(redirectTarget, { replace: true });
      } else {
        await api.auth.register({
          username,
          email: showRegisterEmail ? email.trim() : undefined,
          phone: showRegisterPhone ? phone.trim() : undefined,
          password,
          display_name: displayName,
          email_code: needEmailVerify ? emailCode.trim() : undefined,
          sms_code: needSmsVerify ? smsCode.trim() : undefined,
          captcha_token: captchaToken,
        });
        setSuccessMsg('注册成功，请使用账号密码登录');
        setEmailCode('');
        setSmsCode('');
        setTab('login');
        setCaptchaReset((n) => n + 1);
      }
    } catch (err) {
      setError((err as Error).message);
      setCaptchaReset((n) => n + 1);
    } finally {
      setSubmitting(false);
    }
  };

  const handleSendRegisterOTP = async (channel: 'email' | 'sms') => {
    setError('');
    setSuccessMsg('');
    const target = (channel === 'email' ? email : phone).trim();
    if (!target) {
      setError(channel === 'email' ? '请先输入注册邮箱' : '请先输入注册手机号');
      return;
    }
    setRegSendingChannel(channel);
    try {
      const res = await api.auth.sendOTP({
        scene: 'register',
        channel,
        target,
        captcha_token: captchaToken,
      });
      setSuccessMsg(res?.message || '注册验证码已发送，请注意查收');
      if (channel === 'email') {
        setRegEmailCooldown(60);
      } else {
        setRegSmsCooldown(60);
      }
      setCaptchaReset((n) => n + 1);
    } catch (err) {
      setError((err as Error).message);
      setCaptchaReset((n) => n + 1);
    } finally {
      setRegSendingChannel(null);
    }
  };

  const handleSendLoginOTP = async () => {
    setError('');
    setSuccessMsg('');
    if (!otpTarget.trim()) {
      setError(otpChannel === 'sms' ? '请输入绑定手机号' : '请输入绑定邮箱');
      return;
    }
    setOtpSending(true);
    try {
      const res = await api.auth.sendOTP({
        scene: 'login',
        channel: otpChannel,
        target: otpTarget.trim(),
        captcha_token: captchaToken,
      });
      setSuccessMsg(res?.message || '验证码已发送');
      setOtpCooldown(60);
      setCaptchaReset((n) => n + 1);
    } catch (err) {
      setError((err as Error).message);
      setCaptchaReset((n) => n + 1);
    } finally {
      setOtpSending(false);
    }
  };

  const handleSendMFACode = async (channel: 'sms' | 'email') => {
    if (!mfaChallenge?.mfaToken) return;
    setError('');
    setSuccessMsg('');
    try {
      const res = await api.auth.sendMFACode(mfaChallenge.mfaToken, channel);
      setSuccessMsg(res?.message || '验证码已发送');
      setMfaSendCooldown(60);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleVerifyMFA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaChallenge?.mfaToken) return;
    setError('');
    setSubmitting(true);
    try {
      const data = await api.auth.verifyMFA({
        mfa_token: mfaChallenge.mfaToken,
        method: mfaMethod,
        code: mfaCode.trim(),
      });
      await completeOAuthLogin(data.access_token);
      navigate(redirectTarget, { replace: true });
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

  const visibleTabs: ('login' | 'otp' | 'register')[] = siteInfo.allow_public_register
    ? ['login', 'otp', 'register']
    : ['login', 'otp'];

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
        sx={{ width: '100%', maxWidth: 450 }}
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

            {mfaChallenge ? (
              /* MFA 二步验证视图（含风险提示） */
              <Box component="form" onSubmit={handleVerifyMFA}>
                <Stack spacing={2}>
                  <Alert
                    severity={mfaChallenge.riskLevel === 'high' ? 'warning' : 'info'}
                    icon={<RiskIcon fontSize="small" />}
                  >
                    <AlertTitle>
                      {mfaChallenge.riskLevel === 'high' ? '高风险登录二次安全验证' : '多因素身份验证'}
                    </AlertTitle>
                    {mfaChallenge.riskReasons && mfaChallenge.riskReasons.length > 0
                      ? `检测到环境风险：${mfaChallenge.riskReasons.join('；')}。请完成二次身份校验。`
                      : '该账号已开启多因素认证，请完成二次校验后继续登录。'}
                  </Alert>

                  {error && <Alert severity="error">{error}</Alert>}
                  {successMsg && <Alert severity="success">{successMsg}</Alert>}

                  <RadioGroup
                    value={mfaMethod}
                    onChange={(e) => {
                      setMfaMethod(e.target.value);
                      setError('');
                    }}
                  >
                    {(mfaChallenge.methods || []).map((m) => (
                      <FormControlLabel
                        key={m}
                        value={m}
                        control={<Radio size="small" />}
                        label={
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Typography variant="body2">{MFA_METHOD_LABELS[m] || m}</Typography>
                            {m === 'email_otp' && mfaChallenge.emailHint && (
                              <Chip size="small" label={mfaChallenge.emailHint} />
                            )}
                            {m === 'sms_otp' && mfaChallenge.phoneHint && (
                              <Chip size="small" label={mfaChallenge.phoneHint} />
                            )}
                          </Stack>
                        }
                      />
                    ))}
                  </RadioGroup>

                  {(mfaMethod === 'email_otp' || mfaMethod === 'sms_otp') && (
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<SendIcon />}
                      disabled={mfaSendCooldown > 0}
                      onClick={() => handleSendMFACode(mfaMethod === 'sms_otp' ? 'sms' : 'email')}
                    >
                      {mfaSendCooldown > 0 ? `${mfaSendCooldown} 秒后可重发` : '发送一次性验证码'}
                    </Button>
                  )}

                  <TextField
                    label={mfaMethod === 'recovery_code' ? '8 位备用恢复码' : '6 位动态验证码'}
                    size="small"
                    fullWidth
                    required
                    autoFocus
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                  />

                  <Button type="submit" variant="contained" size="large" disabled={submitting} fullWidth>
                    {submitting ? '验证中...' : '完成验证并登录'}
                  </Button>

                  <Button
                    size="small"
                    startIcon={<BackIcon />}
                    onClick={() => {
                      setMfaChallenge(null);
                      setError('');
                      setSuccessMsg('');
                    }}
                  >
                    返回重新登录
                  </Button>
                </Stack>
              </Box>
            ) : (
              <>
                {/* 灵动弹性滑动胶囊 Tabs */}
                <Box
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: `repeat(${visibleTabs.length}, 1fr)`,
                    p: 0.5,
                    mb: 2.5,
                    borderRadius: `${Math.max(4, radius - 2)}px`,
                    bgcolor: alpha(theme.palette.text.primary, 0.05),
                    position: 'relative',
                  }}
                >
                  {visibleTabs.map((item) => {
                    const active = tab === item;
                    return (
                      <Box
                        key={item}
                        onClick={() => {
                          setTab(item);
                          setError('');
                          setSuccessMsg('');
                        }}
                        sx={{
                          position: 'relative',
                          py: 0.9,
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
                          {item === 'login' ? '密码登录' : item === 'otp' ? '验证码登录' : '注册账号'}
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
                    {tab === 'otp' ? (
                      <>
                        <Stack direction="row" spacing={1}>
                          <Chip
                            label="邮箱验证码"
                            color={otpChannel === 'email' ? 'primary' : 'default'}
                            variant={otpChannel === 'email' ? 'filled' : 'outlined'}
                            onClick={() => setOtpChannel('email')}
                          />
                          <Chip
                            label="手机短信验证码"
                            color={otpChannel === 'sms' ? 'primary' : 'default'}
                            variant={otpChannel === 'sms' ? 'filled' : 'outlined'}
                            onClick={() => setOtpChannel('sms')}
                          />
                        </Stack>
                        <TextField
                          label={otpChannel === 'sms' ? '绑定手机号' : '绑定邮箱'}
                          value={otpTarget}
                          onChange={(e) => setOtpTarget(e.target.value)}
                          required
                          fullWidth
                          size="small"
                        />
                        <Stack direction="row" spacing={1}>
                          <TextField
                            label="6 位验证码"
                            value={otpCode}
                            onChange={(e) => setOtpCode(e.target.value)}
                            required
                            fullWidth
                            size="small"
                          />
                          <Button
                            variant="outlined"
                            onClick={handleSendLoginOTP}
                            disabled={otpSending || otpCooldown > 0}
                            sx={{ whiteSpace: 'nowrap', minWidth: 112 }}
                          >
                            {otpCooldown > 0 ? `${otpCooldown}s` : otpSending ? '发送中' : '获取验证码'}
                          </Button>
                        </Stack>
                        <CapWidget scene="otp" onToken={setCaptchaToken} resetSignal={captchaReset} />
                      </>
                    ) : (
                      <>
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
                                {registerVerifyMode === 'either' && (
                                  <Alert severity="info" sx={{ py: 0.3 }}>
                                    请至少填写邮箱或手机号并完成对应验证码校验
                                  </Alert>
                                )}
                                {showRegisterEmail && (
                                  <>
                                    <TextField
                                      label={requireRegisterEmail ? '邮箱' : '邮箱（选填）'}
                                      type="email"
                                      value={email}
                                      onChange={(e) => setEmail(e.target.value)}
                                      required={requireRegisterEmail}
                                      fullWidth
                                      size="small"
                                    />
                                    {needEmailVerify && (
                                      <Stack direction="row" spacing={1}>
                                        <TextField
                                          label="6 位邮箱验证码"
                                          value={emailCode}
                                          onChange={(e) => setEmailCode(e.target.value)}
                                          required={registerVerifyMode === 'email' || registerVerifyMode === 'both'}
                                          fullWidth
                                          size="small"
                                        />
                                        <Button
                                          variant="outlined"
                                          onClick={() => handleSendRegisterOTP('email')}
                                          disabled={regSendingChannel === 'email' || regEmailCooldown > 0}
                                          sx={{ whiteSpace: 'nowrap', minWidth: 112 }}
                                        >
                                          {regEmailCooldown > 0
                                            ? `${regEmailCooldown}s`
                                            : regSendingChannel === 'email'
                                              ? '发送中'
                                              : '获取验证码'}
                                        </Button>
                                      </Stack>
                                    )}
                                  </>
                                )}
                                {showRegisterPhone && (
                                  <>
                                    <TextField
                                      label={requireRegisterPhone ? '手机号' : '手机号（选填）'}
                                      value={phone}
                                      placeholder="如 +8613800138000 或 13800138000"
                                      onChange={(e) => setPhone(e.target.value)}
                                      required={requireRegisterPhone}
                                      fullWidth
                                      size="small"
                                    />
                                    {needSmsVerify && (
                                      <Stack direction="row" spacing={1}>
                                        <TextField
                                          label="6 位短信验证码"
                                          value={smsCode}
                                          onChange={(e) => setSmsCode(e.target.value)}
                                          required={registerVerifyMode === 'sms' || registerVerifyMode === 'both'}
                                          fullWidth
                                          size="small"
                                        />
                                        <Button
                                          variant="outlined"
                                          onClick={() => handleSendRegisterOTP('sms')}
                                          disabled={regSendingChannel === 'sms' || regSmsCooldown > 0}
                                          sx={{ whiteSpace: 'nowrap', minWidth: 112 }}
                                        >
                                          {regSmsCooldown > 0
                                            ? `${regSmsCooldown}s`
                                            : regSendingChannel === 'sms'
                                              ? '发送中'
                                              : '获取验证码'}
                                        </Button>
                                      </Stack>
                                    )}
                                  </>
                                )}
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

                        {/* Cap.js 人机验证插件插槽 */}
                        <CapWidget
                          scene={tab === 'register' ? 'register' : 'login'}
                          onToken={setCaptchaToken}
                          resetSignal={captchaReset}
                        />
                      </>
                    )}

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
                        startIcon={tab === 'register' ? <RegisterIcon /> : <LoginIcon />}
                        fullWidth
                        sx={{ py: 1.15 }}
                      >
                        {submitting ? '处理中...' : tab === 'register' ? '注 册' : '登 录'}
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
              </>
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
                <Alert severity="info">验证码已发送至 {resetEmail}，请在 10 分钟内完成验证。</Alert>
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
