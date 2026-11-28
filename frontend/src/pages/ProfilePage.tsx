import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  alpha,
  Avatar,
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
  Grid2 as Grid,
  IconButton,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Stack,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Add as AddIcon,
  Computer as DeviceIcon,
  DeleteOutline as DeleteIcon,
  Fingerprint as PasskeyIcon,
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Link as LinkIcon,
  LinkOff as UnlinkIcon,
  LockReset as PasswordIcon,
  Logout as KickIcon,
  Person as PersonIcon,
  QrCode2 as TOTPIcon,
  Refresh as RegenIcon,
  Security as SecurityIcon,
  Shield as RiskIcon,
  VpnKey as OAuthIcon,
} from '@mui/icons-material';
import QRCode from 'qrcode';
import dayjs from 'dayjs';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { passwordHint, policyFromSite, validatePassword } from '../utils/password';
import {
  PublicProvider,
  RiskEvent,
  TOTPStatus,
  UserIdentity,
  UserPasskey,
  UserSession,
} from '../types/api';
import { createPasskeyCredential, isWebAuthnSupported } from '../utils/webauthn';

const TAB_KEYS = ['basic', 'security', 'sessions', 'oauth', 'risk'] as const;
type TabKey = (typeof TAB_KEYS)[number];
const ALLOWED_AVATAR_EXT_RE = /\.(png|ico|jpg)$/i;

const RISK_LEVEL_META: Record<string, { label: string; color: 'error' | 'warning' | 'default' }> = {
  high: { label: '高风险', color: 'error' },
  medium: { label: '中风险', color: 'warning' },
  low: { label: '低风险', color: 'default' },
};

const RISK_ACTION_LABELS: Record<string, string> = {
  allow: '已放行',
  notify: '已发送提醒',
  challenge_mfa: '已要求两步验证',
  block: '已阻止登录',
};

const LAST_METHOD_HINT = '这是你唯一的登录方式，请先设置登录密码或添加其他登录方式后再移除';

function validateAvatarInput(raw: string, isAdmin: boolean): string {
  const val = raw.trim();
  if (!val) return '';
  if (val.length > 512) return '头像地址长度不能超过 512 个字符';
  if (val.startsWith('/')) {
    if (!isAdmin) {
      return '非管理员禁止使用站内路径，请填写以 .png、.ico 或 .jpg 结尾的外部图片链接';
    }
    if (val.startsWith('//') || val.includes('..')) {
      return '头像站内路径格式无效';
    }
    const cleanPath = val.split(/[?#]/)[0];
    if (!ALLOWED_AVATAR_EXT_RE.test(cleanPath)) {
      return '头像仅支持 .png、.ico、.jpg 格式的图片地址';
    }
    return '';
  }
  try {
    const u = new URL(val);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return '头像地址必须是有效的 http(s) 图片链接';
    }
    if (!ALLOWED_AVATAR_EXT_RE.test(u.pathname)) {
      return '头像仅支持 .png、.ico、.jpg 格式的图片地址';
    }
    return '';
  } catch {
    return '头像地址必须是有效的 http(s) 图片链接';
  }
}

export const ProfilePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user, isAdmin, adminTier, hasPassword, refreshProfile, logout } = useAuth();
  const { siteInfo } = useSite();
  const confirm = useConfirm();
  const pwPolicy = policyFromSite(siteInfo);

  const initialTab = TAB_KEYS.includes(searchParams.get('tab') as TabKey)
    ? (searchParams.get('tab') as TabKey)
    : 'basic';
  const [tab, setTab] = useState<TabKey>(initialTab);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  // 弹窗内的错误单独显示在弹窗里，避免被弹窗遮住看不到。
  const [dialogError, setDialogError] = useState('');
  const [dialogBusy, setDialogBusy] = useState(false);

  // 更换邮箱
  const [emailDialogOpen, setEmailDialogOpen] = useState(false);
  const [emailStep, setEmailStep] = useState<'input' | 'verify'>('input');
  const [newEmail, setNewEmail] = useState('');
  const [emailCode, setEmailCode] = useState('');

  // 基本资料表单
  const [displayName, setDisplayName] = useState(user?.display_name || '');
  const [avatarUrl, setAvatarUrl] = useState(user?.avatar_url || '');
  const [phone, setPhone] = useState(user?.phone || '');
  const [phoneCode, setPhoneCode] = useState('');
  const [phoneCodeCooldown, setPhoneCodeCooldown] = useState(0);
  const [sendingPhoneCode, setSendingPhoneCode] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const phoneChanged = phone.trim() !== (user?.phone || '');

  useEffect(() => {
    if (phoneCodeCooldown <= 0) return;
    const t = setTimeout(() => setPhoneCodeCooldown((n) => n - 1), 1000);
    return () => clearTimeout(t);
  }, [phoneCodeCooldown]);

  // 修改密码表单
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPwd, setChangingPwd] = useState(false);

  // 通行密钥
  const [passkeys, setPasskeys] = useState<UserPasskey[]>([]);
  const [loadingPasskeys, setLoadingPasskeys] = useState(false);
  const [passkeyDialogOpen, setPasskeyDialogOpen] = useState(false);
  const [newPasskeyName, setNewPasskeyName] = useState('');
  const [registeringPasskey, setRegisteringPasskey] = useState(false);

  // TOTP 状态
  const [totpStatus, setTotpStatus] = useState<TOTPStatus>({ enabled: false, verified_at: null, remaining_recovery_codes: 0 });
  const [totpSetupOpen, setTotpSetupOpen] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [totpQrDataUrl, setTotpQrDataUrl] = useState('');
  const [totpVerifyCode, setTotpVerifyCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [unbindDialogOpen, setUnbindDialogOpen] = useState(false);
  const [unbindPassword, setUnbindPassword] = useState('');
  const [unbindCode, setUnbindCode] = useState('');
  const [regenDialogOpen, setRegenDialogOpen] = useState(false);
  const [regenCode, setRegenCode] = useState('');

  // 会话与设备
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(false);

  // 风险安全记录
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [totpLoadFailed, setTotpLoadFailed] = useState(false);
  const [riskLoadFailed, setRiskLoadFailed] = useState(false);

  // 第三方账号绑定
  const [providers, setProviders] = useState<PublicProvider[]>([]);
  const [identities, setIdentities] = useState<UserIdentity[]>([]);
  const [loadingOAuth, setLoadingOAuth] = useState(false);

  useEffect(() => {
    setDisplayName(user?.display_name || '');
    setAvatarUrl(user?.avatar_url || '');
    setPhone(user?.phone || '');
  }, [user]);

  useEffect(() => {
    if (searchParams.get('bound') === '1') {
      setSuccess('第三方账号已成功绑定');
      const next = new URLSearchParams(searchParams);
      next.delete('bound');
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const loadPasskeys = useCallback(async () => {
    setLoadingPasskeys(true);
    try {
      setPasskeys((await api.auth.listPasskeys()) || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingPasskeys(false);
    }
  }, []);

  const loadTOTP = useCallback(async () => {
    try {
      setTotpStatus(await api.auth.totpStatus());
      setTotpLoadFailed(false);
    } catch {
      setTotpLoadFailed(true);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    setLoadingSessions(true);
    try {
      setSessions((await api.auth.mySessions()) || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  const loadRiskEvents = useCallback(async () => {
    try {
      setRiskEvents((await api.auth.myRiskEvents()) || []);
      setRiskLoadFailed(false);
    } catch {
      setRiskLoadFailed(true);
    }
  }, []);

  const loadOAuthBindings = useCallback(async () => {
    setLoadingOAuth(true);
    try {
      const [provRes, idRes] = await Promise.allSettled([api.auth.publicProviders(), api.auth.listIdentities()]);
      setProviders(provRes.status === 'fulfilled' ? provRes.value || [] : []);
      if (idRes.status === 'fulfilled') {
        setIdentities(idRes.value || []);
      } else {
        setError((idRes.reason as Error).message);
      }
    } finally {
      setLoadingOAuth(false);
    }
  }, []);

  useEffect(() => {
    void Promise.all([loadPasskeys(), loadTOTP(), loadSessions(), loadOAuthBindings(), loadRiskEvents()]);
  }, [loadPasskeys, loadTOTP, loadSessions, loadOAuthBindings, loadRiskEvents]);

  const handleTabChange = (_: React.SyntheticEvent, value: TabKey) => {
    setTab(value);
    setError('');
    setSuccess('');
    setSearchParams({ tab: value }, { replace: true });
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    const avatarErr = validateAvatarInput(avatarUrl, isAdmin);
    if (avatarErr) {
      setError(avatarErr);
      return;
    }
    if (phoneChanged && phone.trim() !== '' && !phoneCode.trim()) {
      setError('请先获取并填写新手机号收到的短信验证码');
      return;
    }
    if (phoneChanged && phone.trim() === '' &&
      !(await confirm({
        title: '解除手机号绑定',
        content: '解除后将无法再用手机号登录或接收短信验证码。确定要解除吗？',
        confirmText: '解除绑定',
        danger: true,
      }))) {
      return;
    }
    setSavingProfile(true);
    try {
      await api.auth.updateProfile({
        display_name: displayName.trim(),
        avatar_url: avatarUrl.trim(),
        phone: phone.trim(),
        phone_code: phoneChanged ? phoneCode.trim() : undefined,
      });
      setPhoneCode('');
      await refreshProfile();
      setSuccess('个人资料已更新');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSavingProfile(false);
    }
  };

  const handleSendPhoneCode = async () => {
    setError('');
    setSuccess('');
    setSendingPhoneCode(true);
    try {
      const res = await api.auth.sendPhoneBindCode(phone.trim());
      setSuccess(res?.message || '验证码已发送到新手机号');
      setPhoneCodeCooldown(60);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSendingPhoneCode(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    const pwErr = validatePassword(newPassword, pwPolicy);
    if (pwErr) {
      setError(pwErr);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致');
      return;
    }
    setChangingPwd(true);
    try {
      await api.auth.changePassword(hasPassword ? oldPassword : '', newPassword);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      // 后端已吊销全部会话，直接回登录页，并提示用新密码登录。
      await logout();
      navigate('/login?changed=1', { replace: true });
    } catch (err) {
      setError((err as Error).message);
      setChangingPwd(false);
    }
  };

  const openEmailDialog = () => {
    setEmailStep('input');
    setNewEmail('');
    setEmailCode('');
    setDialogError('');
    setEmailDialogOpen(true);
  };

  const handleSendEmailCode = async () => {
    setDialogError('');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail.trim())) {
      setDialogError('请输入有效的邮箱地址');
      return;
    }
    setDialogBusy(true);
    try {
      await api.auth.sendEmailChangeCode(newEmail.trim());
      setEmailStep('verify');
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setDialogBusy(false);
    }
  };

  const handleConfirmEmailChange = async () => {
    setDialogError('');
    if (emailCode.trim().length !== 6) {
      setDialogError('请输入 6 位验证码');
      return;
    }
    setDialogBusy(true);
    try {
      await api.auth.changeEmail(newEmail.trim(), emailCode.trim());
      setEmailDialogOpen(false);
      await refreshProfile();
      setSuccess('邮箱已更换');
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setDialogBusy(false);
    }
  };

  const handleOpenTOTPSetup = async () => {
    setError('');
    setDialogError('');
    setRecoveryCodes([]);
    setTotpVerifyCode('');
    try {
      const data = await api.auth.totpSetup();
      setTotpSecret(data.secret);
      const qr = await QRCode.toDataURL(data.otpauth_uri, { width: 220, margin: 1 });
      setTotpQrDataUrl(qr);
      setTotpSetupOpen(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleVerifyBindTOTP = async () => {
    setDialogError('');
    if (!/^\d{6}$/.test(totpVerifyCode.trim())) {
      setDialogError('请输入身份验证器上显示的 6 位动态码');
      return;
    }
    setDialogBusy(true);
    try {
      const res = await api.auth.totpVerifyBind(totpVerifyCode.trim());
      setRecoveryCodes(res.recovery_codes || []);
      setTotpSetupOpen(false);
      await Promise.all([loadTOTP(), refreshProfile()]);
      setSuccess('两步验证已开启。请立即保存下方的恢复码，手机丢失时需要用它登录。');
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setDialogBusy(false);
    }
  };

  const handleUnbindTOTP = async () => {
    setDialogError('');
    if (!unbindCode.trim() || (hasPassword && !unbindPassword)) {
      setDialogError(hasPassword ? '请填写登录密码和动态码（或恢复码）' : '请填写动态码或恢复码');
      return;
    }
    setDialogBusy(true);
    try {
      await api.auth.totpUnbind({ password: hasPassword ? unbindPassword : undefined, code: unbindCode.trim() });
      setUnbindDialogOpen(false);
      setUnbindPassword('');
      setUnbindCode('');
      setRecoveryCodes([]);
      await Promise.all([loadTOTP(), refreshProfile()]);
      setSuccess('两步验证已关闭');
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setDialogBusy(false);
    }
  };

  const handleRegenerateRecovery = () => {
    setRegenCode('');
    setDialogError('');
    setRegenDialogOpen(true);
  };

  const handleConfirmRegenerateRecovery = async () => {
    const code = regenCode.trim();
    if (!code) return;
    setDialogError('');
    setDialogBusy(true);
    try {
      const res = await api.auth.totpRegenerateCodes(code);
      setRecoveryCodes(res.recovery_codes || []);
      setRegenDialogOpen(false);
      setRegenCode('');
      await loadTOTP();
      setSuccess('已生成 10 个新的恢复码，旧恢复码已全部失效');
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setDialogBusy(false);
    }
  };

  const handleRegisterPasskey = async () => {
    setDialogError('');
    if (!isWebAuthnSupported()) {
      setDialogError('当前浏览器不支持通行密钥，请换用新版浏览器，并通过 HTTPS 访问本站');
      return;
    }
    setRegisteringPasskey(true);
    try {
      const begin = await api.auth.passkeyRegisterBegin();
      const credential = await createPasskeyCredential(begin.options);
      await api.auth.passkeyRegisterFinish(begin.session_id, newPasskeyName.trim() || '我的设备', credential);
      setPasskeyDialogOpen(false);
      setNewPasskeyName('');
      await Promise.all([loadPasskeys(), refreshProfile()]);
      setSuccess('通行密钥已添加，下次可以直接用它登录');
    } catch (err) {
      const e = err as Error;
      setDialogError(e.name === 'NotAllowedError' ? '已取消或超时，请重试' : e.message);
    } finally {
      setRegisteringPasskey(false);
    }
  };

  const handleDeletePasskey = async (pk: UserPasskey) => {
    if (
      !(await confirm({
        title: '移除通行密钥',
        content: `确定要移除通行密钥「${pk.name}」吗？移除后将无法再用它登录。`,
        confirmText: '移除',
        danger: true,
      }))
    )
      return;
    setError('');
    setSuccess('');
    try {
      await api.auth.deletePasskey(pk.id);
      await Promise.all([loadPasskeys(), refreshProfile()]);
      setSuccess('已移除该通行密钥');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRevokeSession = async (sess: UserSession) => {
    if (
      sess.is_current &&
      !(await confirm({ title: '退出当前设备', content: '确定要退出当前设备的登录吗？退出后需要重新登录。', confirmText: '退出登录' }))
    )
      return;
    try {
      await api.auth.revokeMySession(sess.session_id);
      if (sess.is_current) {
        await logout();
        navigate('/login', { replace: true });
        return;
      }
      await loadSessions();
      setSuccess('该设备已下线');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRevokeAllOtherSessions = async () => {
    if (
      !(await confirm({
        title: '下线其他设备',
        content: '除当前设备外，其他已登录的设备都将退出登录。确定继续吗？',
        confirmText: '全部下线',
        danger: true,
      }))
    )
      return;
    try {
      await api.auth.revokeAllMySessions(true);
      await loadSessions();
      setSuccess('已下线其他所有设备');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleBindOAuth = async (providerName: string) => {
    setError('');
    try {
      const callbackUri = `${window.location.origin}/oauth/callback/${providerName}`;
      localStorage.setItem('openiam_post_login_redirect', '/profile?tab=oauth&bound=1');
      const data = await api.auth.linkIdentity(providerName, callbackUri);
      window.location.href = data.auth_url;
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleUnbindOAuth = async (identity: UserIdentity) => {
    if (
      !(await confirm({
        title: '解除第三方账号绑定',
        content: `确定要解除与「${providerLabel(identity.provider_name)}」账号的绑定吗？解除后将无法再用它登录。`,
        confirmText: '解除绑定',
        danger: true,
      }))
    )
      return;
    setError('');
    setSuccess('');
    try {
      await api.auth.unbindIdentity(identity.id);
      await Promise.all([loadOAuthBindings(), refreshProfile()]);
      setSuccess('已解除第三方账号绑定');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const providerIcon = (pluginType: string) => {
    if (pluginType === 'github') return <GitHubIcon />;
    if (pluginType === 'google') return <GoogleIcon />;
    return <OAuthIcon />;
  };

  function providerLabel(name: string) {
    return providers.find((p) => p.name === name)?.display_name || name;
  }

  // 没有密码时，通行密钥与第三方账号合计只剩一个就是唯一登录方式，不允许移除。
  const isLastLoginMethod = !hasPassword && passkeys.length + identities.length <= 1;
  const orphanIdentities = identities.filter((i) => !providers.some((p) => p.name === i.provider_name));

  const tierLabel =
    adminTier === 'platform_admin'
        ? '平台管理员'
      : adminTier === 'domain_admin'
        ? '域管理员'
        : adminTier === 'auditor'
          ? '审计员'
          : '普通用户';

  const initialChar = (user?.display_name || user?.username || 'U').slice(0, 1).toUpperCase();

  return (
    <Box>
      <Card
        sx={{
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.06)} 100%)`,
        }}
      >
        <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2.5} alignItems={{ xs: 'flex-start', sm: 'center' }}>
            <Avatar
              src={user?.avatar_url || undefined}
              sx={{ width: 64, height: 64, bgcolor: 'primary.main', fontSize: '1.5rem', fontWeight: 700 }}
            >
              {initialChar}
            </Avatar>
            <Box>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                <Typography variant="h5" fontWeight={700}>
                  {user?.display_name || user?.username}
                </Typography>
                <Chip size="small" color={isAdmin ? 'primary' : 'default'} label={tierLabel} />
                {totpStatus.enabled && <Chip size="small" color="success" label="已开启两步验证" />}
              </Stack>
              <Typography variant="body2" color="text.secondary" mt={0.3}>
                @{user?.username} · {user?.email}
                {user?.phone ? ` · ${user.phone}` : ''}
              </Typography>
              {user?.last_login_at && (
                <Typography variant="caption" color="text.secondary">
                  上次登录：{dayjs(user.last_login_at).format('YYYY-MM-DD HH:mm')}
                  {user.last_login_ip ? ` · IP 地址 ${user.last_login_ip}` : ''}
                </Typography>
              )}
            </Box>
          </Stack>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
          {success}
        </Alert>
      )}

      {recoveryCodes.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="subtitle2" fontWeight={700} mb={0.5}>
            请保存以下恢复码
          </Typography>
          <Typography variant="body2" mb={1}>
            手机丢失或无法使用身份验证器时，可用恢复码登录，每个只能用一次。离开本页后将无法再次查看。
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {recoveryCodes.map((c) => (
              <Chip key={c} label={c} sx={{ fontFamily: 'monospace', fontWeight: 700 }} />
            ))}
          </Stack>
          <Button
            size="small"
            sx={{ mt: 1 }}
            onClick={() => {
              void navigator.clipboard?.writeText(recoveryCodes.join('\n')).then(
                () => setSuccess('恢复码已复制'),
                () => setError('复制失败，请手动记录'),
              );
            }}
          >
            复制全部
          </Button>
        </Alert>
      )}

      <Card>
        <Tabs
          value={tab}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab value="basic" icon={<PersonIcon fontSize="small" />} iconPosition="start" label="基本资料" />
          <Tab value="security" icon={<SecurityIcon fontSize="small" />} iconPosition="start" label="密码与两步验证" />
          <Tab value="sessions" icon={<DeviceIcon fontSize="small" />} iconPosition="start" label="设备与会话" />
          <Tab value="oauth" icon={<LinkIcon fontSize="small" />} iconPosition="start" label="第三方账号" />
          <Tab value="risk" icon={<RiskIcon fontSize="small" />} iconPosition="start" label="安全记录" />
        </Tabs>

        <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
          {tab === 'basic' && (
            <Box component="form" onSubmit={handleSaveProfile} maxWidth={560}>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>
                基本资料
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={3}>
                修改显示名称、手机号和头像
              </Typography>

              <Stack spacing={2.5}>
                <Stack direction="row" spacing={2} alignItems="center">
                  <Avatar
                    src={avatarUrl && !validateAvatarInput(avatarUrl, isAdmin) ? avatarUrl.trim() : undefined}
                    sx={{ width: 52, height: 52, bgcolor: 'primary.main', fontWeight: 700 }}
                  >
                    {(displayName || user?.username || 'U').slice(0, 1).toUpperCase()}
                  </Avatar>
                  <Box>
                    <Typography variant="body2" fontWeight={600}>
                      头像预览
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {isAdmin
                        ? '支持 .png、.ico、.jpg 格式的站内路径（如 /logo.png）或 http(s) 图片链接'
                        : '支持 .png、.ico、.jpg 格式的 http(s) 图片链接，留空则显示名称首字'}
                    </Typography>
                  </Box>
                </Stack>

                <TextField label="用户名" value={user?.username || ''} disabled size="small" fullWidth helperText="用户名创建后不可修改" />
                <Stack direction="row" spacing={1} alignItems="flex-start">
                  <TextField
                    label="邮箱"
                    value={user?.email || ''}
                    disabled
                    size="small"
                    fullWidth
                    helperText={siteInfo.smtp_enabled ? undefined : '如需更换邮箱，请联系管理员'}
                  />
                  {siteInfo.smtp_enabled && (
                    <Button variant="outlined" sx={{ whiteSpace: 'nowrap', minWidth: 96 }} onClick={openEmailDialog}>
                      更换邮箱
                    </Button>
                  )}
                </Stack>
                <TextField
                  label="手机号"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  size="small"
                  fullWidth
                  placeholder="例如：+8613800138000"
                  helperText={
                    phoneChanged
                      ? phone.trim() === ''
                        ? '保存后将解除手机号绑定'
                        : '更换手机号需要先验证身份，并填写新手机号收到的验证码'
                      : '用于接收短信验证码'
                  }
                />
                {phoneChanged && phone.trim() !== '' && (
                  <Stack direction="row" spacing={1}>
                    <TextField
                      label="新手机号验证码"
                      value={phoneCode}
                      onChange={(e) => setPhoneCode(e.target.value)}
                      size="small"
                      fullWidth
                      inputMode="numeric"
                    />
                    <Button
                      variant="outlined"
                      sx={{ whiteSpace: 'nowrap', minWidth: 120 }}
                      disabled={phoneCodeCooldown > 0 || sendingPhoneCode}
                      onClick={handleSendPhoneCode}
                    >
                      {phoneCodeCooldown > 0 ? `${phoneCodeCooldown} 秒` : sendingPhoneCode ? '发送中…' : '发送验证码'}
                    </Button>
                  </Stack>
                )}
                <TextField
                  label="显示名称"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  size="small"
                  fullWidth
                  slotProps={{ htmlInput: { maxLength: 64 } }}
                />
                <TextField label="头像地址" value={avatarUrl} onChange={(e) => setAvatarUrl(e.target.value)} size="small" fullWidth />
                <Box>
                  <Button type="submit" variant="contained" disabled={savingProfile}>
                    {savingProfile ? '保存中…' : '保存'}
                  </Button>
                </Box>
              </Stack>
            </Box>
          )}

          {tab === 'security' && (
            <Grid container spacing={3}>
              {/* 修改密码 */}
              <Grid size={{ xs: 12, lg: 4 }}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack direction="row" spacing={1} alignItems="center" mb={0.5}>
                      <PasswordIcon color="primary" fontSize="small" />
                      <Typography variant="subtitle1" fontWeight={600}>
                        {hasPassword ? '修改登录密码' : '设置登录密码'}
                      </Typography>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2.5}>
                      {hasPassword ? '修改后所有设备都会退出登录，需要用新密码重新登录' : '设置密码后可以用用户名或邮箱加密码登录'}
                    </Typography>
                    <Box component="form" onSubmit={handleChangePassword}>
                      <Stack spacing={2}>
                        {hasPassword && (
                          <TextField
                            label="当前密码"
                            type="password"
                            size="small"
                            fullWidth
                            required
                            autoComplete="current-password"
                            value={oldPassword}
                            onChange={(e) => setOldPassword(e.target.value)}
                          />
                        )}
                        <TextField
                          label="新密码"
                          type="password"
                          size="small"
                          fullWidth
                          required
                          autoComplete="new-password"
                          helperText={passwordHint(pwPolicy)}
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                        />
                        <TextField
                          label="确认新密码"
                          type="password"
                          size="small"
                          fullWidth
                          required
                          autoComplete="new-password"
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                        />
                        <Button type="submit" variant="contained" disabled={changingPwd}>
                          {changingPwd ? '提交中…' : hasPassword ? '修改密码' : '设置密码'}
                        </Button>
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              {/* TOTP 验证器 */}
              <Grid size={{ xs: 12, lg: 4 }}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={0.5}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <TOTPIcon color="primary" fontSize="small" />
                        <Typography variant="subtitle1" fontWeight={600}>
                          两步验证
                        </Typography>
                      </Stack>
                      {!totpLoadFailed && (
                        <Chip
                          size="small"
                          color={totpStatus.enabled ? 'success' : 'default'}
                          label={totpStatus.enabled ? '已开启' : '未开启'}
                        />
                      )}
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2.5}>
                      登录时除密码外，还需输入身份验证器（如 Google Authenticator、Microsoft Authenticator）上的 6 位动态码
                    </Typography>

                    {totpLoadFailed ? (
                      <Alert
                        severity="warning"
                        action={
                          <Button color="inherit" size="small" onClick={() => void loadTOTP()}>
                            重试
                          </Button>
                        }
                      >
                        两步验证状态加载失败
                      </Alert>
                    ) : totpStatus.enabled ? (
                      <Stack spacing={2}>
                        <Alert severity={totpStatus.remaining_recovery_codes <= 2 ? 'warning' : 'success'} sx={{ py: 0.5 }}>
                          开启时间：{totpStatus.verified_at ? dayjs(totpStatus.verified_at).format('YYYY-MM-DD HH:mm') : '—'}
                          <br />
                          剩余恢复码：{totpStatus.remaining_recovery_codes} 个
                          {totpStatus.remaining_recovery_codes <= 2 && '，建议重新生成'}
                        </Alert>
                        <Stack direction="row" spacing={1}>
                          <Button size="small" variant="outlined" startIcon={<RegenIcon />} onClick={handleRegenerateRecovery}>
                            重新生成恢复码
                          </Button>
                          <Button
                            size="small"
                            color="error"
                            variant="outlined"
                            onClick={() => {
                              setDialogError('');
                              setUnbindPassword('');
                              setUnbindCode('');
                              setUnbindDialogOpen(true);
                            }}
                          >
                            关闭两步验证
                          </Button>
                        </Stack>
                      </Stack>
                    ) : (
                      <Button variant="contained" startIcon={<TOTPIcon />} onClick={handleOpenTOTPSetup}>
                        开启两步验证
                      </Button>
                    )}
                  </CardContent>
                </Card>
              </Grid>

              {/* 通行密钥 */}
              <Grid size={{ xs: 12, lg: 4 }}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" mb={0.5}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <PasskeyIcon color="primary" fontSize="small" />
                        <Typography variant="subtitle1" fontWeight={600}>
                          通行密钥（Passkey）
                        </Typography>
                      </Stack>
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={<AddIcon />}
                        onClick={() => {
                          setDialogError('');
                          setPasskeyDialogOpen(true);
                        }}
                      >
                        添加
                      </Button>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                      使用指纹、面容或安全密钥登录，无需输入密码
                    </Typography>

                    {loadingPasskeys ? (
                      <Typography variant="body2" color="text.secondary">加载中…</Typography>
                    ) : passkeys.length === 0 ? (
                      <Box sx={{ py: 3, textAlign: 'center', border: '1px dashed', borderColor: 'divider', borderRadius: 2 }}>
                        <PasskeyIcon sx={{ fontSize: 32, color: 'text.disabled', mb: 0.5 }} />
                        <Typography variant="body2" color="text.secondary">还没有添加通行密钥</Typography>
                      </Box>
                    ) : (
                      <List disablePadding>
                        {passkeys.map((pk, idx) => (
                          <React.Fragment key={pk.id}>
                            {idx > 0 && <Divider />}
                            <ListItem
                              disableGutters
                              secondaryAction={
                                <Tooltip title={isLastLoginMethod ? LAST_METHOD_HINT : '移除'}>
                                  <span>
                                    <IconButton
                                      edge="end"
                                      color="error"
                                      size="small"
                                      disabled={isLastLoginMethod}
                                      onClick={() => handleDeletePasskey(pk)}
                                    >
                                      <DeleteIcon fontSize="small" />
                                    </IconButton>
                                  </span>
                                </Tooltip>
                              }
                            >
                              <ListItemAvatar>
                                <Avatar sx={{ bgcolor: alpha(theme.palette.primary.main, 0.12), color: 'primary.main' }}>
                                  <PasskeyIcon fontSize="small" />
                                </Avatar>
                              </ListItemAvatar>
                              <ListItemText
                                primary={pk.name}
                                secondary={`添加于 ${dayjs(pk.created_at).format('YYYY-MM-DD HH:mm')}`}
                              />
                            </ListItem>
                          </React.Fragment>
                        ))}
                      </List>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {tab === 'sessions' && (
            <Box>
              <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
                <Box>
                  <Typography variant="subtitle1" fontWeight={600}>
                    已登录的设备
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    如发现不认识的设备，请立即将其下线并修改密码
                  </Typography>
                </Box>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<KickIcon />}
                  onClick={handleRevokeAllOtherSessions}
                  disabled={!sessions.some((s) => !s.is_current)}
                >
                  下线其他设备
                </Button>
              </Stack>

              {loadingSessions ? (
                <Typography variant="body2" color="text.secondary">加载中…</Typography>
              ) : sessions.length === 0 ? (
                <Alert severity="info">暂无登录设备</Alert>
              ) : (
                <Stack spacing={1.5}>
                  {sessions.map((s) => (
                    <Card key={s.session_id} variant="outlined">
                      <CardContent sx={{ py: 1.8, '&:last-child': { pb: 1.8 } }}>
                        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1.5}>
                          <Stack direction="row" spacing={1.5} alignItems="center">
                            <Avatar sx={{ bgcolor: alpha(theme.palette.primary.main, 0.12), color: 'primary.main' }}>
                              <DeviceIcon fontSize="small" />
                            </Avatar>
                            <Box>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="subtitle2" fontWeight={600}>
                                  {s.device_name || '未知设备'}
                                </Typography>
                                {s.is_current && <Chip size="small" color="success" label="当前设备" />}
                              </Stack>
                              <Typography variant="caption" color="text.secondary" display="block">
                                {s.location || '未知地点'} · IP 地址 {s.ip_address || '—'} · 最近活跃 {dayjs(s.last_active_at).format('YYYY-MM-DD HH:mm')}
                              </Typography>
                            </Box>
                          </Stack>
                          <Button size="small" color="error" variant="outlined" onClick={() => handleRevokeSession(s)}>
                            {s.is_current ? '退出登录' : '下线'}
                          </Button>
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              )}
            </Box>
          )}

          {tab === 'oauth' && (
            <Box>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>第三方账号</Typography>
              <Typography variant="body2" color="text.secondary" mb={2.5}>绑定后可以直接用第三方账号登录</Typography>
              {loadingOAuth ? (
                <Typography variant="body2" color="text.secondary">加载中…</Typography>
              ) : providers.length === 0 && identities.length === 0 ? (
                <Alert severity="info">暂未开放第三方账号登录</Alert>
              ) : (
                <Stack spacing={2}>
                  {providers.map((prov) => {
                    const bound = identities.find((i) => i.provider_name === prov.name);
                    return (
                      <Card key={prov.name} variant="outlined">
                        <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                          <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ xs: 'flex-start', sm: 'center' }} spacing={2}>
                            <Stack direction="row" spacing={1.5} alignItems="center">
                              <Avatar sx={{ bgcolor: alpha(theme.palette.primary.main, 0.12), color: 'primary.main' }}>
                                {providerIcon(prov.plugin_type)}
                              </Avatar>
                              <Box>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <Typography variant="subtitle2" fontWeight={600}>{prov.display_name}</Typography>
                                  <Chip size="small" color={bound ? 'success' : 'default'} variant={bound ? 'filled' : 'outlined'} label={bound ? '已绑定' : '未绑定'} />
                                </Stack>
                                <Typography variant="caption" color="text.secondary">
                                  {bound
                                    ? `${bound.external_username || bound.external_email || bound.external_user_id} · 绑定于 ${dayjs(bound.created_at).format('YYYY-MM-DD HH:mm')}`
                                    : '绑定后可使用该账号快速登录'}
                                </Typography>
                              </Box>
                            </Stack>
                            {bound ? (
                              <Tooltip title={isLastLoginMethod ? LAST_METHOD_HINT : ''}>
                                <span>
                                  <Button
                                    size="small"
                                    color="error"
                                    variant="outlined"
                                    startIcon={<UnlinkIcon />}
                                    disabled={isLastLoginMethod}
                                    onClick={() => handleUnbindOAuth(bound)}
                                  >
                                    解除绑定
                                  </Button>
                                </span>
                              </Tooltip>
                            ) : (
                              <Button size="small" variant="contained" startIcon={<LinkIcon />} onClick={() => handleBindOAuth(prov.name)}>
                                绑定
                              </Button>
                            )}
                          </Stack>
                        </CardContent>
                      </Card>
                    );
                  })}
                  {orphanIdentities.map((idt) => (
                    <Card key={idt.id} variant="outlined">
                      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ xs: 'flex-start', sm: 'center' }} spacing={2}>
                          <Stack direction="row" spacing={1.5} alignItems="center">
                            <Avatar sx={{ bgcolor: 'action.hover', color: 'text.secondary' }}>
                              <OAuthIcon />
                            </Avatar>
                            <Box>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="subtitle2" fontWeight={600}>{idt.provider_name}</Typography>
                                <Chip size="small" variant="outlined" label="已停用" />
                              </Stack>
                              <Typography variant="caption" color="text.secondary">
                                该登录方式已被管理员停用，暂时无法用它登录
                              </Typography>
                            </Box>
                          </Stack>
                          <Tooltip title={isLastLoginMethod ? LAST_METHOD_HINT : ''}>
                            <span>
                              <Button
                                size="small"
                                color="error"
                                variant="outlined"
                                startIcon={<UnlinkIcon />}
                                disabled={isLastLoginMethod}
                                onClick={() => handleUnbindOAuth(idt)}
                              >
                                解除绑定
                              </Button>
                            </span>
                          </Tooltip>
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              )}
            </Box>
          )}

          {tab === 'risk' && (
            <Box>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>异常登录记录</Typography>
              <Typography variant="body2" color="text.secondary" mb={2}>在新设备、不常用地点或异常时间登录时会记录在这里。如不是你本人操作，请立即修改密码</Typography>
              {riskLoadFailed ? (
                <Alert
                  severity="warning"
                  action={
                    <Button color="inherit" size="small" onClick={() => void loadRiskEvents()}>
                      重试
                    </Button>
                  }
                >
                  异常登录记录加载失败
                </Alert>
              ) : riskEvents.length === 0 ? (
                <Alert severity="success">近期没有异常登录</Alert>
              ) : (
                <Stack spacing={1.5}>
                  {riskEvents.map((ev) => (
                    <Card key={ev.id} variant="outlined">
                      <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
                          <Stack direction="row" spacing={1} alignItems="center">
                            <Chip
                              size="small"
                              color={(RISK_LEVEL_META[ev.risk_level] || { color: 'warning' as const }).color}
                              label={(RISK_LEVEL_META[ev.risk_level] || { label: '风险' }).label}
                            />
                            <Typography variant="body2" fontWeight={600}>
                              {ev.location || '未知地点'}（{ev.ip_address}）
                            </Typography>
                          </Stack>
                          <Typography variant="caption" color="text.secondary">
                            {dayjs(ev.created_at).format('YYYY-MM-DD HH:mm')} · {RISK_ACTION_LABELS[ev.action_taken] || ev.action_taken}
                          </Typography>
                        </Stack>
                        {(ev.reasons || []).length > 0 && (
                          <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                            原因：{ev.reasons.join('；')}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      {/* TOTP 绑定弹窗 */}
      <Dialog open={totpSetupOpen} onClose={() => !dialogBusy && setTotpSetupOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>开启两步验证</DialogTitle>
        <DialogContent>
          <Stack spacing={2} alignItems="center" mt={1}>
            {dialogError && (
              <Alert severity="error" sx={{ width: '100%' }}>
                {dialogError}
              </Alert>
            )}
            <Typography variant="body2" color="text.secondary" textAlign="center">
              用身份验证器扫描下方二维码（无法扫码时可手动输入密钥），然后填写它显示的 6 位动态码
            </Typography>
            {totpQrDataUrl && <Box component="img" src={totpQrDataUrl} alt="两步验证二维码" sx={{ width: 190, height: 190, borderRadius: 2, border: 1, borderColor: 'divider' }} />}
            <Chip label={totpSecret} sx={{ fontFamily: 'monospace', maxWidth: '100%' }} />
            <TextField
              autoFocus
              fullWidth
              size="small"
              label="6 位动态码"
              value={totpVerifyCode}
              onChange={(e) => setTotpVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              slotProps={{ htmlInput: { inputMode: 'numeric', autoComplete: 'one-time-code' } }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleVerifyBindTOTP();
              }}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setTotpSetupOpen(false)} disabled={dialogBusy}>取消</Button>
          <Button variant="contained" onClick={handleVerifyBindTOTP} disabled={dialogBusy}>
            {dialogBusy ? '验证中…' : '验证并开启'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 关闭两步验证弹窗 */}
      <Dialog open={unbindDialogOpen} onClose={() => !dialogBusy && setUnbindDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>关闭两步验证</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {dialogError && <Alert severity="error">{dialogError}</Alert>}
            <Typography variant="body2" color="text.secondary">
              {hasPassword
                ? '关闭后登录只需密码，账号安全性会降低。请输入登录密码和动态码（或一个恢复码）确认：'
                : '关闭后账号安全性会降低。请输入动态码或一个恢复码确认：'}
            </Typography>
            {hasPassword && (
              <TextField
                label="登录密码"
                type="password"
                size="small"
                fullWidth
                autoComplete="current-password"
                value={unbindPassword}
                onChange={(e) => setUnbindPassword(e.target.value)}
              />
            )}
            <TextField label="动态码或恢复码" size="small" fullWidth value={unbindCode} onChange={(e) => setUnbindCode(e.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setUnbindDialogOpen(false)} disabled={dialogBusy}>取消</Button>
          <Button color="error" variant="contained" onClick={handleUnbindTOTP} disabled={dialogBusy}>
            {dialogBusy ? '处理中…' : '关闭两步验证'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 重新生成恢复码弹窗 */}
      <Dialog open={regenDialogOpen} onClose={() => !dialogBusy && setRegenDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>重新生成恢复码</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {dialogError && <Alert severity="error">{dialogError}</Alert>}
            <Typography variant="body2" color="text.secondary">
              请输入身份验证器当前显示的 6 位动态码。生成后，旧的恢复码将全部失效。
            </Typography>
            <TextField
              autoFocus
              fullWidth
              size="small"
              label="6 位动态码"
              value={regenCode}
              onChange={(e) => setRegenCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              slotProps={{ htmlInput: { inputMode: 'numeric', autoComplete: 'one-time-code' } }}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setRegenDialogOpen(false)} disabled={dialogBusy}>取消</Button>
          <Button variant="contained" onClick={handleConfirmRegenerateRecovery} disabled={dialogBusy || regenCode.trim().length !== 6}>
            {dialogBusy ? '生成中…' : '生成'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 添加通行密钥弹窗 */}
      <Dialog open={passkeyDialogOpen} onClose={() => !registeringPasskey && setPasskeyDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>添加通行密钥</DialogTitle>
        <DialogContent>
          {dialogError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {dialogError}
            </Alert>
          )}
          <Typography variant="body2" color="text.secondary" mb={2}>
            给这个通行密钥起个名字，方便日后识别。点击“添加”后，按浏览器提示完成指纹、面容或安全密钥验证。
          </Typography>
          <TextField
            autoFocus
            fullWidth
            size="small"
            label="名称"
            placeholder="例如：我的 MacBook"
            value={newPasskeyName}
            onChange={(e) => setNewPasskeyName(e.target.value)}
            slotProps={{ htmlInput: { maxLength: 64 } }}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setPasskeyDialogOpen(false)} disabled={registeringPasskey}>取消</Button>
          <Button variant="contained" startIcon={<PasskeyIcon />} onClick={handleRegisterPasskey} disabled={registeringPasskey}>
            {registeringPasskey ? '等待验证…' : '添加'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 更换邮箱弹窗 */}
      <Dialog open={emailDialogOpen} onClose={() => !dialogBusy && setEmailDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>更换邮箱</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {dialogError && <Alert severity="error">{dialogError}</Alert>}
            {emailStep === 'input' ? (
              <>
                <Typography variant="body2" color="text.secondary">
                  当前邮箱：{user?.email || '—'}。我们会向新邮箱发送一封验证码邮件，原邮箱也会收到更换提醒。
                </Typography>
                <TextField
                  autoFocus
                  fullWidth
                  size="small"
                  type="email"
                  label="新邮箱"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void handleSendEmailCode();
                  }}
                />
              </>
            ) : (
              <>
                <Typography variant="body2" color="text.secondary">
                  验证码已发送到 {newEmail.trim()}，请查收邮件（也可能在垃圾邮件中）。
                </Typography>
                <TextField
                  autoFocus
                  fullWidth
                  size="small"
                  label="6 位验证码"
                  value={emailCode}
                  onChange={(e) => setEmailCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  slotProps={{ htmlInput: { inputMode: 'numeric', autoComplete: 'one-time-code' } }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') void handleConfirmEmailChange();
                  }}
                />
                <Box>
                  <Button size="small" onClick={() => setEmailStep('input')} disabled={dialogBusy}>
                    修改邮箱地址或重新发送
                  </Button>
                </Box>
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setEmailDialogOpen(false)} disabled={dialogBusy}>取消</Button>
          {emailStep === 'input' ? (
            <Button variant="contained" onClick={handleSendEmailCode} disabled={dialogBusy || !newEmail.trim()}>
              {dialogBusy ? '发送中…' : '发送验证码'}
            </Button>
          ) : (
            <Button variant="contained" onClick={handleConfirmEmailChange} disabled={dialogBusy}>
              {dialogBusy ? '提交中…' : '确认更换'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};
