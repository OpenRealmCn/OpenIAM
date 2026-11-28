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
import { useAuth } from '../context/AuthContext';
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
  allow: '正常放行',
  notify: '风险提醒',
  challenge_mfa: '二次身份验证',
  block: '已拦截',
};

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

  const initialTab = TAB_KEYS.includes(searchParams.get('tab') as TabKey)
    ? (searchParams.get('tab') as TabKey)
    : 'basic';
  const [tab, setTab] = useState<TabKey>(initialTab);

  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 基本资料表单
  const [displayName, setDisplayName] = useState(user?.display_name || '');
  const [avatarUrl, setAvatarUrl] = useState(user?.avatar_url || '');
  const [phone, setPhone] = useState(user?.phone || '');
  const [savingProfile, setSavingProfile] = useState(false);

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
    } catch {
      // ignore
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
    } catch {
      // ignore
    }
  }, []);

  const loadOAuthBindings = useCallback(async () => {
    setLoadingOAuth(true);
    try {
      const [provList, idList] = await Promise.all([api.auth.publicProviders(), api.auth.listIdentities()]);
      setProviders(provList || []);
      setIdentities(idList || []);
    } catch (err) {
      setError((err as Error).message);
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
    setSavingProfile(true);
    try {
      await api.auth.updateProfile({
        display_name: displayName.trim(),
        avatar_url: avatarUrl.trim(),
        phone: phone.trim(),
      });
      await refreshProfile();
      setSuccess('个人资料已更新');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (newPassword.length < 8 || newPassword.length > 72) {
      setError('新密码长度需在 8 到 72 位之间');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致');
      return;
    }
    setChangingPwd(true);
    try {
      await api.auth.changePassword(hasPassword ? oldPassword : '', newPassword);
      setSuccess('密码已更新，即将跳转至登录页以使用新密码重新登录...');
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(async () => {
        await logout();
        navigate('/login', { replace: true });
      }, 1400);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setChangingPwd(false);
    }
  };

  const handleOpenTOTPSetup = async () => {
    setError('');
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
    setError('');
    try {
      const res = await api.auth.totpVerifyBind(totpVerifyCode.trim());
      setRecoveryCodes(res.recovery_codes || []);
      setTotpSetupOpen(false);
      await Promise.all([loadTOTP(), refreshProfile()]);
      setSuccess('已成功启用 TOTP 验证器，请务必妥善保存以下一次性备用恢复码！');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleUnbindTOTP = async () => {
    setError('');
    try {
      await api.auth.totpUnbind({ password: unbindPassword, code: unbindCode });
      setUnbindDialogOpen(false);
      setUnbindPassword('');
      setUnbindCode('');
      setRecoveryCodes([]);
      await Promise.all([loadTOTP(), refreshProfile()]);
      setSuccess('已关闭并解绑 TOTP 验证器');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRegenerateRecovery = () => {
    setRegenCode('');
    setRegenDialogOpen(true);
  };

  const handleConfirmRegenerateRecovery = async () => {
    const code = regenCode.trim();
    if (!code) return;
    setError('');
    try {
      const res = await api.auth.totpRegenerateCodes(code);
      setRecoveryCodes(res.recovery_codes || []);
      setRegenDialogOpen(false);
      setRegenCode('');
      await loadTOTP();
      setSuccess('已重新生成 10 组备用恢复码（旧恢复码已全部作废）');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRegisterPasskey = async () => {
    setError('');
    setSuccess('');
    if (!isWebAuthnSupported()) {
      setError('当前浏览器不支持通行密钥，请使用支持通行密钥的现代浏览器并在 HTTPS 安全连接下访问');
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
      setSuccess('通行密钥绑定成功，下次登录可直接使用通行密钥验证');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRegisteringPasskey(false);
    }
  };

  const handleDeletePasskey = async (pk: UserPasskey) => {
    if (!window.confirm(`确认移除通行密钥「${pk.name}」？移除后该设备将无法免密登录。`)) return;
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
    if (sess.is_current && !window.confirm('确认下线当前正在使用的设备会话？您将需要重新登录。')) return;
    try {
      await api.auth.revokeMySession(sess.session_id);
      if (sess.is_current) {
        await logout();
        navigate('/login', { replace: true });
        return;
      }
      await loadSessions();
      setSuccess('指定设备已下线');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRevokeAllOtherSessions = async () => {
    if (!window.confirm('确认将除当前设备外的所有其他在线设备强制下线？')) return;
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
    if (!window.confirm(`确认解除与「${identity.provider_name}」的账号绑定？`)) return;
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

  const tierLabel =
    adminTier === 'platform_admin'
      ? '平台超级管理员'
      : adminTier === 'domain_admin'
        ? '域管理员'
        : adminTier === 'auditor'
          ? '安全审计员'
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
                  最近登录：{dayjs(user.last_login_at).format('YYYY-MM-DD HH:mm:ss')}
                  {user.last_login_ip ? ` · IP ${user.last_login_ip}` : ''}
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
          <Typography variant="subtitle2" fontWeight={700} mb={1}>
            请保存您的 TOTP 一次性备用恢复码（离开页面后不再完整展示）：
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {recoveryCodes.map((c) => (
              <Chip key={c} label={c} sx={{ fontFamily: 'monospace', fontWeight: 700 }} />
            ))}
          </Stack>
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
          <Tab value="security" icon={<SecurityIcon fontSize="small" />} iconPosition="start" label="密码与多因素认证" />
          <Tab value="sessions" icon={<DeviceIcon fontSize="small" />} iconPosition="start" label="设备与会话" />
          <Tab value="oauth" icon={<LinkIcon fontSize="small" />} iconPosition="start" label="第三方账号" />
          <Tab value="risk" icon={<RiskIcon fontSize="small" />} iconPosition="start" label="安全记录" />
        </Tabs>

        <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
          {tab === 'basic' && (
            <Box component="form" onSubmit={handleSaveProfile} maxWidth={560}>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>
                个人基本信息
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={3}>
                修改您的对外显示名称、手机号与头像地址，保存后立即在全局生效
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
                        ? '仅支持 .png、.ico、.jpg 格式的站内路径（如 /logo.png）或外部 http(s) 图片链接'
                        : '仅支持 .png、.ico、.jpg 格式的外部 http(s) 图片链接，留空将显示首字母头像'}
                    </Typography>
                  </Box>
                </Stack>

                <TextField label="用户名" value={user?.username || ''} disabled size="small" fullWidth helperText="用户名作为唯一账号标识，不支持自助修改" />
                <TextField label="绑定邮箱" value={user?.email || ''} disabled size="small" fullWidth />
                <TextField
                  label="绑定手机号（用于短信验证码与二步验证）"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  size="small"
                  fullWidth
                  placeholder="例如：+8613800138000"
                />
                <TextField label="显示名称" value={displayName} onChange={(e) => setDisplayName(e.target.value)} size="small" fullWidth />
                <TextField label="头像图片 URL" value={avatarUrl} onChange={(e) => setAvatarUrl(e.target.value)} size="small" fullWidth />
                <Box>
                  <Button type="submit" variant="contained" disabled={savingProfile}>
                    {savingProfile ? '保存中...' : '保存个人资料'}
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
                      修改后将注销所有旧设备会话，需要重新登录
                    </Typography>
                    <Box component="form" onSubmit={handleChangePassword}>
                      <Stack spacing={2}>
                        {hasPassword && (
                          <TextField label="当前密码" type="password" size="small" fullWidth required value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} />
                        )}
                        <TextField label="新密码（8 ~ 72 位）" type="password" size="small" fullWidth required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
                        <TextField label="确认新密码" type="password" size="small" fullWidth required value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
                        <Button type="submit" variant="contained" disabled={changingPwd}>
                          {changingPwd ? '提交中...' : '更新密码'}
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
                          验证器 App（TOTP）
                        </Typography>
                      </Stack>
                      <Chip
                        size="small"
                        color={totpStatus.enabled ? 'success' : 'default'}
                        label={totpStatus.enabled ? '已启用' : '未启用'}
                      />
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2.5}>
                      使用 Google / Microsoft Authenticator 等验证器生成 6 位动态口令保护账号安全
                    </Typography>

                    {totpStatus.enabled ? (
                      <Stack spacing={2}>
                        <Alert severity="success" sx={{ py: 0.5 }}>
                          绑定时间：{totpStatus.verified_at ? dayjs(totpStatus.verified_at).format('YYYY-MM-DD HH:mm') : '已验证'}
                          <br />
                          剩余备用恢复码：{totpStatus.remaining_recovery_codes} 组
                        </Alert>
                        <Stack direction="row" spacing={1}>
                          <Button size="small" variant="outlined" startIcon={<RegenIcon />} onClick={handleRegenerateRecovery}>
                            重置恢复码
                          </Button>
                          <Button size="small" color="error" variant="outlined" onClick={() => setUnbindDialogOpen(true)}>
                            解绑验证器
                          </Button>
                        </Stack>
                      </Stack>
                    ) : (
                      <Button variant="contained" startIcon={<TOTPIcon />} onClick={handleOpenTOTPSetup}>
                        立即绑定验证器
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
                      <Button size="small" variant="contained" startIcon={<AddIcon />} onClick={() => setPasskeyDialogOpen(true)}>
                        添加
                      </Button>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                      使用设备指纹、面容或安全密钥免密登录
                    </Typography>

                    {loadingPasskeys ? (
                      <Typography variant="body2" color="text.secondary">加载中...</Typography>
                    ) : passkeys.length === 0 ? (
                      <Box sx={{ py: 3, textAlign: 'center', border: '1px dashed', borderColor: 'divider', borderRadius: 2 }}>
                        <PasskeyIcon sx={{ fontSize: 32, color: 'text.disabled', mb: 0.5 }} />
                        <Typography variant="body2" color="text.secondary">尚未绑定任何通行密钥</Typography>
                      </Box>
                    ) : (
                      <List disablePadding>
                        {passkeys.map((pk, idx) => (
                          <React.Fragment key={pk.id}>
                            {idx > 0 && <Divider />}
                            <ListItem
                              disableGutters
                              secondaryAction={
                                <Tooltip title="移除">
                                  <IconButton edge="end" color="error" size="small" onClick={() => handleDeletePasskey(pk)}>
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
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
                                secondary={`绑定于 ${dayjs(pk.created_at).format('MM-DD HH:mm')}`}
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
                    在线设备与登录会话
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    查看当前账号全部在线设备的 IP、归属地与活跃时间，发现异常可立即踢下线
                  </Typography>
                </Box>
                <Button variant="outlined" color="error" startIcon={<KickIcon />} onClick={handleRevokeAllOtherSessions}>
                  下线其他全部设备
                </Button>
              </Stack>

              {loadingSessions ? (
                <Typography variant="body2" color="text.secondary">加载中...</Typography>
              ) : sessions.length === 0 ? (
                <Alert severity="info">暂无在线设备记录</Alert>
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
                                  {s.device_name || '浏览器设备'}
                                </Typography>
                                {s.is_current && <Chip size="small" color="success" label="当前设备" />}
                              </Stack>
                              <Typography variant="caption" color="text.secondary" display="block">
                                IP：{s.ip_address || '-'} · 地点：{s.location || '未知'} · 最近活跃：{dayjs(s.last_active_at).format('YYYY-MM-DD HH:mm:ss')}
                              </Typography>
                            </Box>
                          </Stack>
                          <Button size="small" color="error" variant="outlined" onClick={() => handleRevokeSession(s)}>
                            {s.is_current ? '退出登录' : '强制下线'}
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
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>第三方账号关联</Typography>
              <Typography variant="body2" color="text.secondary" mb={2.5}>关联外部身份提供商后，可使用对应的第三方账号一键登录平台</Typography>
              {loadingOAuth ? (
                <Typography variant="body2" color="text.secondary">加载中...</Typography>
              ) : providers.length === 0 && identities.length === 0 ? (
                <Alert severity="info">管理员暂未启用任何第三方登录方式</Alert>
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
                              <Button size="small" color="error" variant="outlined" startIcon={<UnlinkIcon />} onClick={() => handleUnbindOAuth(bound)}>
                                解除绑定
                              </Button>
                            ) : (
                              <Button size="small" variant="contained" startIcon={<LinkIcon />} onClick={() => handleBindOAuth(prov.name)}>
                                立即绑定
                              </Button>
                            )}
                          </Stack>
                        </CardContent>
                      </Card>
                    );
                  })}
                </Stack>
              )}
            </Box>
          )}

          {tab === 'risk' && (
            <Box>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>账号异常风险记录</Typography>
              <Typography variant="body2" color="text.secondary" mb={2}>记录近期异地、新设备、非常用时间登录触发的风险自适应评估历史</Typography>
              {riskEvents.length === 0 ? (
                <Alert severity="success">近期账号登录环境均处于低风险安全状态</Alert>
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
                              label={`${(RISK_LEVEL_META[ev.risk_level] || { label: ev.risk_level }).label} · ${ev.risk_score} 分`}
                            />
                            <Typography variant="body2" fontWeight={600}>{ev.location}（{ev.ip_address}）</Typography>
                          </Stack>
                          <Typography variant="caption" color="text.secondary">
                            {dayjs(ev.created_at).format('YYYY-MM-DD HH:mm:ss')} · 处置：{RISK_ACTION_LABELS[ev.action_taken] || ev.action_taken}
                          </Typography>
                        </Stack>
                        <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                          触发原因：{(ev.reasons || []).join('；')}
                        </Typography>
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
      <Dialog open={totpSetupOpen} onClose={() => setTotpSetupOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>绑定 TOTP 验证器</DialogTitle>
        <DialogContent>
          <Stack spacing={2} alignItems="center" mt={1}>
            <Typography variant="body2" color="text.secondary" textAlign="center">
              请使用验证器 App 扫描下方二维码，或手动输入密钥后填写生成的 6 位动态码：
            </Typography>
            {totpQrDataUrl && <Box component="img" src={totpQrDataUrl} alt="TOTP QRCode" sx={{ width: 190, height: 190, borderRadius: 2, border: 1, borderColor: 'divider' }} />}
            <Chip label={totpSecret} sx={{ fontFamily: 'monospace', maxWidth: '100%' }} />
            <TextField
              autoFocus
              fullWidth
              size="small"
              label="6 位动态验证码"
              value={totpVerifyCode}
              onChange={(e) => setTotpVerifyCode(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setTotpSetupOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleVerifyBindTOTP}>验证并启用</Button>
        </DialogActions>
      </Dialog>

      {/* 解绑 TOTP 弹窗 */}
      <Dialog open={unbindDialogOpen} onClose={() => setUnbindDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>解绑 TOTP 验证器</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <Typography variant="body2" color="text.secondary">
              请输入您的登录密码或验证器动态码/恢复码以确认关闭：
            </Typography>
            <TextField label="登录密码（或留空填动态码）" type="password" size="small" fullWidth value={unbindPassword} onChange={(e) => setUnbindPassword(e.target.value)} />
            <TextField label="动态码或备用恢复码" size="small" fullWidth value={unbindCode} onChange={(e) => setUnbindCode(e.target.value)} />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setUnbindDialogOpen(false)}>取消</Button>
          <Button color="error" variant="contained" onClick={handleUnbindTOTP}>确认解绑</Button>
        </DialogActions>
      </Dialog>

      {/* 重新生成备用恢复码弹窗 */}
      <Dialog open={regenDialogOpen} onClose={() => setRegenDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>重新生成备用恢复码</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <Typography variant="body2" color="text.secondary">
              请输入验证器 App 当前显示的 6 位动态验证码，确认后旧恢复码将全部失效。
            </Typography>
            <TextField
              autoFocus
              fullWidth
              size="small"
              label="6 位动态验证码"
              value={regenCode}
              onChange={(e) => setRegenCode(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setRegenDialogOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleConfirmRegenerateRecovery} disabled={!regenCode.trim()}>
            确认生成
          </Button>
        </DialogActions>
      </Dialog>

      {/* 添加通行密钥弹窗 */}
      <Dialog open={passkeyDialogOpen} onClose={() => !registeringPasskey && setPasskeyDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>添加通行密钥</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" mb={2}>
            为当前设备设置一个便于识别的名称，点击确认后浏览器将弹出指纹、面容或安全密钥验证窗口。
          </Typography>
          <TextField autoFocus fullWidth size="small" label="设备名称" placeholder="例如：MacBook Touch ID" value={newPasskeyName} onChange={(e) => setNewPasskeyName(e.target.value)} />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setPasskeyDialogOpen(false)} disabled={registeringPasskey}>取消</Button>
          <Button variant="contained" startIcon={<PasskeyIcon />} onClick={handleRegisterPasskey} disabled={registeringPasskey}>
            {registeringPasskey ? '等待设备验证...' : '开始绑定'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
