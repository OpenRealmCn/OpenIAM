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
  DeleteOutline as DeleteIcon,
  Fingerprint as PasskeyIcon,
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  Link as LinkIcon,
  LinkOff as UnlinkIcon,
  LockReset as PasswordIcon,
  Person as PersonIcon,
  Save as SaveIcon,
  Security as SecurityIcon,
  VpnKey as OAuthIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { PublicProvider, UserIdentity, UserPasskey } from '../types/api';
import { createPasskeyCredential, isWebAuthnSupported } from '../utils/webauthn';

const TAB_KEYS = ['basic', 'security', 'oauth'] as const;
type TabKey = (typeof TAB_KEYS)[number];

const ALLOWED_AVATAR_EXT_RE = /\.(png|ico|jpg)$/i;

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
  const { user, isAdmin, hasPassword, refreshProfile, logout } = useAuth();

  const initialTab = TAB_KEYS.includes(searchParams.get('tab') as TabKey)
    ? (searchParams.get('tab') as TabKey)
    : 'basic';
  const [tab, setTab] = useState<TabKey>(initialTab);

  // 全局反馈
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 基本资料表单
  const [displayName, setDisplayName] = useState(user?.display_name || '');
  const [avatarUrl, setAvatarUrl] = useState(user?.avatar_url || '');
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

  // 第三方账号绑定
  const [providers, setProviders] = useState<PublicProvider[]>([]);
  const [identities, setIdentities] = useState<UserIdentity[]>([]);
  const [loadingOAuth, setLoadingOAuth] = useState(false);

  useEffect(() => {
    setDisplayName(user?.display_name || '');
    setAvatarUrl(user?.avatar_url || '');
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
      const list = await api.auth.listPasskeys();
      setPasskeys(list || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingPasskeys(false);
    }
  }, []);

  const loadOAuthBindings = useCallback(async () => {
    setLoadingOAuth(true);
    try {
      const [provList, idList] = await Promise.all([
        api.auth.publicProviders(),
        api.auth.listIdentities(),
      ]);
      setProviders(provList || []);
      setIdentities(idList || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingOAuth(false);
    }
  }, []);

  useEffect(() => {
    loadPasskeys();
    loadOAuthBindings();
  }, [loadPasskeys, loadOAuthBindings]);

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

  const handleRegisterPasskey = async () => {
    setError('');
    setSuccess('');
    if (!isWebAuthnSupported()) {
      setError('当前浏览器不支持通行密钥，请使用现代浏览器或在 HTTPS / localhost 环境下访问');
      return;
    }
    setRegisteringPasskey(true);
    try {
      const begin = await api.auth.passkeyRegisterBegin();
      const credential = await createPasskeyCredential(begin.options);
      await api.auth.passkeyRegisterFinish(
        begin.session_id,
        newPasskeyName.trim() || '我的设备',
        credential,
      );
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

  const initialChar = (user?.display_name || user?.username || 'U').slice(0, 1).toUpperCase();

  return (
    <Box>
      {/* 头部个人名片 */}
      <Card
        sx={{
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.06)} 100%)`,
        }}
      >
        <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
          <Stack
            direction={{ xs: 'column', sm: 'row' }}
            spacing={2.5}
            alignItems={{ xs: 'flex-start', sm: 'center' }}
            justifyContent="space-between"
          >
            <Stack direction="row" spacing={2} alignItems="center">
              <Avatar
                src={user?.avatar_url || undefined}
                sx={{
                  width: 64,
                  height: 64,
                  bgcolor: 'primary.main',
                  fontSize: '1.5rem',
                  fontWeight: 700,
                }}
              >
                {initialChar}
              </Avatar>
              <Box>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                  <Typography variant="h5" fontWeight={700}>
                    {user?.display_name || user?.username}
                  </Typography>
                  <Chip
                    size="small"
                    color={isAdmin ? 'primary' : 'default'}
                    label={isAdmin ? '管理员' : '普通用户'}
                  />
                </Stack>
                <Typography variant="body2" color="text.secondary" mt={0.3}>
                  @{user?.username} · {user?.email}
                </Typography>
                {user?.last_login_at && (
                  <Typography variant="caption" color="text.secondary">
                    最近登录：{dayjs(user.last_login_at).format('YYYY-MM-DD HH:mm:ss')}
                    {user.last_login_ip ? ` · IP ${user.last_login_ip}` : ''}
                  </Typography>
                )}
              </Box>
            </Stack>
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

      <Card>
        <Tabs
          value={tab}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab value="basic" icon={<PersonIcon fontSize="small" />} iconPosition="start" label="基本资料" />
          <Tab value="security" icon={<SecurityIcon fontSize="small" />} iconPosition="start" label="密码与通行密钥" />
          <Tab value="oauth" icon={<LinkIcon fontSize="small" />} iconPosition="start" label="第三方账号" />
        </Tabs>

        <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
          {/* Tab 1: 基本资料 */}
          {tab === 'basic' && (
            <Box component="form" onSubmit={handleSaveProfile} maxWidth={560}>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>
                个人基本信息
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={3}>
                修改您的对外显示名称与头像地址，保存后立即在全局生效
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
                        ? '仅支持 .png、.ico、.jpg 格式的站内路径（如 /logo.png）或外部 http(s) 图片链接，留空将显示首字母头像'
                        : '仅支持 .png、.ico、.jpg 格式的外部 http(s) 图片链接，留空将显示首字母头像'}
                    </Typography>
                  </Box>
                </Stack>

                <TextField
                  label="用户名"
                  value={user?.username || ''}
                  disabled
                  size="small"
                  fullWidth
                  helperText="用户名作为唯一账号标识，不支持自助修改"
                />
                <TextField
                  label="绑定邮箱"
                  value={user?.email || ''}
                  disabled
                  size="small"
                  fullWidth
                />
                <TextField
                  label="显示名称"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  size="small"
                  fullWidth
                  placeholder="请输入您的显示名称"
                />
                <TextField
                  label="头像图片 URL"
                  value={avatarUrl}
                  onChange={(e) => setAvatarUrl(e.target.value)}
                  size="small"
                  fullWidth
                  placeholder="https://example.com/avatar.png"
                />
                <Box>
                  <Button
                    type="submit"
                    variant="contained"
                    startIcon={<SaveIcon />}
                    disabled={savingProfile}
                  >
                    {savingProfile ? '保存中...' : '保存个人资料'}
                  </Button>
                </Box>
              </Stack>
            </Box>
          )}

          {/* Tab 2: 密码与通行密钥 */}
          {tab === 'security' && (
            <Grid container spacing={3}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack direction="row" spacing={1} alignItems="center" mb={0.5}>
                      <PasswordIcon color="primary" fontSize="small" />
                      <Typography variant="subtitle1" fontWeight={600}>
                        {hasPassword ? '修改登录密码' : '设置登录密码'}
                      </Typography>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2.5}>
                      {hasPassword
                        ? '修改密码后将自动注销所有旧设备会话，需要重新登录'
                        : '当前账号尚未设置本地密码，设置后可使用用户名与密码登录'}
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
                          helperText="密码长度需为 8 ~ 72 位"
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                        />
                        <TextField
                          label="确认新密码"
                          type="password"
                          size="small"
                          fullWidth
                          required
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                        />
                        <Box>
                          <Button type="submit" variant="contained" disabled={changingPwd}>
                            {changingPwd ? '提交中...' : hasPassword ? '更新密码' : '设置密码'}
                          </Button>
                        </Box>
                      </Stack>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid size={{ xs: 12, md: 6 }}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack
                      direction="row"
                      justifyContent="space-between"
                      alignItems="center"
                      mb={0.5}
                    >
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
                        onClick={() => setPasskeyDialogOpen(true)}
                      >
                        添加通行密钥
                      </Button>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                      使用设备指纹、面容识别或硬件安全密钥免密登录，更安全防钓鱼
                    </Typography>

                    {!isWebAuthnSupported() && (
                      <Alert severity="warning" sx={{ mb: 2 }}>
                        当前浏览器或访问协议不支持通行密钥（需 HTTPS 或 localhost 环境）
                      </Alert>
                    )}

                    {loadingPasskeys ? (
                      <Typography variant="body2" color="text.secondary" py={2}>
                        加载中...
                      </Typography>
                    ) : passkeys.length === 0 ? (
                      <Box
                        sx={{
                          py: 4,
                          textAlign: 'center',
                          border: '1px dashed',
                          borderColor: 'divider',
                          borderRadius: 2,
                        }}
                      >
                        <PasskeyIcon sx={{ fontSize: 36, color: 'text.disabled', mb: 1 }} />
                        <Typography variant="body2" color="text.secondary">
                          尚未绑定任何通行密钥
                        </Typography>
                      </Box>
                    ) : (
                      <List disablePadding>
                        {passkeys.map((pk, idx) => (
                          <React.Fragment key={pk.id}>
                            {idx > 0 && <Divider />}
                            <ListItem
                              disableGutters
                              secondaryAction={
                                <Tooltip title="移除通行密钥">
                                  <IconButton
                                    edge="end"
                                    color="error"
                                    size="small"
                                    onClick={() => handleDeletePasskey(pk)}
                                  >
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
                                secondary={
                                  <>
                                    绑定于 {dayjs(pk.created_at).format('YYYY-MM-DD HH:mm')}
                                    {pk.last_used_at
                                      ? ` · 最近使用 ${dayjs(pk.last_used_at).format('YYYY-MM-DD HH:mm')}`
                                      : ' · 尚未使用'}
                                  </>
                                }
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

          {/* Tab 3: 第三方账号 */}
          {tab === 'oauth' && (
            <Box>
              <Typography variant="subtitle1" fontWeight={600} mb={0.5}>
                第三方账号关联
              </Typography>
              <Typography variant="body2" color="text.secondary" mb={2.5}>
                关联外部身份提供商后，可使用对应的第三方账号一键登录平台
              </Typography>

              {loadingOAuth ? (
                <Typography variant="body2" color="text.secondary">
                  加载中...
                </Typography>
              ) : providers.length === 0 && identities.length === 0 ? (
                <Alert severity="info">管理员暂未启用任何第三方登录方式</Alert>
              ) : (
                <Stack spacing={2}>
                  {providers.map((prov) => {
                    const bound = identities.find((i) => i.provider_name === prov.name);
                    return (
                      <Card key={prov.name} variant="outlined">
                        <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                          <Stack
                            direction={{ xs: 'column', sm: 'row' }}
                            justifyContent="space-between"
                            alignItems={{ xs: 'flex-start', sm: 'center' }}
                            spacing={2}
                          >
                            <Stack direction="row" spacing={1.5} alignItems="center">
                              <Avatar
                                sx={{
                                  bgcolor: alpha(theme.palette.primary.main, 0.12),
                                  color: 'primary.main',
                                }}
                              >
                                {providerIcon(prov.plugin_type)}
                              </Avatar>
                              <Box>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <Typography variant="subtitle2" fontWeight={600}>
                                    {prov.display_name}
                                  </Typography>
                                  <Chip
                                    size="small"
                                    color={bound ? 'success' : 'default'}
                                    variant={bound ? 'filled' : 'outlined'}
                                    label={bound ? '已绑定' : '未绑定'}
                                  />
                                </Stack>
                                <Typography variant="caption" color="text.secondary">
                                  {bound
                                    ? `${bound.external_username || bound.external_email || bound.external_user_id} · 绑定于 ${dayjs(bound.created_at).format('YYYY-MM-DD HH:mm')}`
                                    : '绑定后可使用该账号快速登录'}
                                </Typography>
                              </Box>
                            </Stack>

                            {bound ? (
                              <Button
                                size="small"
                                color="error"
                                variant="outlined"
                                startIcon={<UnlinkIcon />}
                                onClick={() => handleUnbindOAuth(bound)}
                              >
                                解除绑定
                              </Button>
                            ) : (
                              <Button
                                size="small"
                                variant="contained"
                                startIcon={<LinkIcon />}
                                onClick={() => handleBindOAuth(prov.name)}
                              >
                                立即绑定
                              </Button>
                            )}
                          </Stack>
                        </CardContent>
                      </Card>
                    );
                  })}

                  {/* 展示历史已绑定但当前已被管理员禁用的提供方，允许解绑 */}
                  {identities
                    .filter((id) => !providers.some((p) => p.name === id.provider_name))
                    .map((orphan) => (
                      <Card key={orphan.id} variant="outlined">
                        <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Box>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="subtitle2" fontWeight={600}>
                                  {orphan.provider_name}
                                </Typography>
                                <Chip size="small" label="提供方已停用" />
                              </Stack>
                              <Typography variant="caption" color="text.secondary">
                                {orphan.external_username || orphan.external_email || orphan.external_user_id}
                              </Typography>
                            </Box>
                            <Button
                              size="small"
                              color="error"
                              variant="outlined"
                              startIcon={<UnlinkIcon />}
                              onClick={() => handleUnbindOAuth(orphan)}
                            >
                              解除绑定
                            </Button>
                          </Stack>
                        </CardContent>
                      </Card>
                    ))}
                </Stack>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      {/* 添加通行密钥弹窗 */}
      <Dialog
        open={passkeyDialogOpen}
        onClose={() => !registeringPasskey && setPasskeyDialogOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>添加通行密钥</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" mb={2}>
            为当前设备设置一个便于识别的名称，点击确认后浏览器将弹出指纹、面容或安全密钥验证窗口。
          </Typography>
          <TextField
            autoFocus
            fullWidth
            size="small"
            label="设备名称"
            placeholder="例如：MacBook Touch ID / Windows Hello"
            value={newPasskeyName}
            onChange={(e) => setNewPasskeyName(e.target.value)}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setPasskeyDialogOpen(false)} disabled={registeringPasskey}>
            取消
          </Button>
          <Button
            variant="contained"
            startIcon={<PasskeyIcon />}
            onClick={handleRegisterPasskey}
            disabled={registeringPasskey}
          >
            {registeringPasskey ? '等待设备验证...' : '开始绑定'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
