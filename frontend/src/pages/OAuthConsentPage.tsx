import React, { useEffect, useRef, useState } from 'react';
import {
  Alert,
  alpha,
  Avatar,
  Box,
  Button,
  Stack,
  Typography,
  useTheme,
} from '@mui/material';
import {
  AccessTimeRounded as OfflineIcon,
  AppsRounded as AppIcon,
  BadgeRounded as ProfileIcon,
  CancelOutlined as DenyIcon,
  CheckCircleRounded as AllowIcon,
  EmailRounded as EmailIcon,
  FingerprintRounded as IdentityIcon,
  LockRounded as LockIcon,
  PhoneAndroidRounded as PhoneIcon,
  SecurityRounded as RoleIcon,
  VerifiedUserRounded as ShieldIcon,
} from '@mui/icons-material';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { HandshakeStatus, IdentityHandshakeDiagram, OAuthBackdrop } from '../components/OAuthAuthStage';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { isSafeClientRedirect } from '../utils/redirect';

const SCOPE_META: Record<string, { label: string; icon: React.ReactNode }> = {
  openid: { label: '确认你的唯一身份标识', icon: <IdentityIcon fontSize="small" /> },
  profile: { label: '读取你的显示名称和头像', icon: <ProfileIcon fontSize="small" /> },
  email: { label: '读取你的绑定邮箱地址', icon: <EmailIcon fontSize="small" /> },
  phone: { label: '读取你的绑定手机号', icon: <PhoneIcon fontSize="small" /> },
  offline_access: { label: '在你未打开应用时保持访问', icon: <OfflineIcon fontSize="small" /> },
  roles: { label: '读取你在所属域中的角色', icon: <RoleIcon fontSize="small" /> },
};

function redirectHost(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return uri;
  }
}

interface ConsentData {
  id: string;
  client_id: string;
  client_name: string;
  domain_code: string;
  redirect_uri: string;
  scopes: string[];
}

type ConsentPhase = 'loading' | 'ready' | 'approving' | 'approved' | 'denying' | 'error';

export const OAuthConsentPage: React.FC = () => {
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  const requestId = searchParams.get('request_id') || '';
  const { user } = useAuth();
  const { siteInfo } = useSite();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  const [consent, setConsent] = useState<ConsentData | null>(null);
  const [phase, setPhase] = useState<ConsentPhase>('loading');
  const [error, setError] = useState('');
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!requestId) {
      setError('授权链接无效，请返回应用重新登录');
      setPhase('error');
      return;
    }
    setPhase('loading');
    api.oauth2Server
      .getConsent(requestId)
      .then((data) => {
        if (!mountedRef.current) return;
        setConsent(data);
        setPhase('ready');
      })
      .catch((err) => {
        if (!mountedRef.current) return;
        setError((err as Error).message);
        setPhase('error');
      });
  }, [requestId]);

  const sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      if (scale === 0 || ms <= 0) {
        resolve();
        return;
      }
      setTimeout(resolve, Math.round(ms * scale));
    });

  const handleDecision = async (approved: boolean) => {
    setError('');
    setPhase(approved ? 'approving' : 'denying');
    try {
      const res = await api.oauth2Server.submitConsent(requestId, approved);
      if (!isSafeClientRedirect(res.redirect_uri)) {
        throw new Error('该应用的回调地址不安全，已阻止跳转，请联系应用管理员');
      }
      if (!mountedRef.current) return;
      if (approved) {
        setPhase('approved');
        await sleep(420);
      }
      window.location.href = res.redirect_uri;
    } catch (err) {
      if (!mountedRef.current) return;
      setError((err as Error).message);
      setPhase(consent ? 'ready' : 'error');
    }
  };

  const initialChar = (user?.display_name || user?.username || 'U').slice(0, 1).toUpperCase();
  const targetAppInitial = (consent?.client_name || 'A').slice(0, 1).toUpperCase();
  const targetHost = consent ? redirectHost(consent.redirect_uri) : '应用回调地址';

  const handshakeStatus: HandshakeStatus =
    phase === 'loading' || phase === 'approving' || phase === 'denying'
      ? 'verifying'
      : phase === 'approved'
        ? 'success'
        : phase === 'error'
          ? 'error'
          : 'idle';

  const busy = phase === 'approving' || phase === 'approved' || phase === 'denying';
  const appName = consent?.client_name || '该应用';

  const buttonSx = {
    py: 1.15,
    borderRadius: '12px',
    touchAction: 'manipulation',
    transition: 'transform 160ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 160ms ease',
    '&:active': { transform: 'scale(0.98)', transitionDuration: '0s' },
  };

  return (
    <OAuthBackdrop maxWidth={440}>
      <Stack spacing={2.75}>
        <Box>
          <Typography variant="h5" fontWeight={700} letterSpacing="-0.03em">
            {phase === 'error'
              ? '无法完成授权'
              : phase === 'loading'
                ? '确认登录请求'
                : phase === 'denying'
                  ? '正在返回应用'
                  : `允许 ${appName} 登录`}
          </Typography>
          <Typography variant="body2" color="text.secondary" mt={0.6}>
            {phase === 'approved'
              ? `正在返回 ${appName}`
              : phase === 'approving'
                ? '正在签发授权码'
                : phase === 'denying'
                  ? `正在返回 ${targetHost}`
                  : phase === 'loading'
                    ? '正在确认这次登录请求'
                    : `将使用你的 ${siteInfo.name || 'OpenIAM'} 账号，并获得下面这些权限`}
          </Typography>
        </Box>

        <IdentityHandshakeDiagram
          status={handshakeStatus}
          leftNode={{
            label: siteInfo.name || 'OpenIAM',
            subLabel: '身份认证',
            accent: theme.palette.primary.main,
            icon: siteInfo.logo_url ? (
              <Box
                component="img"
                src={siteInfo.logo_url}
                alt=""
                sx={{ width: 28, height: 28, objectFit: 'contain' }}
              />
            ) : (
              <ShieldIcon />
            ),
          }}
          rightNode={{
            label: consent?.client_name || '接入应用',
            subLabel: consent ? consent.domain_code : '确认中',
            accent: theme.palette.primary.main,
            icon: consent?.client_name ? (
              <Typography fontWeight={700} fontSize="1.25rem" color="primary.main">
                {targetAppInitial}
              </Typography>
            ) : (
              <AppIcon />
            ),
          }}
        />

        {phase === 'error' && <Alert severity="error">{error || '授权请求无效或已过期，请返回应用重试'}</Alert>}

        {consent && phase !== 'error' && (
          <Stack spacing={2.25}>
            {error && (
              <Alert severity="error" onClose={() => setError('')}>
                {error}
              </Alert>
            )}

            <Stack direction="row" spacing={1.25} alignItems="center">
              <Avatar
                src={user?.avatar_url || undefined}
                sx={{ width: 40, height: 40, bgcolor: 'primary.main', fontWeight: 700 }}
              >
                {initialChar}
              </Avatar>
              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography variant="body2" fontWeight={700} noWrap>
                  {user?.display_name || user?.username}
                </Typography>
                <Typography variant="caption" color="text.secondary" noWrap display="block">
                  @{user?.username}
                  {user?.email ? ` · ${user.email}` : ''}
                </Typography>
              </Box>
              <Typography variant="caption" color="success.main" fontWeight={600} sx={{ flexShrink: 0 }}>
                已验证
              </Typography>
            </Stack>

            <Stack
              spacing={0}
              sx={{
                borderTop: 1,
                borderColor: 'divider',
              }}
            >
              {consent.scopes.map((s) => {
                const meta = SCOPE_META[s] || { label: '应用自定义权限', icon: <RoleIcon fontSize="small" /> };
                return (
                  <Stack
                    key={s}
                    direction="row"
                    spacing={1.25}
                    alignItems="center"
                    sx={{ py: 1.15, borderBottom: 1, borderColor: 'divider' }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: '10px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'primary.main',
                        bgcolor: alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.16 : 0.08),
                        flexShrink: 0,
                      }}
                    >
                      {meta.icon}
                    </Box>
                    <Typography variant="body2" sx={{ flex: 1, minWidth: 0 }}>
                      {meta.label}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'ui-monospace, monospace' }}>
                      {s}
                    </Typography>
                  </Stack>
                );
              })}
            </Stack>

            <Stack direction="row" spacing={0.6} alignItems="center">
              <LockIcon sx={{ fontSize: 14, color: 'text.secondary' }} />
              <Typography variant="caption" color="text.secondary">
                授权后将返回 {targetHost}
              </Typography>
            </Stack>

            <Stack direction="row" spacing={1.25}>
              <Button
                variant="outlined"
                color="inherit"
                size="large"
                startIcon={<DenyIcon />}
                disabled={busy}
                onClick={() => handleDecision(false)}
                sx={{ ...buttonSx, flex: 1 }}
              >
                {phase === 'denying' ? '正在返回' : '拒绝'}
              </Button>
              <Button
                variant="contained"
                disableElevation
                size="large"
                startIcon={<AllowIcon />}
                disabled={busy}
                onClick={() => handleDecision(true)}
                sx={{
                  ...buttonSx,
                  flex: 1.35,
                  boxShadow: `0 8px 18px ${alpha(theme.palette.primary.main, 0.22)}`,
                }}
              >
                {phase === 'approved' ? '正在跳转' : phase === 'approving' ? '正在授权' : '允许'}
              </Button>
            </Stack>
          </Stack>
        )}
      </Stack>
    </OAuthBackdrop>
  );
};
