import React, { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, Stack, Typography } from '@mui/material';
import {
  AccessTimeRounded as OfflineIcon,
  BadgeRounded as ProfileIcon,
  CancelOutlined as DenyIcon,
  CheckCircleRounded as AllowIcon,
  EmailRounded as EmailIcon,
  FingerprintRounded as IdentityIcon,
  PhoneAndroidRounded as PhoneIcon,
  SecurityRounded as RoleIcon,
} from '@mui/icons-material';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { OAuthScopeList, OAuthStage } from '../components/OAuthStage';
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
  const targetHost = consent ? redirectHost(consent.redirect_uri) : '';
  const busy = phase === 'approving' || phase === 'approved' || phase === 'denying';
  const appName = consent?.client_name || '该应用';
  const headline =
    phase === 'error'
      ? '无法完成授权'
      : phase === 'loading'
        ? '正在读取授权请求'
        : phase === 'denying'
          ? '正在返回应用'
          : phase === 'approved'
            ? `正在返回 ${appName}`
            : phase === 'approving'
              ? '正在签发授权码'
              : `${appName} 想登录`;

  const buttonSx = {
    py: 1.15,
    borderRadius: '12px',
    touchAction: 'manipulation',
    transition: 'transform 160ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 160ms ease',
    '&:active': { transform: 'scale(0.98)', transitionDuration: '0s' },
  };

  return (
    <OAuthStage
      identity={{
        label: '当前账号',
        name: user?.display_name || user?.username || '未登录',
        handle: user?.username ? `@${user.username}` : undefined,
        hint: user?.email,
        avatarUrl: user?.avatar_url,
        fallback: initialChar,
      }}
    >
      <Stack spacing={3}>
        <Box>
          <Typography variant="h4" fontWeight={700} letterSpacing="-0.03em">
            {headline}
          </Typography>
          <Typography variant="body2" color="text.secondary" mt={1}>
            {phase === 'ready' && consent
              ? `允许后，${appName} 可以使用下面这些信息，并回到 ${targetHost}。`
              : phase === 'error'
                ? error || '授权请求无效或已过期，请返回应用重试'
                : `使用你的 ${siteInfo.name || 'OpenIAM'} 账号`}
          </Typography>
        </Box>

        {phase === 'error' && <Alert severity="error">{error || '授权请求无效或已过期，请返回应用重试'}</Alert>}

        {consent && phase !== 'error' && (
          <>
            {error && (
              <Alert severity="error" onClose={() => setError('')}>
                {error}
              </Alert>
            )}
            <OAuthScopeList
              items={consent.scopes.map((s) => {
                const meta = SCOPE_META[s] || { label: '应用自定义权限', icon: <RoleIcon fontSize="small" /> };
                return { id: s, label: meta.label, token: s, icon: meta.icon };
              })}
            />
            {consent.domain_code && (
              <Typography variant="caption" color="text.secondary">
                应用所属域 {consent.domain_code}
              </Typography>
            )}
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
                sx={{ ...buttonSx, flex: 1.4 }}
              >
                {phase === 'approved' ? '正在跳转' : phase === 'approving' ? '正在授权' : '允许'}
              </Button>
            </Stack>
          </>
        )}
      </Stack>
    </OAuthStage>
  );
};
