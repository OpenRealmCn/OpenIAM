import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Box, Button, Stack, Typography } from '@mui/material';
import { ArrowBackRounded as BackIcon, GitHub as GitHubIcon, Google as GoogleIcon, HubRounded as ProviderIcon } from '@mui/icons-material';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { OAuthStage, OAuthStep, OAuthStepList } from '../components/OAuthStage';
import { LoginResponse, useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { safeInternalPath } from '../utils/redirect';

type CallbackResponse = LoginResponse & { bound?: boolean; provider?: string };

const PROVIDER_ERRORS: Record<string, string> = {
  access_denied: '你已取消授权，未完成登录',
  temporarily_unavailable: '第三方登录服务暂时不可用，请稍后重试',
  server_error: '第三方登录服务出错，请稍后重试',
};

// 对相同 (provider, state) 的回调请求去重，避免 React StrictMode 或父级重渲染触发二次消费一次性 state。
const inflightCallbacks = new Map<string, Promise<CallbackResponse>>();

function resolveProviderMeta(providerRaw?: string): { name: string; icon: React.ReactNode; color: string } {
  const key = (providerRaw || '').toLowerCase();
  if (key.includes('github')) {
    return { name: 'GitHub', icon: <GitHubIcon sx={{ fontSize: 26 }} />, color: '#334155' };
  }
  if (key.includes('google')) {
    return { name: 'Google', icon: <GoogleIcon sx={{ fontSize: 26, color: '#EA4335' }} />, color: '#EA4335' };
  }
  if (key.includes('feishu') || key.includes('lark')) {
    return { name: '飞书', icon: <ProviderIcon sx={{ fontSize: 26, color: '#00D6B9' }} />, color: '#00D6B9' };
  }
  if (key.includes('wecom') || key.includes('wechat')) {
    return { name: '企业微信', icon: <ProviderIcon sx={{ fontSize: 26, color: '#07C160' }} />, color: '#07C160' };
  }
  return {
    name: providerRaw || '第三方身份源',
    icon: <ProviderIcon color="secondary" sx={{ fontSize: 26 }} />,
    color: '#6366F1',
  };
}

type CallbackPhase = 'verifying' | 'success' | 'error';

export const OAuthCallbackPage: React.FC = () => {
  const { provider } = useParams<{ provider: string }>();
  const [searchParams] = useSearchParams();
  const { user, applyLoginResponse, refreshProfile } = useAuth();
  const { siteInfo } = useSite();
  const navigate = useNavigate();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  const [phase, setPhase] = useState<CallbackPhase>('verifying');
  const [stageIndex, setStageIndex] = useState<number>(0);
  const [isBindingMode, setIsBindingMode] = useState<boolean>(Boolean(user));
  const [successHeadline, setSuccessHeadline] = useState<string>('身份校验通过，正在进入工作台…');
  const [error, setError] = useState('');
  const mountedRef = useRef(true);

  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const errParam = searchParams.get('error');

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    const sleep = (ms: number) =>
      new Promise<void>((resolve) => {
        if (scale === 0 || ms <= 0) {
          resolve();
          return;
        }
        setTimeout(resolve, Math.round(ms * scale));
      });

    if (errParam) {
      setError(PROVIDER_ERRORS[errParam] || '第三方登录未完成，请重试');
      setPhase('error');
      setStageIndex(0);
      return;
    }
    if (!provider || !code || !state) {
      setError('登录链接无效或已过期，请重新发起登录');
      setPhase('error');
      setStageIndex(0);
      return;
    }

    const run = async () => {
      try {
        setPhase('verifying');
        setStageIndex(0);
        await sleep(180);
        if (!active || !mountedRef.current) return;

        setStageIndex(1);
        const key = `${provider}:${state}`;
        const redirectUri = `${window.location.origin}/oauth/callback/${provider}`;
        let req = inflightCallbacks.get(key);
        if (!req) {
          req = api.auth.oauthCallback(provider, { code, state, redirect_uri: redirectUri });
          inflightCallbacks.set(key, req);
        }

        const data = await req;
        if (!active || !mountedRef.current) return;

        setStageIndex(2);
        const target = safeInternalPath(localStorage.getItem('openiam_post_login_redirect'));
        localStorage.removeItem('openiam_post_login_redirect');

        if (data?.bound) {
          setIsBindingMode(true);
          await refreshProfile();
          if (!active || !mountedRef.current) return;
          setSuccessHeadline('账号绑定成功，正在返回个人中心…');
          setStageIndex(3);
          setPhase('success');
          await sleep(460);
          if (active) navigate('/profile?tab=oauth&bound=1', { replace: true });
          return;
        }

        const step = await applyLoginResponse(data);
        if (!active || !mountedRef.current) return;

        if (step.mfaRequired && step.mfaToken) {
          setSuccessHeadline('检测到需要完成二步身份验证，正在跳转…');
          setStageIndex(3);
          setPhase('success');
          await sleep(420);
          if (active) {
            navigate(`/login?redirect=${encodeURIComponent(target)}`, { replace: true, state: { mfaChallenge: step } });
          }
          return;
        }

        setSuccessHeadline(step.mustChangePassword ? '身份已验证，请先修改初始密码…' : '认证通过，正在进入工作台…');
        setStageIndex(3);
        setPhase('success');
        await sleep(460);
        if (active) {
          navigate(step.mustChangePassword ? '/change-password' : target, { replace: true });
        }
      } catch (err) {
        inflightCallbacks.delete(`${provider}:${state}`);
        if (active && mountedRef.current) {
          setError((err as Error).message);
          setPhase('error');
        }
      }
    };

    void run();

    return () => {
      active = false;
    };
  }, [provider, code, state, errParam, applyLoginResponse, refreshProfile, navigate, scale]);

  const providerMeta = useMemo(() => resolveProviderMeta(provider), [provider]);
  const steps: OAuthStep[] = useMemo(() => {
    const stepStatus = (idx: number): OAuthStep['status'] => {
      if (phase === 'success') return 'done';
      if (phase === 'error') {
        if (idx < stageIndex) return 'done';
        if (idx === stageIndex) return 'error';
        return 'pending';
      }
      if (idx < stageIndex) return 'done';
      if (idx === stageIndex) return 'active';
      return 'pending';
    };

    return [
      {
        key: 'state',
        label: '确认这次登录',
        detail: providerMeta.name,
        status: stepStatus(0),
      },
      {
        key: 'exchange',
        label: `向${providerMeta.name}核对身份`,
        status: stepStatus(1),
      },
      {
        key: 'session',
        label: isBindingMode ? '关联到当前账号' : `进入 ${siteInfo.name || 'OpenIAM'}`,
        detail: phase === 'success' ? successHeadline : undefined,
        status: stepStatus(2),
      },
    ];
  }, [phase, stageIndex, providerMeta.name, isBindingMode, successHeadline, siteInfo.name]);

  const signedIn = Boolean(user);
  const initial = (user?.display_name || user?.username || siteInfo.name || 'O').slice(0, 1).toUpperCase();

  return (
    <OAuthStage
      identity={
        signedIn
          ? {
              label: isBindingMode ? '绑定到' : '当前账号',
              name: user?.display_name || user?.username || '',
              handle: user?.username ? `@${user.username}` : undefined,
              hint: user?.email,
              avatarUrl: user?.avatar_url,
              fallback: initial,
            }
          : {
              label: '登录后进入',
              name: siteInfo.name || 'OpenIAM',
              fallback: initial,
            }
      }
    >
      <Stack spacing={3}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Box sx={{ color: providerMeta.color, display: 'flex' }}>{providerMeta.icon}</Box>
          <Box>
            <Typography variant="h4" fontWeight={700} letterSpacing="-0.03em">
              {phase === 'error' ? '登录没有完成' : phase === 'success' ? (isBindingMode ? '账号已关联' : '登录成功') : `通过${providerMeta.name}登录`}
            </Typography>
            <Typography variant="body2" color="text.secondary" mt={0.5}>
              {phase === 'success' ? successHeadline : phase === 'error' ? '可以返回后重新发起' : '请稍等，正在完成身份核对'}
            </Typography>
          </Box>
        </Stack>

        <OAuthStepList steps={steps} />

        {phase === 'error' && (
          <Stack spacing={2}>
            <Alert severity="error">{error}</Alert>
            <Button
              variant="contained"
              size="large"
              startIcon={<BackIcon />}
              onClick={() => navigate(user ? '/profile?tab=oauth' : '/login', { replace: true })}
              sx={{ alignSelf: 'flex-start', borderRadius: '12px' }}
            >
              {user ? '返回个人中心' : '返回登录'}
            </Button>
          </Stack>
        )}
      </Stack>
    </OAuthStage>
  );
};
