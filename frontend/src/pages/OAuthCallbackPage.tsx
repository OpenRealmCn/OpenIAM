import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Box, Button, Stack, Typography, useTheme } from '@mui/material';
import {
  ArrowBackRounded as BackIcon,
  GitHub as GitHubIcon,
  Google as GoogleIcon,
  HubRounded as ProviderIcon,
  VerifiedUserRounded as ShieldIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import {
  AuthStageStep,
  AuthStageTimeline,
  HandshakeStatus,
  IdentityHandshakeDiagram,
  OAuthBackdrop,
} from '../components/OAuthAuthStage';
import { LoginResponse, useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { safeInternalPath } from '../utils/redirect';

const MotionBox = motion.create(Box);

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
  const theme = useTheme();
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
  const handshakeStatus: HandshakeStatus =
    phase === 'success' ? 'success' : phase === 'error' ? 'error' : 'verifying';

  const steps: AuthStageStep[] = useMemo(() => {
    const stepStatus = (idx: number): AuthStageStep['status'] => {
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
        label: '校验安全防篡改状态参数',
        detail: `身份源：${providerMeta.name}`,
        status: stepStatus(0),
      },
      {
        key: 'exchange',
        label: '向第三方身份源交换访问凭证',
        detail: '加密通道核验身份档案',
        status: stepStatus(1),
      },
      {
        key: 'session',
        label: isBindingMode ? '关联第三方账号至当前身份' : '建立加密会话并同步权限',
        detail: phase === 'success' ? successHeadline : undefined,
        status: stepStatus(2),
      },
    ];
  }, [phase, stageIndex, providerMeta.name, isBindingMode, successHeadline]);

  return (
    <OAuthBackdrop maxWidth={450}>
      <Stack spacing={2.5}>
        <Box textAlign="center">
          <Typography variant="h6" fontWeight={700} letterSpacing="-0.01em">
            {phase === 'success'
              ? isBindingMode
                ? '账号关联成功'
                : '身份认证通过'
              : phase === 'error'
                ? '联合身份验证未完成'
                : `正在验证 ${providerMeta.name} 身份`}
          </Typography>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            {phase === 'success'
              ? successHeadline
              : phase === 'error'
                ? '请查看下方提示信息或返回重新发起登录'
                : '正在核验这次登录'}
          </Typography>
        </Box>

        <IdentityHandshakeDiagram
          status={handshakeStatus}
          leftNode={{
            label: providerMeta.name,
            subLabel: '外部身份源',
            accent: providerMeta.color,
            icon: providerMeta.icon,
          }}
          rightNode={{
            label: siteInfo.name || 'OpenIAM',
            subLabel: isBindingMode ? '账号安全绑定' : '统一身份认证',
            accent: theme.palette.primary.main,
            icon: siteInfo.logo_url ? (
              <Box
                component="img"
                src={siteInfo.logo_url}
                alt={siteInfo.name}
                sx={{ width: 28, height: 28, objectFit: 'contain', borderRadius: 1 }}
              />
            ) : (
              <ShieldIcon color="primary" />
            ),
          }}
        />

        <AuthStageTimeline steps={steps} />

        <AnimatePresence>
          {phase === 'error' && (
            <MotionBox
              key="callback-error"
              initial={scale === 0 ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 * scale }}
            >
              <Stack spacing={2}>
                <Alert severity="error">{error}</Alert>
                <Button
                  variant="contained"
                  fullWidth
                  size="large"
                  startIcon={<BackIcon />}
                  onClick={() => navigate(user ? '/profile?tab=oauth' : '/login', { replace: true })}
                >
                  {user ? '返回个人中心' : '返回登录页'}
                </Button>
              </Stack>
            </MotionBox>
          )}
        </AnimatePresence>
      </Stack>
    </OAuthBackdrop>
  );
};
