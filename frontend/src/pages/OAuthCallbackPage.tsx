import React, { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, CircularProgress, Stack, Typography } from '@mui/material';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { LoginResponse, useAuth } from '../context/AuthContext';
import { safeInternalPath } from '../utils/redirect';

type CallbackResponse = LoginResponse & { bound?: boolean; provider?: string };

const PROVIDER_ERRORS: Record<string, string> = {
  access_denied: '你已取消授权，未完成登录',
  temporarily_unavailable: '第三方登录服务暂时不可用，请稍后重试',
  server_error: '第三方登录服务出错，请稍后重试',
};

// 对相同 (provider, state) 的回调请求去重，避免 React StrictMode 或父级重渲染触发二次消费一次性 state。
const inflightCallbacks = new Map<string, Promise<CallbackResponse>>();

export const OAuthCallbackPage: React.FC = () => {
  const { provider } = useParams<{ provider: string }>();
  const [searchParams] = useSearchParams();
  const [error, setError] = useState('');
  const { user, applyLoginResponse, refreshProfile } = useAuth();
  const navigate = useNavigate();

  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const errParam = searchParams.get('error');

  useEffect(() => {
    let active = true;

    if (errParam) {
      setError(PROVIDER_ERRORS[errParam] || '第三方登录未完成，请重试');
      return;
    }
    if (!provider || !code || !state) {
      setError('登录链接无效或已过期，请重新发起登录');
      return;
    }

    const key = `${provider}:${state}`;
    const redirectUri = `${window.location.origin}/oauth/callback/${provider}`;
    let req = inflightCallbacks.get(key);
    if (!req) {
      req = api.auth.oauthCallback(provider, { code, state, redirect_uri: redirectUri });
      inflightCallbacks.set(key, req);
    }

    req
      .then(async (data) => {
        const target = safeInternalPath(localStorage.getItem('openiam_post_login_redirect'));
        localStorage.removeItem('openiam_post_login_redirect');

        // 绑定流程不签发新令牌，沿用当前登录态
        if (data?.bound) {
          await refreshProfile();
          if (active) navigate('/profile?tab=oauth&bound=1', { replace: true });
          return;
        }

        const step = await applyLoginResponse(data);
        if (!active) return;
        if (step.mfaRequired && step.mfaToken) {
          navigate(`/login?redirect=${encodeURIComponent(target)}`, { replace: true, state: { mfaChallenge: step } });
          return;
        }
        navigate(step.mustChangePassword ? '/change-password' : target, { replace: true });
      })
      .catch((err) => {
        inflightCallbacks.delete(key);
        if (active) {
          setError((err as Error).message);
        }
      });

    return () => {
      active = false;
    };
  }, [provider, code, state, errParam, applyLoginResponse, refreshProfile, navigate]);

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 2 }}>
      <Card sx={{ maxWidth: 420, width: '100%' }}>
        <CardContent sx={{ p: 3 }}>
          <Stack spacing={2} alignItems="center">
            {error ? (
              <>
                <Alert severity="error" sx={{ width: '100%' }}>
                  {error}
                </Alert>
                <Button
                  variant="contained"
                  onClick={() => navigate(user ? '/profile?tab=oauth' : '/login', { replace: true })}
                >
                  {user ? '返回个人中心' : '返回登录页'}
                </Button>
              </>
            ) : (
              <>
                <CircularProgress />
                <Typography variant="body1">正在完成第三方账号登录…</Typography>
              </>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
};
