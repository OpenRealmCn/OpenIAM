import React, { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, CircularProgress, Stack, Typography } from '@mui/material';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const OAuthCallbackPage: React.FC = () => {
  const { provider } = useParams<{ provider: string }>();
  const [searchParams] = useSearchParams();
  const [error, setError] = useState('');
  const { completeOAuthLogin } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const errParam = searchParams.get('error');

    if (errParam) {
      setError(`身份源返回错误: ${errParam}`);
      return;
    }
    if (!provider || !code || !state) {
      setError('回调缺少必要的 code 或 state 参数');
      return;
    }

    const redirectUri = `${window.location.origin}/oauth/callback/${provider}`;
    api.auth
      .oauthCallback(provider, { code, state, redirect_uri: redirectUri })
      .then(async (data) => {
        if (data?.access_token) {
          await completeOAuthLogin(data.access_token);
        }
        const target = localStorage.getItem('openiam_post_login_redirect') || '/';
        localStorage.removeItem('openiam_post_login_redirect');
        navigate(target, { replace: true });
      })
      .catch((err) => {
        setError((err as Error).message);
      });
  }, [provider, searchParams, completeOAuthLogin, navigate]);

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
                <Button variant="contained" onClick={() => navigate('/login')}>
                  返回登录页
                </Button>
              </>
            ) : (
              <>
                <CircularProgress />
                <Typography variant="body1">正在完成 {provider} 联合身份验证...</Typography>
              </>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
};
