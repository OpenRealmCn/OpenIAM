import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Stack,
  Typography,
} from '@mui/material';
import { CheckCircle as AllowIcon, Cancel as DenyIcon, VerifiedUser as ShieldIcon } from '@mui/icons-material';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { isSafeClientRedirect } from '../utils/redirect';

const SCOPE_LABELS: Record<string, string> = {
  openid: '确认你的身份',
  profile: '读取你的显示名称和头像',
  email: '读取你的邮箱地址',
  phone: '读取你的手机号',
  offline_access: '在你未打开应用时保持访问',
  roles: '读取你的角色',
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

export const OAuthConsentPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const requestId = searchParams.get('request_id') || '';
  const { user } = useAuth();
  const [consent, setConsent] = useState<ConsentData | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!requestId) {
      setError('授权链接无效，请返回应用重新登录');
      setLoading(false);
      return;
    }
    api.oauth2Server
      .getConsent(requestId)
      .then((data) => setConsent(data))
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [requestId]);

  const handleDecision = async (approved: boolean) => {
    setSubmitting(true);
    setError('');
    try {
      const res = await api.oauth2Server.submitConsent(requestId, approved);
      if (!isSafeClientRedirect(res.redirect_uri)) {
        throw new Error('该应用的回调地址不安全，已阻止跳转，请联系应用管理员');
      }
      window.location.href = res.redirect_uri;
    } catch (err) {
      setError((err as Error).message);
      setSubmitting(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2,
        bgcolor: 'background.default',
      }}
    >
      <Card sx={{ maxWidth: 460, width: '100%' }}>
        <CardContent sx={{ p: 3.5 }}>
          <Stack direction="row" spacing={1.5} alignItems="center" mb={2}>
            <ShieldIcon color="primary" fontSize="large" />
            <Box>
              <Typography variant="h6">授权登录</Typography>
              <Typography variant="caption" color="text.secondary">
                请确认是否允许该应用使用你的账号登录
              </Typography>
            </Box>
          </Stack>

          <Divider sx={{ mb: 2.5 }} />

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : error && !consent ? (
            <Alert severity="error">{error}</Alert>
          ) : consent ? (
            <Stack spacing={2.5}>
              {error && <Alert severity="error">{error}</Alert>}
              <Box>
                <Typography variant="body1">
                  <strong>{consent.client_name}</strong> 请求使用你的账号{' '}
                  <strong>{user?.display_name || user?.username}</strong> 登录，并获得以下权限：
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                  授权后将跳转到 {redirectHost(consent.redirect_uri)}
                </Typography>
              </Box>

              <Box sx={{ p: 2, borderRadius: 2, bgcolor: 'action.hover' }}>
                <Stack spacing={0.75}>
                  {consent.scopes.map((s) => (
                    <Stack key={s} direction="row" spacing={1} alignItems="center">
                      <Chip label={s} size="small" variant="outlined" sx={{ fontFamily: 'monospace' }} />
                      <Typography variant="body2">{SCOPE_LABELS[s] || '应用自定义权限'}</Typography>
                    </Stack>
                  ))}
                </Stack>
              </Box>

              <Stack direction="row" spacing={1.5}>
                <Button
                  variant="outlined"
                  color="inherit"
                  fullWidth
                  startIcon={<DenyIcon />}
                  disabled={submitting}
                  onClick={() => handleDecision(false)}
                >
                  拒绝
                </Button>
                <Button
                  variant="contained"
                  fullWidth
                  startIcon={<AllowIcon />}
                  disabled={submitting}
                  onClick={() => handleDecision(true)}
                >
                  {submitting ? '正在跳转…' : '允许'}
                </Button>
              </Stack>
            </Stack>
          ) : null}
        </CardContent>
      </Card>
    </Box>
  );
};
