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
      setError('缺少授权请求参数 request_id');
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
              <Typography variant="h6">应用授权确认</Typography>
              <Typography variant="caption" color="text.secondary">
                OpenIAM OAuth 2.0 / OIDC 统一授权中心
              </Typography>
            </Box>
          </Stack>

          <Divider sx={{ mb: 2.5 }} />

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : error ? (
            <Alert severity="error">{error}</Alert>
          ) : consent ? (
            <Stack spacing={2.5}>
              <Box>
                <Typography variant="body1">
                  应用 <strong>{consent.client_name}</strong> 请求以您的身份{' '}
                  <strong>{user?.display_name || user?.username}</strong> 登录并访问以下权限：
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                  所属域: {consent.domain_code} · Client ID: {consent.client_id}
                </Typography>
              </Box>

              <Box sx={{ p: 2, borderRadius: 2, bgcolor: 'action.hover' }}>
                <Typography variant="caption" color="text.secondary" display="block" mb={1}>
                  申请的授权范围 (Scopes):
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {consent.scopes.map((s) => (
                    <Chip key={s} label={s} color="primary" size="small" variant="outlined" />
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
                  拒绝授权
                </Button>
                <Button
                  variant="contained"
                  fullWidth
                  startIcon={<AllowIcon />}
                  disabled={submitting}
                  onClick={() => handleDecision(true)}
                >
                  {submitting ? '正在跳转...' : '允许授权'}
                </Button>
              </Stack>
            </Stack>
          ) : null}
        </CardContent>
      </Card>
    </Box>
  );
};
