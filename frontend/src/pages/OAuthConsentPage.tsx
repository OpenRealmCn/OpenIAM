import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  alpha,
  Avatar,
  Box,
  Button,
  Chip,
  Divider,
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
import { AnimatePresence, motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import {
  AuthStageStep,
  AuthStageTimeline,
  HandshakeStatus,
  IdentityHandshakeDiagram,
  OAuthBackdrop,
} from '../components/OAuthAuthStage';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { isSafeClientRedirect } from '../utils/redirect';

const MotionBox = motion.create(Box);

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
  const [stageIndex, setStageIndex] = useState<number>(0);
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
    if (!approved) {
      setPhase('denying');
      try {
        const res = await api.oauth2Server.submitConsent(requestId, false);
        if (!isSafeClientRedirect(res.redirect_uri)) {
          throw new Error('该应用的回调地址不安全，已阻止跳转，请联系应用管理员');
        }
        await sleep(220);
        window.location.href = res.redirect_uri;
      } catch (err) {
        if (!mountedRef.current) return;
        setError((err as Error).message);
        setPhase('ready');
      }
      return;
    }

    setPhase('approving');
    setStageIndex(0);
    try {
      const submitPromise = api.oauth2Server.submitConsent(requestId, true);
      await sleep(220);
      if (!mountedRef.current) return;
      setStageIndex(1);

      const res = await submitPromise;
      if (!isSafeClientRedirect(res.redirect_uri)) {
        throw new Error('该应用的回调地址不安全，已阻止跳转，请联系应用管理员');
      }
      if (!mountedRef.current) return;
      setStageIndex(2);
      await sleep(180);
      if (!mountedRef.current) return;
      setPhase('approved');
      setStageIndex(3);

      await sleep(540);
      window.location.href = res.redirect_uri;
    } catch (err) {
      if (!mountedRef.current) return;
      setError((err as Error).message);
      setPhase('ready');
    }
  };

  const radius = Number(theme.shape.borderRadius);
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

  const approvalSteps: AuthStageStep[] = useMemo(
    () => [
      {
        key: 'session',
        label: '核验当前账号会话与安全上下文',
        detail: user?.username ? `当前身份：${user.display_name || user.username}` : undefined,
        status: stageIndex > 0 ? 'done' : stageIndex === 0 ? 'active' : 'pending',
      },
      {
        key: 'issue',
        label: '签发一次性加密授权码',
        detail: consent ? `授权范围：${consent.scopes.join(' / ')}` : undefined,
        status: stageIndex > 1 ? 'done' : stageIndex === 1 ? 'active' : 'pending',
      },
      {
        key: 'redirect',
        label: `准备安全跳转至 ${targetHost}`,
        detail: phase === 'approved' ? `已签发凭证，正在返回 ${consent?.client_name}` : undefined,
        status: phase === 'approved' ? 'done' : stageIndex === 2 ? 'active' : 'pending',
      },
    ],
    [stageIndex, phase, user, consent, targetHost],
  );

  return (
    <OAuthBackdrop maxWidth={480}>
      <Stack spacing={2.5}>
        {/* 头部标题 */}
        <Box textAlign="center">
          <Typography variant="h6" fontWeight={700} letterSpacing="-0.01em">
            {phase === 'approved'
              ? '授权验证通过'
              : phase === 'approving'
                ? '正在完成安全授权'
                : phase === 'denying'
                  ? '正在取消授权'
                  : '应用授权确认'}
          </Typography>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            {phase === 'approved'
              ? `正在安全返回 ${consent?.client_name || '目标应用'}…`
              : phase === 'approving'
                ? '正在为您生成一次性授权凭证'
                : '请确认是否允许该应用使用您的身份登录'}
          </Typography>
        </Box>

        {/* 双端连接握手图 */}
        <IdentityHandshakeDiagram
          status={handshakeStatus}
          leftNode={{
            label: siteInfo.name || 'OpenIAM',
            subLabel: '身份认证中心',
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
          rightNode={{
            label: consent?.client_name || '接入应用',
            subLabel: consent ? `域 · ${consent.domain_code}` : '正在验证应用',
            accent: theme.palette.secondary.main,
            icon: consent?.client_name ? (
              <Typography variant="h6" fontWeight={800} color="secondary.main">
                {targetAppInitial}
              </Typography>
            ) : (
              <AppIcon color="secondary" />
            ),
          }}
        />

        {/* 动态主体状态区 */}
        <AnimatePresence mode="wait">
          {phase === 'loading' && (
            <MotionBox
              key="loading"
              initial={scale === 0 ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 * scale }}
              sx={{ py: 1 }}
            >
              <AuthStageTimeline
                steps={[
                  {
                    key: 'inspect',
                    label: '正在核验应用身份与授权参数…',
                    detail: '校验客户端签名状态与回调地址白名单',
                    status: 'active',
                  },
                ]}
              />
            </MotionBox>
          )}

          {phase === 'error' && (
            <MotionBox
              key="error"
              initial={scale === 0 ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 * scale }}
            >
              <Alert severity="error">{error || '授权请求无效或已过期，请返回应用重试'}</Alert>
            </MotionBox>
          )}

          {(phase === 'approving' || phase === 'approved' || phase === 'denying') && (
            <MotionBox
              key="progress"
              initial={scale === 0 ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22 * scale }}
            >
              {phase === 'denying' ? (
                <AuthStageTimeline
                  steps={[
                    {
                      key: 'deny',
                      label: '已拒绝本次授权请求',
                      detail: `正在安全返回 ${targetHost}`,
                      status: 'active',
                    },
                  ]}
                />
              ) : (
                <AuthStageTimeline steps={approvalSteps} />
              )}
            </MotionBox>
          )}

          {phase === 'ready' && consent && (
            <MotionBox
              key="ready"
              initial={scale === 0 ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.22 * scale }}
            >
              <Stack spacing={2.2}>
                {error && (
                  <Alert severity="error" onClose={() => setError('')}>
                    {error}
                  </Alert>
                )}

                {/* 当前登录账号名片 */}
                <Box
                  sx={{
                    p: 1.5,
                    borderRadius: `${Math.max(8, radius - 2)}px`,
                    bgcolor: alpha(theme.palette.text.primary, theme.palette.mode === 'dark' ? 0.05 : 0.03),
                    border: `1px solid ${theme.palette.divider}`,
                  }}
                >
                  <Stack direction="row" spacing={1.4} alignItems="center" justifyContent="space-between">
                    <Stack direction="row" spacing={1.2} alignItems="center" sx={{ minWidth: 0 }}>
                      <Avatar
                        src={user?.avatar_url || undefined}
                        sx={{ width: 34, height: 34, bgcolor: 'primary.main', fontSize: '0.85rem', fontWeight: 700 }}
                      >
                        {initialChar}
                      </Avatar>
                      <Box sx={{ minWidth: 0 }}>
                        <Typography variant="body2" fontWeight={700} noWrap>
                          {user?.display_name || user?.username}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" noWrap display="block">
                          @{user?.username}
                          {user?.email ? ` · ${user.email}` : ''}
                        </Typography>
                      </Box>
                    </Stack>
                    <Chip
                      size="small"
                      color="success"
                      variant="outlined"
                      label="身份已验证"
                      sx={{ fontWeight: 600, flexShrink: 0 }}
                    />
                  </Stack>
                </Box>

                {/* 申请的权限清单（带交错进场动效） */}
                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={700} display="block" mb={1}>
                    应用「{consent.client_name}」将获得以下授权范围：
                  </Typography>
                  <Box
                    sx={{
                      p: 1.5,
                      borderRadius: `${Math.max(8, radius - 2)}px`,
                      bgcolor: alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.06 : 0.035),
                      border: `1px solid ${alpha(theme.palette.primary.main, 0.14)}`,
                    }}
                  >
                    <Stack spacing={1} divider={<Divider flexItem sx={{ opacity: 0.5 }} />}>
                      {consent.scopes.map((s, idx) => {
                        const meta = SCOPE_META[s] || {
                          label: '应用自定义授权范围',
                          icon: <RoleIcon fontSize="small" />,
                        };
                        return (
                          <MotionBox
                            key={s}
                            initial={scale === 0 ? false : { opacity: 0, x: -6 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={
                              scale === 0 ? { duration: 0 } : { duration: 0.2 * scale, delay: idx * 0.045 * scale }
                            }
                          >
                            <Stack direction="row" spacing={1.2} alignItems="center" justifyContent="space-between">
                              <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                                <Box sx={{ color: 'primary.main', display: 'flex', flexShrink: 0 }}>{meta.icon}</Box>
                                <Typography variant="body2" fontWeight={500}>
                                  {meta.label}
                                </Typography>
                              </Stack>
                              <Chip
                                label={s}
                                size="small"
                                variant="outlined"
                                sx={{ fontFamily: 'monospace', height: 20, fontSize: '0.7rem', flexShrink: 0 }}
                              />
                            </Stack>
                          </MotionBox>
                        );
                      })}
                    </Stack>
                  </Box>
                </Box>

                {/* 回调目标安全提示 */}
                <Stack direction="row" spacing={0.8} alignItems="center" justifyContent="center">
                  <LockIcon sx={{ fontSize: 13, color: 'text.secondary' }} />
                  <Typography variant="caption" color="text.secondary">
                    授权后将安全跳转至{' '}
                    <Box component="span" sx={{ fontWeight: 700, color: 'text.primary' }}>
                      {targetHost}
                    </Box>
                  </Typography>
                </Stack>

                {/* 授权确认按钮 */}
                <Stack direction="row" spacing={1.5} pt={0.4}>
                  <MotionBox
                    sx={{ flex: 1 }}
                    whileHover={scale === 0 ? undefined : { y: -1 }}
                    whileTap={scale === 0 ? undefined : { scale: 0.985 }}
                  >
                    <Button
                      variant="outlined"
                      color="inherit"
                      fullWidth
                      size="large"
                      startIcon={<DenyIcon />}
                      onClick={() => handleDecision(false)}
                      sx={{ py: 1.05 }}
                    >
                      拒绝
                    </Button>
                  </MotionBox>
                  <MotionBox
                    sx={{ flex: 1.35 }}
                    whileHover={scale === 0 ? undefined : { y: -1.5 }}
                    whileTap={scale === 0 ? undefined : { scale: 0.985 }}
                  >
                    <Button
                      variant="contained"
                      fullWidth
                      size="large"
                      startIcon={<AllowIcon />}
                      onClick={() => handleDecision(true)}
                      sx={{
                        py: 1.05,
                        background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                        boxShadow: `0 8px 20px ${alpha(theme.palette.primary.main, 0.32)}`,
                        '&:hover': {
                          boxShadow: `0 10px 24px ${alpha(theme.palette.primary.main, 0.42)}`,
                        },
                      }}
                    >
                      允许授权
                    </Button>
                  </MotionBox>
                </Stack>
              </Stack>
            </MotionBox>
          )}
        </AnimatePresence>
      </Stack>
    </OAuthBackdrop>
  );
};
