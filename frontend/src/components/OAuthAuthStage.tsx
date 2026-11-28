import React, { useState } from 'react';
import { alpha, Box, Card, CardContent, Stack, Typography, useTheme } from '@mui/material';
import {
  CloseRounded as ErrorIcon,
  LockRounded as LockIcon,
  ShieldRounded as ShieldIcon,
  SyncLockRounded as HandshakeIcon,
  VerifiedUserRounded as VerifiedShieldIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';

const MotionBox = motion.create(Box);

export type HandshakeStatus = 'idle' | 'verifying' | 'success' | 'error';

export interface HandshakeNode {
  label: string;
  subLabel?: string;
  icon: React.ReactNode;
  accent?: string;
}

export interface AuthStageStep {
  key: string;
  label: string;
  detail?: string;
  status: 'pending' | 'active' | 'done' | 'error';
}

interface OAuthBackdropProps {
  children: React.ReactNode;
  maxWidth?: number;
}

/**
 * OAuth 2.0 / OIDC 统一鉴权舞台背景：提供双色氛围光晕、渐隐微点阵、品牌顶栏、高质感毛玻璃容器与安全底注。
 */
export const OAuthBackdrop: React.FC<OAuthBackdropProps> = ({ children, maxWidth = 480 }) => {
  const theme = useTheme();
  const { siteInfo } = useSite();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const [logoError, setLogoError] = useState(false);

  const isDark = theme.palette.mode === 'dark';
  const radius = Number(theme.shape.borderRadius);
  const dotColor = alpha(theme.palette.text.primary, isDark ? 0.08 : 0.07);

  const springTransition =
    scale === 0
      ? { duration: 0 }
      : { type: 'spring' as const, stiffness: 360 / scale, damping: 32, mass: 0.9 };

  return (
    <Box
      sx={{
        position: 'relative',
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        px: 2,
        py: 4,
        bgcolor: 'background.default',
      }}
    >
      {/* 氛围光晕背景层 */}
      <MotionBox
        aria-hidden
        animate={
          scale === 0
            ? undefined
            : {
                scale: [1, 1.06, 1],
                opacity: [0.85, 1, 0.85],
              }
        }
        transition={
          scale === 0
            ? { duration: 0 }
            : { duration: 8 * scale, repeat: Infinity, ease: 'easeInOut' }
        }
        sx={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          backgroundImage: `
            radial-gradient(circle at 18% 18%, ${alpha(theme.palette.primary.main, isDark ? 0.2 : 0.14)} 0%, transparent 46%),
            radial-gradient(circle at 82% 82%, ${alpha(theme.palette.secondary.main, isDark ? 0.18 : 0.12)} 0%, transparent 48%),
            radial-gradient(circle at 50% 45%, ${alpha(theme.palette.primary.main, isDark ? 0.08 : 0.05)} 0%, transparent 62%)
          `,
        }}
      />

      {/* 中心渐隐微点阵装饰 */}
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          backgroundImage: `radial-gradient(${dotColor} 1px, transparent 1px)`,
          backgroundSize: '22px 22px',
          maskImage: 'radial-gradient(ellipse 68% 62% at 50% 48%, #000 35%, transparent 100%)',
          WebkitMaskImage: 'radial-gradient(ellipse 68% 62% at 50% 48%, #000 35%, transparent 100%)',
        }}
      />

      <MotionBox
        layout
        initial={scale === 0 ? false : { opacity: 0, y: 18, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={springTransition}
        sx={{ position: 'relative', zIndex: 1, width: '100%', maxWidth }}
      >
        {/* 顶部站点品牌徽章 */}
        <Stack direction="row" spacing={1.2} alignItems="center" justifyContent="center" mb={2.2}>
          {siteInfo.logo_url && !logoError ? (
            <Box
              component="img"
              src={siteInfo.logo_url}
              alt={siteInfo.name}
              onError={() => setLogoError(true)}
              sx={{
                width: 32,
                height: 32,
                borderRadius: `${Math.max(6, Math.round(radius * 0.65))}px`,
                objectFit: 'contain',
              }}
            />
          ) : (
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: `${Math.max(6, Math.round(radius * 0.65))}px`,
                background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: `0 6px 16px ${alpha(theme.palette.primary.main, 0.35)}`,
              }}
            >
              <ShieldIcon sx={{ fontSize: 18 }} />
            </Box>
          )}
          <Typography variant="subtitle1" fontWeight={700} letterSpacing="-0.01em">
            {siteInfo.name || 'OpenIAM'}
          </Typography>
        </Stack>

        {/* 主体毛玻璃卡片 */}
        <Card
          sx={{
            position: 'relative',
            overflow: 'hidden',
            borderRadius: `${Math.max(12, radius + 4)}px`,
            bgcolor: alpha(theme.palette.background.paper, isDark ? 0.8 : 0.88),
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.9 : 0.8)}`,
            boxShadow: isDark
              ? `0 24px 64px rgba(0, 0, 0, 0.6), 0 0 0 1px ${alpha(theme.palette.common.white, 0.04)} inset`
              : `0 22px 54px rgba(15, 23, 42, 0.09), 0 0 0 1px ${alpha('#fff', 0.7)} inset`,
          }}
        >
          {/* 顶部微妙高光边 */}
          <Box
            aria-hidden
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 3,
              background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              opacity: 0.85,
            }}
          />
          <CardContent sx={{ p: { xs: 3, sm: 3.75 }, '&:last-child': { pb: { xs: 3, sm: 3.75 } } }}>
            {children}
          </CardContent>
        </Card>

        {/* 安全底注 */}
        <Stack spacing={0.5} alignItems="center" mt={2.2}>
          <Stack direction="row" spacing={0.6} alignItems="center" color="text.secondary">
            <LockIcon sx={{ fontSize: 13, color: 'success.main' }} />
            <Typography variant="caption" color="text.secondary" fontWeight={500}>
              OAuth 2.0 / OIDC 加密认证
            </Typography>
          </Stack>
          {siteInfo.footer_text && (
            <Typography variant="caption" color="text.disabled">
              {siteInfo.footer_text}
            </Typography>
          )}
        </Stack>
      </MotionBox>
    </Box>
  );
};

interface IdentityHandshakeDiagramProps {
  leftNode: HandshakeNode;
  rightNode: HandshakeNode;
  status: HandshakeStatus;
}

/**
 * 双端身份连接握手可视化：展现授权确认与联合登录在双端系统之间的加密校验、脉冲传输、成功描边对勾及错误反馈。
 */
export const IdentityHandshakeDiagram: React.FC<IdentityHandshakeDiagramProps> = ({
  leftNode,
  rightNode,
  status,
}) => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const radius = Number(theme.shape.borderRadius);

  const trackColor =
    status === 'success'
      ? theme.palette.success.main
      : status === 'error'
        ? theme.palette.error.main
        : theme.palette.primary.main;

  const renderNode = (node: HandshakeNode, side: 'left' | 'right') => {
    const accent = node.accent || theme.palette.primary.main;
    return (
      <Stack alignItems="center" spacing={0.8} sx={{ width: 96, flexShrink: 0 }}>
        <MotionBox
          initial={scale === 0 ? false : { opacity: 0, x: side === 'left' ? -10 : 10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={scale === 0 ? { duration: 0 } : { type: 'spring', stiffness: 320 / scale, damping: 26 }}
          sx={{
            width: 54,
            height: 54,
            borderRadius: `${Math.max(12, radius)}px`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: alpha(accent, theme.palette.mode === 'dark' ? 0.16 : 0.1),
            border: `1.5px solid ${
              status === 'success'
                ? alpha(theme.palette.success.main, 0.55)
                : alpha(accent, 0.35)
            }`,
            boxShadow: `0 8px 20px ${alpha(accent, 0.16)}`,
            transition: 'border-color 0.25s ease',
          }}
        >
          {node.icon}
        </MotionBox>
        <Box textAlign="center" sx={{ width: '100%' }}>
          <Typography variant="caption" fontWeight={700} noWrap display="block">
            {node.label}
          </Typography>
          {node.subLabel && (
            <Typography variant="caption" color="text.secondary" noWrap display="block" sx={{ fontSize: '0.68rem' }}>
              {node.subLabel}
            </Typography>
          )}
        </Box>
      </Stack>
    );
  };

  return (
    <MotionBox
      animate={
        status === 'error' && scale > 0
          ? { x: [0, -5, 5, -3, 3, 0] }
          : { x: 0 }
      }
      transition={{ duration: 0.38 * Math.max(scale, 0.5) }}
      sx={{
        py: 1.5,
        px: 1,
        borderRadius: `${Math.max(10, radius)}px`,
        bgcolor: alpha(trackColor, theme.palette.mode === 'dark' ? 0.06 : 0.04),
        border: `1px solid ${alpha(trackColor, status === 'idle' ? 0.12 : 0.24)}`,
        transition: 'background-color 0.3s ease, border-color 0.3s ease',
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1}>
        {renderNode(leftNode, 'left')}

        {/* 中央连接轨道与握手徽标 */}
        <Box sx={{ flex: 1, position: 'relative', height: 42, display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2.2 }}>
          {/* 底层基础连线 */}
          <Box
            sx={{
              position: 'absolute',
              left: 4,
              right: 4,
              height: 2,
              borderRadius: 1,
              bgcolor: alpha(trackColor, status === 'success' || status === 'error' ? 0.75 : 0.22),
              transition: 'background-color 0.35s ease',
            }}
          />

          {/* 传输流光粒子（idle 为轻柔缓流，verifying 为高亮快速穿梭） */}
          {(status === 'idle' || status === 'verifying') && scale > 0 && (
            <MotionBox
              animate={{ left: ['4%', '88%'], opacity: [0, 1, 1, 0] }}
              transition={{
                duration: (status === 'verifying' ? 1.05 : 2.2) * scale,
                repeat: Infinity,
                ease: 'easeInOut',
              }}
              sx={{
                position: 'absolute',
                width: status === 'verifying' ? 22 : 14,
                height: 4,
                borderRadius: 2,
                background: `linear-gradient(90deg, transparent, ${theme.palette.primary.main})`,
                boxShadow: `0 0 10px ${alpha(theme.palette.primary.main, 0.75)}`,
              }}
            />
          )}

          {/* 中心成功扩散涟漪 */}
          {status === 'success' && scale > 0 && (
            <MotionBox
              initial={{ scale: 0.7, opacity: 0.8 }}
              animate={{ scale: 2.1, opacity: 0 }}
              transition={{ duration: 0.75 * scale, ease: 'easeOut' }}
              sx={{
                position: 'absolute',
                width: 34,
                height: 34,
                borderRadius: '50%',
                border: `2px solid ${theme.palette.success.main}`,
                pointerEvents: 'none',
              }}
            />
          )}

          {/* 校验中旋转外环 */}
          {status === 'verifying' && scale > 0 && (
            <MotionBox
              animate={{ rotate: 360 }}
              transition={{ duration: 1.4 * scale, repeat: Infinity, ease: 'linear' }}
              sx={{
                position: 'absolute',
                width: 40,
                height: 40,
                borderRadius: '50%',
                border: `2px solid transparent`,
                borderTopColor: theme.palette.primary.main,
                borderRightColor: alpha(theme.palette.secondary.main, 0.7),
              }}
            />
          )}

          {/* 中心状态徽标 */}
          <MotionBox
            key={status}
            initial={scale === 0 ? false : { scale: 0.72, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={scale === 0 ? { duration: 0 } : { type: 'spring', stiffness: 420 / scale, damping: 24 }}
            sx={{
              position: 'relative',
              zIndex: 1,
              width: 32,
              height: 32,
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor:
                status === 'success'
                  ? 'success.main'
                  : status === 'error'
                    ? 'error.main'
                    : 'background.paper',
              color:
                status === 'success' || status === 'error'
                  ? '#fff'
                  : theme.palette.primary.main,
              border: `1.5px solid ${alpha(trackColor, status === 'idle' ? 0.35 : 0.9)}`,
              boxShadow: `0 4px 14px ${alpha(trackColor, 0.25)}`,
            }}
          >
            {status === 'success' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <motion.path
                  d="M5 13l4 4L19 7"
                  stroke="#fff"
                  strokeWidth="2.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  initial={scale === 0 ? false : { pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 0.34 * scale, ease: 'easeOut' }}
                />
              </svg>
            ) : status === 'error' ? (
              <ErrorIcon sx={{ fontSize: 17 }} />
            ) : status === 'verifying' ? (
              <HandshakeIcon sx={{ fontSize: 17 }} />
            ) : (
              <VerifiedShieldIcon sx={{ fontSize: 17 }} />
            )}
          </MotionBox>
        </Box>

        {renderNode(rightNode, 'right')}
      </Stack>
    </MotionBox>
  );
};

interface AuthStageTimelineProps {
  steps: AuthStageStep[];
}

/**
 * 多阶段鉴权进度时间轴：清晰反馈每一步安全核验与令牌交换状态。
 */
export const AuthStageTimeline: React.FC<AuthStageTimelineProps> = ({ steps }) => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const radius = Number(theme.shape.borderRadius);

  return (
    <Stack spacing={1.1}>
      {steps.map((step, idx) => {
        const isActive = step.status === 'active';
        const isDone = step.status === 'done';
        const isErr = step.status === 'error';

        const accent = isErr
          ? theme.palette.error.main
          : isDone
            ? theme.palette.success.main
            : isActive
              ? theme.palette.primary.main
              : theme.palette.text.disabled;

        return (
          <MotionBox
            key={step.key}
            initial={scale === 0 ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={
              scale === 0
                ? { duration: 0 }
                : { duration: 0.22 * scale, delay: idx * 0.05 * scale }
            }
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.4,
              px: 1.6,
              py: 1.15,
              borderRadius: `${Math.max(8, radius - 2)}px`,
              bgcolor: isActive
                ? alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.14 : 0.08)
                : isErr
                  ? alpha(theme.palette.error.main, theme.palette.mode === 'dark' ? 0.14 : 0.08)
                  : isDone
                    ? alpha(theme.palette.success.main, theme.palette.mode === 'dark' ? 0.1 : 0.05)
                    : alpha(theme.palette.text.primary, 0.025),
              border: `1px solid ${
                isActive || isErr
                  ? alpha(accent, 0.38)
                  : isDone
                    ? alpha(theme.palette.success.main, 0.22)
                    : alpha(theme.palette.divider, 0.6)
              }`,
              transition: 'background-color 0.25s ease, border-color 0.25s ease',
            }}
          >
            <Box
              sx={{
                position: 'relative',
                width: 24,
                height: 24,
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <AnimatePresence mode="wait">
                {isDone ? (
                  <MotionBox
                    key="done"
                    initial={scale === 0 ? false : { scale: 0.5, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={scale === 0 ? { duration: 0 } : { type: 'spring', stiffness: 450 / scale, damping: 22 }}
                    sx={{
                      width: 22,
                      height: 22,
                      borderRadius: '50%',
                      bgcolor: 'success.main',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                      <motion.path
                        d="M5 13l4 4L19 7"
                        stroke="#fff"
                        strokeWidth="3"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        initial={scale === 0 ? false : { pathLength: 0 }}
                        animate={{ pathLength: 1 }}
                        transition={{ duration: 0.28 * scale }}
                      />
                    </svg>
                  </MotionBox>
                ) : isErr ? (
                  <MotionBox
                    key="error"
                    initial={scale === 0 ? false : { scale: 0.6, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    sx={{
                      width: 22,
                      height: 22,
                      borderRadius: '50%',
                      bgcolor: 'error.main',
                      color: '#fff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <ErrorIcon sx={{ fontSize: 14 }} />
                  </MotionBox>
                ) : isActive ? (
                  <MotionBox
                    key="active"
                    initial={scale === 0 ? false : { opacity: 0 }}
                    animate={{ opacity: 1 }}
                    sx={{
                      position: 'relative',
                      width: 22,
                      height: 22,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {scale > 0 && (
                      <MotionBox
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1.05 * scale, repeat: Infinity, ease: 'linear' }}
                        sx={{
                          position: 'absolute',
                          inset: 0,
                          borderRadius: '50%',
                          border: `2px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                          borderTopColor: theme.palette.primary.main,
                        }}
                      />
                    )}
                    <Box
                      sx={{
                        width: 7,
                        height: 7,
                        borderRadius: '50%',
                        bgcolor: 'primary.main',
                      }}
                    />
                  </MotionBox>
                ) : (
                  <MotionBox
                    key="pending"
                    sx={{
                      width: 18,
                      height: 18,
                      borderRadius: '50%',
                      border: `1.5px solid ${alpha(theme.palette.text.disabled, 0.5)}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Box sx={{ width: 5, height: 5, borderRadius: '50%', bgcolor: 'text.disabled' }} />
                  </MotionBox>
                )}
              </AnimatePresence>
            </Box>

            <Box sx={{ minWidth: 0, flex: 1 }}>
              <Typography
                variant="body2"
                fontWeight={isActive || isDone ? 600 : 500}
                color={isErr ? 'error.main' : step.status === 'pending' ? 'text.secondary' : 'text.primary'}
              >
                {step.label}
              </Typography>
              {step.detail && (
                <Typography variant="caption" color="text.secondary" display="block" noWrap>
                  {step.detail}
                </Typography>
              )}
            </Box>
          </MotionBox>
        );
      })}
    </Stack>
  );
};
