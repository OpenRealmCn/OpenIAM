import React, { useState } from 'react';
import { alpha, Box, Card, CardContent, Stack, Typography, useTheme } from '@mui/material';
import { CloseRounded as ErrorIcon, LockRounded as LockIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';

const MotionBox = motion.create(Box);
const EASE = [0.22, 1, 0.36, 1] as const;

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

export const OAuthBackdrop: React.FC<OAuthBackdropProps> = ({ children, maxWidth = 440 }) => {
  const theme = useTheme();
  const { siteInfo } = useSite();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const [logoError, setLogoError] = useState(false);

  const isDark = theme.palette.mode === 'dark';
  const radius = Number(theme.shape.borderRadius);
  const dot = alpha(theme.palette.text.primary, isDark ? 0.07 : 0.055);

  return (
    <Box
      sx={{
        position: 'relative',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        px: 2,
        py: 5,
        bgcolor: 'background.default',
      }}
    >
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          backgroundImage: `radial-gradient(circle at 50% 18%, ${alpha(theme.palette.primary.main, isDark ? 0.16 : 0.09)} 0%, transparent 42%)`,
        }}
      />
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          backgroundImage: `radial-gradient(${dot} 1px, transparent 1px)`,
          backgroundSize: '18px 18px',
          maskImage: 'radial-gradient(ellipse 70% 58% at 50% 42%, #000 20%, transparent 78%)',
          WebkitMaskImage: 'radial-gradient(ellipse 70% 58% at 50% 42%, #000 20%, transparent 78%)',
        }}
      />

      <MotionBox
        initial={scale === 0 ? false : { opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={scale === 0 ? { duration: 0 } : { type: 'spring', stiffness: 420, damping: 36, mass: 0.85 }}
        sx={{ position: 'relative', zIndex: 1, width: '100%', maxWidth }}
      >
        <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" mb={2.5}>
          {siteInfo.logo_url && !logoError ? (
            <Box
              component="img"
              src={siteInfo.logo_url}
              alt=""
              onError={() => setLogoError(true)}
              sx={{ width: 28, height: 28, borderRadius: '8px', objectFit: 'contain' }}
            />
          ) : (
            <Box
              sx={{
                width: 28,
                height: 28,
                borderRadius: '8px',
                bgcolor: 'primary.main',
                color: 'primary.contrastText',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 13,
                fontWeight: 700,
              }}
            >
              {(siteInfo.name || 'O').slice(0, 1)}
            </Box>
          )}
            <Typography variant="body2" fontWeight={600} letterSpacing="-0.01em">
            {siteInfo.name || 'OpenIAM'}
          </Typography>
        </Stack>

        <Card
          elevation={0}
          sx={{
            borderRadius: `${Math.max(18, radius + 6)}px`,
            bgcolor: 'background.paper',
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 1 : 0.9)}`,
            boxShadow: isDark
              ? '0 24px 60px rgba(0, 0, 0, 0.45)'
              : '0 1px 2px rgba(15, 23, 42, 0.04), 0 18px 50px rgba(15, 23, 42, 0.07)',
          }}
        >
          <CardContent sx={{ p: { xs: 2.75, sm: 3.5 }, '&:last-child': { pb: { xs: 2.75, sm: 3.5 } } }}>
            {children}
          </CardContent>
        </Card>

        <Stack direction="row" spacing={0.6} alignItems="center" justifyContent="center" mt={2.25}>
          <LockIcon sx={{ fontSize: 13, color: 'success.main' }} />
          <Typography variant="caption" color="text.secondary">
            OAuth 2.0 / OIDC
          </Typography>
          {siteInfo.footer_text && (
            <Typography variant="caption" color="text.disabled">
              · {siteInfo.footer_text}
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

export const IdentityHandshakeDiagram: React.FC<IdentityHandshakeDiagramProps> = ({
  leftNode,
  rightNode,
  status,
}) => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const isDark = theme.palette.mode === 'dark';

  const track =
    status === 'success'
      ? theme.palette.success.main
      : status === 'error'
        ? theme.palette.error.main
        : theme.palette.primary.main;

  const tile = (node: HandshakeNode) => {
    const accent = node.accent || theme.palette.primary.main;
    return (
      <Stack alignItems="center" spacing={0.75} sx={{ width: '100%', minWidth: 0 }}>
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: alpha(accent, isDark ? 0.16 : 0.08),
            color: accent,
            border: `1px solid ${alpha(accent, 0.18)}`,
          }}
        >
          {node.icon}
        </Box>
        <Box sx={{ width: '100%', textAlign: 'center' }}>
          <Typography
            variant="caption"
            fontWeight={700}
            sx={{
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
              lineHeight: 1.35,
            }}
          >
            {node.label}
          </Typography>
          {node.subLabel && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ fontSize: '0.68rem', mt: 0.15 }}>
              {node.subLabel}
            </Typography>
          )}
        </Box>
      </Stack>
    );
  };

  return (
    <MotionBox
      animate={status === 'error' && scale > 0 ? { x: [0, -4, 4, -2, 0] } : { x: 0 }}
      transition={{ duration: 0.32 }}
      sx={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 108px) minmax(56px, 1fr) minmax(0, 108px)',
        alignItems: 'start',
        columnGap: 0.5,
      }}
    >
      {tile(leftNode)}

      <Box sx={{ height: 56, display: 'flex', alignItems: 'center', position: 'relative' }}>
        <Box component="svg" viewBox="0 0 120 32" sx={{ width: '100%', height: 32, overflow: 'visible' }}>
          <motion.path
            d="M2 16H118"
            fill="none"
            stroke={track}
            strokeWidth="1.5"
            strokeLinecap="round"
            initial={scale === 0 ? false : { pathLength: 0, opacity: 0.35 }}
            animate={{ pathLength: 1, opacity: status === 'idle' ? 0.55 : 1 }}
            transition={{ duration: 0.55 * Math.max(scale, 0.01), ease: EASE, delay: 0.12 * scale }}
          />
        </Box>
        <MotionBox
          key={status}
          initial={scale === 0 ? false : { scale: 0.86, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={scale === 0 ? { duration: 0 } : { type: 'spring', stiffness: 460, damping: 26, delay: 0.38 * scale }}
          sx={{
            position: 'absolute',
            left: '50%',
            top: '50%',
            ml: '-13px',
            mt: '-13px',
            width: 26,
            height: 26,
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: status === 'error' ? 'error.main' : status === 'success' ? 'success.main' : 'primary.main',
            color: '#fff',
            boxShadow: `0 0 0 4px ${theme.palette.background.paper}`,
          }}
        >
          {status === 'error' ? (
            <ErrorIcon sx={{ fontSize: 15 }} />
          ) : status === 'verifying' && scale > 0 ? (
            <Box
              component={motion.span}
              animate={{ rotate: 360 }}
              transition={{ duration: 0.9, repeat: Infinity, ease: 'linear' }}
              sx={{
                width: 12,
                height: 12,
                borderRadius: '50%',
                border: '1.5px solid rgba(255,255,255,0.35)',
                borderTopColor: '#fff',
                display: 'block',
              }}
            />
          ) : (
            <Box component="svg" width="13" height="13" viewBox="0 0 24 24" fill="none">
              <motion.path
                d="M5 13l4 4L19 7"
                stroke="#fff"
                strokeWidth="2.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                initial={scale === 0 ? false : { pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.28 * Math.max(scale, 0.01), delay: 0.48 * scale, ease: 'easeOut' }}
              />
            </Box>
          )}
        </MotionBox>
      </Box>

      {tile(rightNode)}
    </MotionBox>
  );
};

interface AuthStageTimelineProps {
  steps: AuthStageStep[];
}

export const AuthStageTimeline: React.FC<AuthStageTimelineProps> = ({ steps }) => {
  const theme = useTheme();
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  return (
    <Stack spacing={0}>
      {steps.map((step, idx) => {
        const done = step.status === 'done';
        const active = step.status === 'active';
        const failed = step.status === 'error';
        const color = failed
          ? theme.palette.error.main
          : done
            ? theme.palette.success.main
            : active
              ? theme.palette.primary.main
              : theme.palette.text.disabled;

        return (
          <MotionBox
            key={step.key}
            initial={scale === 0 ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.2 * scale, delay: idx * 0.04 * scale }}
            sx={{ display: 'flex', gap: 1.5, minHeight: 52 }}
          >
            <Box sx={{ width: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  mt: '6px',
                  borderRadius: '50%',
                  bgcolor: color,
                  boxShadow: active ? `0 0 0 4px ${alpha(color, 0.16)}` : 'none',
                  flexShrink: 0,
                }}
              />
              {idx < steps.length - 1 && (
                <Box sx={{ width: 1, flex: 1, my: 0.5, bgcolor: alpha(theme.palette.divider, 0.9) }} />
              )}
            </Box>
            <Box sx={{ pb: 1.25, minWidth: 0 }}>
              <Typography variant="body2" fontWeight={active || done ? 600 : 500} color={failed ? 'error.main' : 'text.primary'}>
                {step.label}
              </Typography>
              {step.detail && (
                <Typography variant="caption" color="text.secondary" display="block">
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
