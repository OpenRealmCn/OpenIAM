import React, { useState } from 'react';
import { alpha, Avatar, Box, Stack, Typography, useMediaQuery, useTheme } from '@mui/material';
import { useSite } from '../context/SiteContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';

export interface OAuthIdentity {
  name: string;
  handle?: string;
  hint?: string;
  avatarUrl?: string;
  fallback: string;
  label: string;
}

interface OAuthStageProps {
  identity: OAuthIdentity;
  children: React.ReactNode;
}

export const OAuthStage: React.FC<OAuthStageProps> = ({ identity, children }) => {
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down('md'));
  const { siteInfo } = useSite();
  const scale = MOTION_SPEED_SCALE[useThemeStore((s) => s.motionSpeed)] ?? 1;
  const [logoError, setLogoError] = useState(false);
  const isDark = theme.palette.mode === 'dark';

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', md: 'minmax(280px, 360px) 1fr' },
        bgcolor: 'background.default',
      }}
    >
      <Box
        component="aside"
        sx={{
          position: 'relative',
          display: 'flex',
          flexDirection: compact ? 'row' : 'column',
          justifyContent: compact ? 'flex-start' : 'space-between',
          gap: 2,
          px: { xs: 2.5, md: 4 },
          py: { xs: 2, md: 4 },
          bgcolor: isDark ? alpha(theme.palette.primary.main, 0.08) : alpha(theme.palette.primary.main, 0.05),
          borderRight: { md: 1 },
          borderBottom: { xs: 1, md: 0 },
          borderColor: 'divider',
          overflow: 'hidden',
        }}
      >
        <Box
          aria-hidden
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: { xs: '100%', md: 2 },
            height: { xs: 2, md: '100%' },
            bgcolor: 'primary.main',
            transformOrigin: { xs: 'left center', md: 'center top' },
            animation:
              scale === 0
                ? 'none'
                : {
                    xs: 'oauth-edge-x 0.7s cubic-bezier(0.22, 1, 0.36, 1) both',
                    md: 'oauth-edge-y 0.7s cubic-bezier(0.22, 1, 0.36, 1) both',
                  },
            '@keyframes oauth-edge-x': {
              from: { transform: 'scaleX(0)' },
              to: { transform: 'scaleX(1)' },
            },
            '@keyframes oauth-edge-y': {
              from: { transform: 'scaleY(0)' },
              to: { transform: 'scaleY(1)' },
            },
          }}
        />

        <Stack direction="row" spacing={1} alignItems="center">
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
                display: 'grid',
                placeItems: 'center',
                fontSize: 13,
                fontWeight: 700,
              }}
            >
              {(siteInfo.name || 'O').slice(0, 1)}
            </Box>
          )}
          <Typography variant="body2" fontWeight={600}>
            {siteInfo.name || 'OpenIAM'}
          </Typography>
        </Stack>

        <Stack direction="row" spacing={1.5} alignItems={compact ? 'center' : 'flex-start'} sx={{ minWidth: 0 }}>
          <Avatar src={identity.avatarUrl || undefined} sx={{ width: compact ? 36 : 52, height: compact ? 36 : 52, bgcolor: 'primary.main', fontWeight: 700 }}>
            {identity.fallback}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary">
              {identity.label}
            </Typography>
            <Typography variant={compact ? 'body1' : 'h6'} fontWeight={700} letterSpacing="-0.02em" noWrap>
              {identity.name}
            </Typography>
            {(identity.handle || identity.hint) && (
              <Typography variant="caption" color="text.secondary" noWrap display="block">
                {[identity.handle, identity.hint].filter(Boolean).join(' · ')}
              </Typography>
            )}
          </Box>
        </Stack>

        {!compact && (
          <Typography variant="caption" color="text.disabled">
            OAuth 2.0 / OIDC
            {siteInfo.footer_text ? ` · ${siteInfo.footer_text}` : ''}
          </Typography>
        )}
      </Box>

      <Box
        component="main"
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          px: { xs: 2.5, sm: 6 },
          py: { xs: 3, md: 6 },
        }}
      >
        <Box sx={{ width: '100%', maxWidth: 520 }}>{children}</Box>
      </Box>
    </Box>
  );
};

export interface OAuthScopeItem {
  id: string;
  label: string;
  token: string;
  icon: React.ReactNode;
}

export const OAuthScopeList: React.FC<{ items: OAuthScopeItem[] }> = ({ items }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';

  return (
    <Stack component="ul" spacing={0} sx={{ listStyle: 'none', m: 0, p: 0 }}>
      {items.map((item) => (
        <Stack
          component="li"
          key={item.id}
          direction="row"
          spacing={1.5}
          alignItems="center"
          sx={{ py: 1.35, borderTop: 1, borderColor: 'divider' }}
        >
          <Box
            sx={{
              width: 32,
              height: 32,
              borderRadius: '10px',
              display: 'grid',
              placeItems: 'center',
              flexShrink: 0,
              color: 'primary.main',
              bgcolor: alpha(theme.palette.primary.main, isDark ? 0.16 : 0.08),
            }}
          >
            {item.icon}
          </Box>
          <Typography variant="body2" sx={{ flex: 1, minWidth: 0 }}>
            {item.label}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'ui-monospace, monospace' }}>
            {item.token}
          </Typography>
        </Stack>
      ))}
    </Stack>
  );
};

export interface OAuthStep {
  key: string;
  label: string;
  detail?: string;
  status: 'pending' | 'active' | 'done' | 'error';
}

export const OAuthStepList: React.FC<{ steps: OAuthStep[] }> = ({ steps }) => {
  const theme = useTheme();

  return (
    <Stack component="ol" spacing={0} sx={{ listStyle: 'none', m: 0, p: 0 }}>
      {steps.map((step, idx) => {
        const color =
          step.status === 'error'
            ? theme.palette.error.main
            : step.status === 'done'
              ? theme.palette.success.main
              : step.status === 'active'
                ? theme.palette.primary.main
                : theme.palette.text.disabled;
        return (
          <Box component="li" key={step.key} sx={{ display: 'flex', gap: 1.75 }}>
            <Box sx={{ width: 16, display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  mt: '7px',
                  borderRadius: '50%',
                  bgcolor: color,
                  boxShadow: step.status === 'active' ? `0 0 0 4px ${alpha(color, 0.16)}` : 'none',
                }}
              />
              {idx < steps.length - 1 && <Box sx={{ width: '1px', flex: 1, minHeight: 18, my: '4px', bgcolor: 'divider' }} />}
            </Box>
            <Box sx={{ pb: 2, minWidth: 0 }}>
              <Typography variant="body2" fontWeight={step.status === 'pending' ? 500 : 600} color={step.status === 'error' ? 'error.main' : 'text.primary'}>
                {step.label}
              </Typography>
              {step.detail && (
                <Typography variant="caption" color="text.secondary" display="block">
                  {step.detail}
                </Typography>
              )}
            </Box>
          </Box>
        );
      })}
    </Stack>
  );
};
