import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  alpha,
  Box,
  CircularProgress,
  LinearProgress,
  Stack,
  Typography,
  useTheme,
} from '@mui/material';
import {
  CheckCircle as VerifiedIcon,
  Refresh as RefreshIcon,
  Security as ShieldIcon,
} from '@mui/icons-material';
import { api } from '../api/client';
import { CaptchaPublicConfig } from '../types/api';

interface CapWidgetProps {
  scene: 'login' | 'register' | 'otp';
  onToken: (token: string) => void;
  resetSignal?: number;
}

async function solvePowItem(salt: string, index: number, difficulty: number): Promise<number> {
  const prefix = '0'.repeat(difficulty);
  const encoder = new TextEncoder();
  let nonce = 0;
  while (true) {
    const input = encoder.encode(`${salt}:${index}:${nonce}`);
    const digest = await crypto.subtle.digest('SHA-256', input);
    const bytes = new Uint8Array(digest);
    let hex = '';
    for (let i = 0; i < Math.ceil(difficulty / 2) + 1 && i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    if (hex.startsWith(prefix)) {
      return nonce;
    }
    nonce++;
    if (nonce % 500 === 0) {
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}

// Cap (https://trycap.dev/) 人机验证插槽组件：支持本地自运行 PoW 求解与远端 Cap 部署模式
export const CapWidget: React.FC<CapWidgetProps> = ({ scene, onToken, resetSignal = 0 }) => {
  const theme = useTheme();
  const [cfg, setCfg] = useState<CaptchaPublicConfig | null>(null);
  const [status, setStatus] = useState<'idle' | 'solving' | 'verified' | 'error'>('idle');
  const [progress, setProgress] = useState(0);
  const [errMsg, setErrMsg] = useState('');
  const runningRef = useRef(false);

  useEffect(() => {
    api.captcha
      .config()
      .then((res: CaptchaPublicConfig) => setCfg(res))
      .catch(() => setCfg(null));
  }, []);

  useEffect(() => {
    if (resetSignal > 0) {
      setStatus('idle');
      setProgress(0);
      setErrMsg('');
      onToken('');
    }
  }, [resetSignal, onToken]);

  const sceneEnabled = Boolean(
    cfg?.enabled &&
      ((scene === 'login' && cfg.protect_login) ||
        (scene === 'register' && cfg.protect_register) ||
        (scene === 'otp' && cfg.protect_otp)),
  );

  const handleVerify = useCallback(async () => {
    if (!cfg || runningRef.current || status === 'verified') return;
    runningRef.current = true;
    setStatus('solving');
    setProgress(5);
    setErrMsg('');
    try {
      if (cfg.mode === 'remote' && cfg.remote_endpoint) {
        const base = cfg.remote_endpoint.replace(/\/+$/, '');
        const chRes = await fetch(`${base}/challenge`, { method: 'POST' });
        const chData = await chRes.json();
        const c = Number(chData?.challenge?.c || 16);
        const s = String(chData?.challenge?.s || '');
        const d = Number(chData?.challenge?.d || 4);
        const solutions: number[] = [];
        for (let i = 0; i < c; i++) {
          solutions.push(await solvePowItem(s, i, d));
          setProgress(Math.round(((i + 1) / c) * 90));
        }
        const rdRes = await fetch(`${base}/redeem`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: chData.token, solutions }),
        });
        const rdData = await rdRes.json();
        if (!rdData?.success || !rdData?.token) {
          throw new Error(rdData?.error || '远端人机验证未通过');
        }
        setProgress(100);
        setStatus('verified');
        onToken(rdData.token);
      } else {
        const chData = await api.captcha.capChallenge();
        const c = Number(chData?.challenge?.c || 16);
        const s = String(chData?.challenge?.s || '');
        const d = Number(chData?.challenge?.d || 4);
        const solutions: number[] = [];
        for (let i = 0; i < c; i++) {
          solutions.push(await solvePowItem(s, i, d));
          setProgress(Math.round(((i + 1) / c) * 90));
        }
        const rdData = await api.captcha.capRedeem(chData.token, solutions);
        if (!rdData?.success || !rdData?.token) {
          throw new Error(rdData?.error || '人机验证未通过');
        }
        setProgress(100);
        setStatus('verified');
        onToken(rdData.token);
      }
    } catch (err) {
      setStatus('error');
      setErrMsg((err as Error).message || '验证失败，请点击重试');
      onToken('');
    } finally {
      runningRef.current = false;
    }
  }, [cfg, status, onToken]);

  if (!sceneEnabled) {
    return null;
  }

  return (
    <Box
      onClick={status === 'idle' || status === 'error' ? handleVerify : undefined}
      sx={{
        p: 1.4,
        borderRadius: 2,
        border: 1,
        borderColor:
          status === 'verified'
            ? 'success.main'
            : status === 'error'
              ? 'error.main'
              : 'divider',
        bgcolor:
          status === 'verified'
            ? alpha(theme.palette.success.main, 0.06)
            : alpha(theme.palette.text.primary, 0.03),
        cursor: status === 'idle' || status === 'error' ? 'pointer' : 'default',
        userSelect: 'none',
        transition: 'all 0.2s ease',
        '&:hover':
          status === 'idle' || status === 'error'
            ? { borderColor: 'primary.main', bgcolor: alpha(theme.palette.primary.main, 0.05) }
            : undefined,
      }}
    >
      <Stack direction="row" spacing={1.5} alignItems="center" justifyContent="space-between">
        <Stack direction="row" spacing={1.2} alignItems="center">
          {status === 'solving' ? (
            <CircularProgress size={20} />
          ) : status === 'verified' ? (
            <VerifiedIcon color="success" fontSize="small" />
          ) : (
            <ShieldIcon color={status === 'error' ? 'error' : 'primary'} fontSize="small" />
          )}
          <Box>
            <Typography variant="body2" fontWeight={600}>
              {status === 'idle' && '点击完成人机安全验证'}
              {status === 'solving' && `正在验证环境安全性（${progress}%）...`}
              {status === 'verified' && '已通过人机安全验证'}
              {status === 'error' && '验证失败，点击重试'}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              安全人机验证保护中
            </Typography>
          </Box>
        </Stack>
        {status === 'error' && <RefreshIcon fontSize="small" color="error" />}
      </Stack>
      {status === 'solving' && <LinearProgress variant="determinate" value={progress} sx={{ mt: 1, borderRadius: 1 }} />}
      {status === 'error' && errMsg && (
        <Alert severity="error" sx={{ mt: 1, py: 0 }}>
          {errMsg}
        </Alert>
      )}
    </Box>
  );
};
