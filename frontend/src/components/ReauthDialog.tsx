import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from '@mui/material';
import { api, setReauthHandler } from '../api/client';
import { useAuth } from '../context/AuthContext';

// 全局身份再确认弹窗：敏感操作返回 reauth_required 时弹出，验证通过后由请求拦截器自动重试原请求。
export const ReauthDialog: React.FC = () => {
  const { hasPassword, totpEnabled } = useAuth();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pending = useRef<((ok: boolean) => void) | null>(null);

  const settle = useCallback((ok: boolean) => {
    pending.current?.(ok);
    pending.current = null;
    setOpen(false);
    setPassword('');
    setCode('');
    setError('');
  }, []);

  useEffect(() => {
    setReauthHandler(
      () =>
        new Promise<boolean>((resolve) => {
          pending.current?.(false);
          pending.current = resolve;
          setError('');
          setOpen(true);
        }),
    );
    return () => setReauthHandler(null);
  }, []);

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!password && !code.trim()) {
      setError(hasPassword ? '请输入当前登录密码' : '请输入验证器动态码');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await api.auth.reauth({ password: password || undefined, code: code.trim() || undefined });
      settle(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={() => !busy && settle(false)} maxWidth="xs" fullWidth>
      <form onSubmit={handleSubmit}>
        <DialogTitle>验证身份</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <Typography variant="body2" color="text.secondary">
              这是一项敏感操作，需要先确认是你本人。验证通过后 5 分钟内无需再次验证。
            </Typography>
            {error && <Alert severity="error">{error}</Alert>}
            {hasPassword && (
              <TextField
                label="当前登录密码"
                type="password"
                size="small"
                fullWidth
                autoFocus
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            )}
            {totpEnabled && (
              <TextField
                label={hasPassword ? '或输入验证器动态码' : '验证器动态码'}
                size="small"
                fullWidth
                autoFocus={!hasPassword}
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => settle(false)} disabled={busy}>
            取消
          </Button>
          <Button type="submit" variant="contained" disabled={busy}>
            {busy ? '验证中…' : '确认'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};
