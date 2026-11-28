import React, { useState } from 'react';
import { Alert, Box, Button, Card, CardContent, CircularProgress, Stack, TextField, Typography } from '@mui/material';
import { Navigate, useNavigate } from 'react-router-dom';
import { api, clearTokens } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { INITIAL_PASSWORD_POLICY, passwordHint, takePostChangeRedirect, validatePassword } from '../utils/password';
import { safeInternalPath } from '../utils/redirect';

// 强制改密页：初始管理员以及被标记的存量账号，登录后只能先走这里。
// 后端改密成功会吊销全部旧会话，所以完成后一律回登录页重新登录。
export const ChangePasswordPage: React.FC = () => {
  const { user, loading, mustChangePassword, logout } = useAuth();
  const navigate = useNavigate();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
        <CircularProgress />
      </Box>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  if (!mustChangePassword) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const policyErr = validatePassword(newPassword, INITIAL_PASSWORD_POLICY);
    if (policyErr) {
      setError(policyErr);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致');
      return;
    }
    setSubmitting(true);
    try {
      await api.auth.changePassword(oldPassword, newPassword);
      clearTokens();
      const next = takePostChangeRedirect();
      const redirect = next ? `&redirect=${encodeURIComponent(safeInternalPath(next))}` : '';
      window.location.replace(`/login?changed=1${redirect}`);
    } catch (err) {
      setError((err as Error).message);
      setSubmitting(false);
    }
  };

  const handleSwitchAccount = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center', p: 2 }}>
      <Card sx={{ width: '100%', maxWidth: 460 }}>
        <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
          <Stack spacing={2} component="form" onSubmit={handleSubmit}>
            <Typography variant="h6">请先设置新密码</Typography>
            <Typography variant="body2" color="text.secondary">
              为了账号安全，账号 {user.username} 需要先设置一个新密码，完成后请用新密码重新登录。
            </Typography>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="当前密码"
              type="password"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              required
              fullWidth
              autoComplete="current-password"
            />
            <TextField
              label="新密码"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              fullWidth
              autoComplete="new-password"
              helperText={`${passwordHint(INITIAL_PASSWORD_POLICY)}，且不能使用系统默认密码`}
            />
            <TextField
              label="确认新密码"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              fullWidth
              autoComplete="new-password"
            />
            <Button type="submit" variant="contained" disabled={submitting}>
              {submitting ? '提交中…' : '修改密码并重新登录'}
            </Button>
            <Button variant="text" color="inherit" onClick={handleSwitchAccount} disabled={submitting}>
              退出，换个账号登录
            </Button>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
};
