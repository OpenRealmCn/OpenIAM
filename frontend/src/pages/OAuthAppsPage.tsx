import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  ContentCopy as CopyIcon,
  Delete as DeleteIcon,
  Refresh as RotateIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { OAuthClient } from '../types/api';

export const OAuthAppsPage: React.FC = () => {
  const { currentDomain } = useAuth();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({
    name: '',
    description: '',
    redirect_uris_text: 'http://localhost:3000/callback',
    scopes_text: 'openid profile email',
    require_pkce: true,
    is_confidential: true,
  });

  const [secretModal, setSecretModal] = useState<{ client_id: string; client_secret: string } | null>(null);

  const loadClients = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.oauthClients.list(currentDomain);
      setClients(list || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    loadClients();
  }, [loadClients]);

  const handleCreate = async () => {
    try {
      const redirect_uris = form.redirect_uris_text
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const scopes = form.scopes_text.split(/\s+/).filter(Boolean);
      const res = await api.oauthClients.create({
        name: form.name,
        description: form.description,
        domain_code: currentDomain,
        redirect_uris,
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
        scopes,
        require_pkce: form.require_pkce,
        is_confidential: form.is_confidential,
      });
      setCreateOpen(false);
      if (res.client_secret) {
        setSecretModal({ client_id: res.client.client_id, client_secret: res.client_secret });
      }
      await loadClients();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRotate = async (row: OAuthClient) => {
    try {
      const res = await api.oauthClients.rotateSecret(row.id);
      setSecretModal({ client_id: res.client_id, client_secret: res.client_secret });
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.oauthClients.delete(id);
      await loadClients();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<OAuthClient>[] = [
    { field: 'name', headerName: '应用名称', width: 170 },
    {
      field: 'client_id',
      headerName: 'Client ID',
      width: 220,
      renderCell: (p) => (
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Typography variant="body2" fontFamily="monospace" fontSize="0.8rem">
            {p.value}
          </Typography>
          <Tooltip title="复制 Client ID">
            <IconButton size="small" onClick={() => navigator.clipboard.writeText(p.value)}>
              <CopyIcon fontSize="inherit" />
            </IconButton>
          </Tooltip>
        </Stack>
      ),
    },
    { field: 'domain_code', headerName: '所属域', width: 110 },
    {
      field: 'redirect_uris',
      headerName: '回调地址白名单',
      flex: 1,
      minWidth: 220,
      valueFormatter: (v: string[]) => (v || []).join(', '),
    },
    {
      field: 'require_pkce',
      headerName: 'PKCE',
      width: 85,
      renderCell: (p) => <Chip size="small" label={p.value ? '强制' : '可选'} color={p.value ? 'primary' : 'default'} />,
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 110,
      getActions: (p) => [
        ...(p.row.is_confidential
          ? [
              <GridActionsCellItem
                key="rot"
                icon={<RotateIcon />}
                label="轮换 Secret"
                onClick={() => handleRotate(p.row)}
              />,
            ]
          : []),
        <GridActionsCellItem
          key="del"
          icon={<DeleteIcon />}
          label="删除应用"
          onClick={() => handleDelete(p.row.id)}
        />,
      ],
    },
  ];

  const baseOrigin = window.location.origin;

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">OpenIAM OAuth 2.0 / OIDC 应用接入</Typography>
          <Typography variant="body2" color="text.secondary">
            创建并管理接入 OpenIAM 授权服务端的子系统与第三方应用
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          创建 OAuth 应用
        </Button>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Typography variant="subtitle2" fontWeight={700} mb={1}>
            标准 OIDC / OAuth 2.0 接入端点（支持客户端自动发现）
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} flexWrap="wrap" useFlexGap>
            <Chip size="small" variant="outlined" label={`Discovery: ${baseOrigin}/.well-known/openid-configuration`} />
            <Chip size="small" variant="outlined" label={`JWKS: ${baseOrigin}/.well-known/jwks.json`} />
            <Chip size="small" variant="outlined" label={`Authorize: ${baseOrigin}/oauth2/authorize`} />
            <Chip size="small" variant="outlined" label={`Token: ${baseOrigin}/oauth2/token`} />
            <Chip size="small" variant="outlined" label={`UserInfo: ${baseOrigin}/oauth2/userinfo`} />
          </Stack>
        </CardContent>
      </Card>

      <Box sx={{ height: 500 }}>
        <DataGrid
          rows={clients}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>

      {/* 创建应用弹窗 */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>创建 OAuth 2.0 应用 ({currentDomain})</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="应用名称"
              size="small"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <TextField
              label="应用描述"
              size="small"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
            <TextField
              label="回调地址白名单（每行一个 URL）"
              size="small"
              multiline
              rows={3}
              required
              value={form.redirect_uris_text}
              onChange={(e) => setForm({ ...form, redirect_uris_text: e.target.value })}
            />
            <TextField
              label="允许的 Scopes（空格分隔）"
              size="small"
              value={form.scopes_text}
              onChange={(e) => setForm({ ...form, scopes_text: e.target.value })}
            />
            <Stack direction="row" spacing={2}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={form.require_pkce}
                    onChange={(e) => setForm({ ...form, require_pkce: e.target.checked })}
                  />
                }
                label="强制启用 PKCE"
              />
              <FormControlLabel
                control={
                  <Checkbox
                    checked={form.is_confidential}
                    onChange={(e) => setForm({ ...form, is_confidential: e.target.checked })}
                  />
                }
                label="机密客户端 (生成 Secret)"
              />
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleCreate}>
            创建应用
          </Button>
        </DialogActions>
      </Dialog>

      {/* 一次性 Secret 展示弹窗 */}
      <Dialog open={Boolean(secretModal)} onClose={() => setSecretModal(null)} maxWidth="sm" fullWidth>
        <DialogTitle>请妥善保存应用凭证</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Client Secret 仅展示一次，关闭弹窗后系统不再明文保存。如遗失请使用“轮换 Secret”。
          </Alert>
          <Stack spacing={1.5}>
            <TextField label="Client ID" size="small" value={secretModal?.client_id || ''} InputProps={{ readOnly: true }} />
            <TextField
              label="Client Secret"
              size="small"
              value={secretModal?.client_secret || ''}
              InputProps={{ readOnly: true }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              if (secretModal) {
                navigator.clipboard.writeText(`Client ID: ${secretModal.client_id}\nClient Secret: ${secretModal.client_secret}`);
              }
            }}
          >
            复制凭证
          </Button>
          <Button variant="contained" onClick={() => setSecretModal(null)}>
            我已保存
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
