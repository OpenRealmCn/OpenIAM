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
  Key as CodeIcon,
  Refresh as RotateIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { OAuthClient } from '../types/api';

export const OAuthAppsPage: React.FC = () => {
  const { currentDomain } = useAuth();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [selfServiceMode, setSelfServiceMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({
    name: '',
    description: '',
    redirect_uris_text: '',
    scopes_text: 'openid profile email',
    require_pkce: true,
    is_confidential: true,
  });

  const [secretModal, setSecretModal] = useState<{ client_id: string; client_secret: string } | null>(null);
  const [codeModal, setCodeModal] = useState<{
    client: OAuthClient;
    redirect_uri: string;
    scopes: string;
    generated?: { code: string; redirect_uri: string; expires_in: number };
  } | null>(null);

  const loadClients = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const list = await api.oauthClients.list(currentDomain);
      setClients(list || []);
      setSelfServiceMode(false);
    } catch {
      // 普通用户无全局管理权限时自动切换至个人应用视角
      try {
        const myList = await api.myOAuthClients.list();
        setClients(myList || []);
        setSelfServiceMode(true);
      } catch (err) {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    loadClients();
  }, [loadClients]);

  const handleRefresh = () => {
    setRefreshCount((c) => c + 1);
    loadClients();
  };

  const handleCreate = async () => {
    try {
      const redirect_uris = form.redirect_uris_text
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const scopes = form.scopes_text.split(/\s+/).filter(Boolean);
      const payload = {
        name: form.name,
        description: form.description,
        domain_code: currentDomain,
        redirect_uris,
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
        scopes,
        require_pkce: form.require_pkce,
        is_confidential: form.is_confidential,
      };
      const res = selfServiceMode
        ? await api.myOAuthClients.create(payload)
        : await api.oauthClients.create(payload);
      setCreateOpen(false);
      setForm({
        name: '',
        description: '',
        redirect_uris_text: '',
        scopes_text: 'openid profile email',
        require_pkce: true,
        is_confidential: true,
      });
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
      const res = selfServiceMode
        ? await api.myOAuthClients.rotateSecret(row.id)
        : await api.oauthClients.rotateSecret(row.id);
      setSecretModal({ client_id: res.client_id, client_secret: res.client_secret });
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      if (selfServiceMode) {
        await api.myOAuthClients.delete(id);
      } else {
        await api.oauthClients.delete(id);
      }
      await loadClients();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleGenerateCode = async () => {
    if (!codeModal) return;
    try {
      const res = await api.oauth2Server.createCode({
        client_id: codeModal.client.client_id,
        redirect_uri: codeModal.redirect_uri,
        scopes: codeModal.scopes.split(/\s+/).filter(Boolean),
      });
      setCodeModal({ ...codeModal, generated: res });
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
      minWidth: 200,
      valueFormatter: (v: string[]) => (v || []).join(', '),
    },
    {
      field: 'require_pkce',
      headerName: 'PKCE',
      width: 80,
      renderCell: (p) => <Chip size="small" label={p.value ? '强制' : '可选'} color={p.value ? 'primary' : 'default'} />,
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 140,
      getActions: (p) => [
        <GridActionsCellItem
          key="code"
          icon={<CodeIcon />}
          label="生成授权码 (Code)"
          onClick={() =>
            setCodeModal({
              client: p.row,
              redirect_uri: p.row.redirect_uris?.[0] || '',
              scopes: (p.row.scopes || ['openid', 'profile', 'email']).join(' '),
            })
          }
        />,
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
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1.5} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="h5">{selfServiceMode ? '我的应用' : '应用管理'}</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            创建 OAuth 2.0 / OIDC 应用，并支持为用户生成一次性授权码（Code）
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.2}>
          <Button
            variant="outlined"
            startIcon={<AnimatedRefreshIcon spinning={loading} spinCount={refreshCount} />}
            onClick={handleRefresh}
          >
            刷新
          </Button>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
            创建应用
          </Button>
        </Stack>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Typography variant="subtitle2" fontWeight={700} mb={1}>
            标准 OIDC / OAuth 2.0 接入端点
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} flexWrap="wrap" useFlexGap>
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
              placeholder="https://app.example.com/callback"
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

      {/* 生成 OAuth 2.0 授权码 (Code) 弹窗 */}
      <Dialog open={Boolean(codeModal)} onClose={() => setCodeModal(null)} maxWidth="sm" fullWidth>
        <DialogTitle>生成授权码 — {codeModal?.client.name}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="回调地址 (Redirect URI)"
              size="small"
              value={codeModal?.redirect_uri || ''}
              onChange={(e) => codeModal && setCodeModal({ ...codeModal, redirect_uri: e.target.value })}
              fullWidth
            />
            <TextField
              label="授权范围 (Scopes)"
              size="small"
              value={codeModal?.scopes || ''}
              onChange={(e) => codeModal && setCodeModal({ ...codeModal, scopes: e.target.value })}
              fullWidth
            />

            {codeModal?.generated && (
              <Alert severity="success">
                <Typography variant="subtitle2" mb={0.8}>
                  已签发一次性授权码（有效期 {codeModal.generated.expires_in} 秒）：
                </Typography>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
                    {codeModal.generated.code}
                  </Typography>
                  <Tooltip title="复制授权码">
                    <IconButton
                      size="small"
                      onClick={() => navigator.clipboard.writeText(codeModal.generated?.code || '')}
                    >
                      <CopyIcon fontSize="inherit" />
                    </IconButton>
                  </Tooltip>
                </Stack>
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCodeModal(null)}>关闭</Button>
          <Button variant="contained" onClick={handleGenerateCode}>
            生成授权码
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
