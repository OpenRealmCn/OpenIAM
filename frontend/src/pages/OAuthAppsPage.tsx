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
  FormControl,
  FormControlLabel,
  FormGroup,
  FormHelperText,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  ContentCopy as CopyIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Key as CodeIcon,
  Refresh as RotateIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { api, ApiError } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { OAuthClient } from '../types/api';

const GRANT_TYPE_OPTIONS = [
  { value: 'authorization_code', label: '授权码模式（authorization_code）' },
  { value: 'refresh_token', label: '刷新令牌（refresh_token）' },
  { value: 'client_credentials', label: '客户端凭证（client_credentials）' },
] as const;

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const codeVerifier = base64UrlEncode(randomBytes);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = base64UrlEncode(new Uint8Array(digest));
  return { codeVerifier, codeChallenge };
}

export const OAuthAppsPage: React.FC = () => {
  const { currentDomain, hasCap } = useAuth();
  const confirm = useConfirm();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [selfServiceMode, setSelfServiceMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');

  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [saving, setSaving] = useState(false);
  const [editingClient, setEditingClient] = useState<OAuthClient | null>(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    redirect_uris_text: '',
    scopes_text: 'openid profile email',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'] as string[],
    require_pkce: true,
    is_confidential: true,
    status: 'active',
  });

  const [secretModal, setSecretModal] = useState<{ client_id: string; client_secret: string } | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);
  const [codeModal, setCodeModal] = useState<{
    client: OAuthClient;
    redirect_uri: string;
    scopes: string;
    error?: string;
    generated?: { code: string; redirect_uri: string; expires_in: number; code_verifier?: string };
  } | null>(null);

  const canWrite = selfServiceMode || hasCap('oauth_clients:write');

  const loadClients = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const list = await api.oauthClients.list(currentDomain);
      setClients(list || []);
      setSelfServiceMode(false);
    } catch (err) {
      // 仅在无管理权限（403）时回退至个人应用视角，其余错误直接提示
      if (err instanceof ApiError && err.status === 403) {
        try {
          const myList = await api.myOAuthClients.list();
          setClients(myList || []);
          setSelfServiceMode(true);
        } catch (myErr) {
          setError((myErr as Error).message);
        }
      } else {
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

  const openCreateDialog = () => {
    setEditingClient(null);
    setDialogError('');
    setForm({
      name: '',
      description: '',
      redirect_uris_text: '',
      scopes_text: 'openid profile email',
      grant_types: selfServiceMode
        ? ['authorization_code', 'refresh_token']
        : ['authorization_code', 'refresh_token', 'client_credentials'],
      require_pkce: true,
      is_confidential: true,
      status: 'active',
    });
    setDialogOpen(true);
  };

  const openEditDialog = (row: OAuthClient) => {
    setEditingClient(row);
    setDialogError('');
    const initialConfidential = Boolean(row.is_confidential);
    const rawGrants =
      row.grant_types && row.grant_types.length > 0
        ? row.grant_types
        : ['authorization_code', 'refresh_token'];
    const filteredGrants = initialConfidential
      ? rawGrants
      : rawGrants.filter((g) => g !== 'client_credentials');
    setForm({
      name: row.name || '',
      description: row.description || '',
      redirect_uris_text: (row.redirect_uris || []).join('\n'),
      scopes_text: (row.scopes || ['openid', 'profile', 'email']).join(' '),
      grant_types: filteredGrants.length > 0 ? filteredGrants : ['authorization_code'],
      require_pkce: initialConfidential ? Boolean(row.require_pkce) : true,
      is_confidential: initialConfidential,
      status: row.status || 'active',
    });
    setDialogOpen(true);
  };

  const handleToggleConfidential = async (checked: boolean) => {
    if (!checked && editingClient?.is_confidential) {
      const ok = await confirm({
        title: '确认切换为公开客户端',
        content: '取消勾选「机密客户端」后，原有应用密钥将被废弃，且不可继续使用客户端凭证授权方式。确定要切换为公开客户端吗？',
        confirmText: '确认切换',
        danger: true,
      });
      if (!ok) return;
    }
    setForm((prev) => {
      const nextGrants = checked
        ? prev.grant_types
        : prev.grant_types.filter((g) => g !== 'client_credentials');
      return {
        ...prev,
        is_confidential: checked,
        require_pkce: checked ? prev.require_pkce : true,
        grant_types: nextGrants.length > 0 ? nextGrants : ['authorization_code'],
      };
    });
  };

  const handleToggleGrantType = (grant: string) => {
    if (grant === 'client_credentials' && !form.is_confidential) return;
    setForm((prev) => {
      const exists = prev.grant_types.includes(grant);
      const next = exists ? prev.grant_types.filter((g) => g !== grant) : [...prev.grant_types, grant];
      return { ...prev, grant_types: next };
    });
  };

  const handleSaveApp = async () => {
    setDialogError('');
    const redirect_uris = form.redirect_uris_text
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    const scopes = form.scopes_text.split(/\s+/).filter(Boolean);

    const effectiveGrantTypes = (
      selfServiceMode
        ? ['authorization_code', 'refresh_token']
        : form.is_confidential
          ? form.grant_types
          : form.grant_types.filter((g) => g !== 'client_credentials')
    ).filter(Boolean);

    if (effectiveGrantTypes.length === 0) {
      setDialogError('请至少选择一种授权方式。');
      return;
    }

    const effectiveRequirePKCE = form.is_confidential ? form.require_pkce : true;

    setSaving(true);
    try {
      if (editingClient) {
        const updatePayload: Record<string, unknown> = {
          name: form.name.trim(),
          description: form.description.trim(),
          redirect_uris,
          grant_types: effectiveGrantTypes,
          scopes,
          require_pkce: effectiveRequirePKCE,
          is_confidential: form.is_confidential,
        };
        if (!selfServiceMode) {
          updatePayload.status = form.status;
        }
        const res = selfServiceMode
          ? await api.myOAuthClients.update(editingClient.id, updatePayload)
          : await api.oauthClients.update(editingClient.id, updatePayload);
        setDialogOpen(false);
        if (res?.client_secret) {
          setSecretCopied(false);
          setSecretModal({ client_id: res.client_id, client_secret: res.client_secret });
        }
      } else {
        const payload = {
          name: form.name.trim(),
          description: form.description.trim(),
          domain_code: currentDomain,
          redirect_uris,
          grant_types: effectiveGrantTypes,
          scopes,
          require_pkce: effectiveRequirePKCE,
          is_confidential: form.is_confidential,
        };
        const res = selfServiceMode
          ? await api.myOAuthClients.create(payload)
          : await api.oauthClients.create(payload);
        setDialogOpen(false);
        if (res.client_secret) {
          setSecretCopied(false);
          setSecretModal({ client_id: res.client.client_id, client_secret: res.client_secret });
        }
      }
      await loadClients();
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleRotate = async (row: OAuthClient) => {
    const ok = await confirm({
      title: '确认轮换应用密钥',
      content: '旧密钥将立即失效，使用旧密钥的应用会无法换取令牌。确定要继续吗？',
      confirmText: '确认轮换',
      danger: true,
    });
    if (!ok) return;
    try {
      const res = selfServiceMode
        ? await api.myOAuthClients.rotateSecret(row.id)
        : await api.oauthClients.rotateSecret(row.id);
      setSecretCopied(false);
      setSecretModal({ client_id: res.client_id, client_secret: res.client_secret });
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (row: OAuthClient) => {
    const ok = await confirm({
      title: '确认删除 OAuth 应用',
      content: `确定要删除 OAuth 应用「${row.name}」吗？删除后该应用将无法继续发起授权或换取令牌。`,
      confirmText: '确认删除',
      danger: true,
    });
    if (!ok) return;
    try {
      if (selfServiceMode) {
        await api.myOAuthClients.delete(row.id);
      } else {
        await api.oauthClients.delete(row.id);
      }
      await loadClients();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleGenerateCode = async () => {
    if (!codeModal) return;
    setCodeModal({ ...codeModal, error: '' });
    try {
      const needsPKCE = Boolean(codeModal.client.require_pkce || !codeModal.client.is_confidential);
      let codeVerifier: string | undefined;
      const payload: Parameters<typeof api.oauth2Server.createCode>[0] = {
        client_id: codeModal.client.client_id,
        redirect_uri: codeModal.redirect_uri,
        scopes: codeModal.scopes.split(/\s+/).filter(Boolean),
      };
      if (needsPKCE) {
        const pkce = await generatePKCE();
        codeVerifier = pkce.codeVerifier;
        payload.code_challenge = pkce.codeChallenge;
        payload.code_challenge_method = 'S256';
      }
      const res = await api.oauth2Server.createCode(payload);
      setCodeModal({
        ...codeModal,
        error: '',
        generated: {
          ...res,
          code_verifier: codeVerifier,
        },
      });
    } catch (err) {
      setCodeModal({ ...codeModal, error: (err as Error).message });
    }
  };

  const columns: GridColDef<OAuthClient>[] = [
    { field: 'name', headerName: '应用名称', width: 170 },
    {
      field: 'client_id',
      headerName: '应用标识（Client ID）',
      width: 220,
      renderCell: (p) => (
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Typography variant="body2" fontFamily="monospace" fontSize="0.8rem">
            {p.value}
          </Typography>
          <Tooltip title="复制应用标识">
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
      valueFormatter: (v: string[]) => (v || []).join('，'),
    },
    {
      field: 'require_pkce',
      headerName: 'PKCE',
      width: 85,
      renderCell: (p) => <Chip size="small" label={p.value ? '强制' : '可选'} color={p.value ? 'primary' : 'default'} />,
    },
    {
      field: 'is_confidential',
      headerName: '客户端类型',
      width: 100,
      renderCell: (p) => <Chip size="small" variant="outlined" label={p.value ? '机密' : '公开'} />,
    },
    {
      field: 'status',
      headerName: '状态',
      width: 90,
      renderCell: (p) => (
        <Chip size="small" color={p.value === 'active' ? 'success' : 'default'} label={p.value === 'active' ? '启用' : '停用'} />
      ),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 170,
      getActions: (p) => [
        ...(canWrite
          ? [
              <GridActionsCellItem
                key="edit"
                icon={<EditIcon />}
                label="编辑 OAuth 应用"
                onClick={() => openEditDialog(p.row)}
              />,
            ]
          : []),
        <GridActionsCellItem
          key="code"
          icon={<CodeIcon />}
          label="生成授权码"
          onClick={() =>
            setCodeModal({
              client: p.row,
              redirect_uri: p.row.redirect_uris?.[0] || '',
              scopes: (p.row.scopes || ['openid', 'profile', 'email']).join(' '),
            })
          }
        />,
        ...(canWrite && p.row.is_confidential
          ? [
              <GridActionsCellItem
                key="rot"
                icon={<RotateIcon />}
                label="轮换密钥"
                onClick={() => void handleRotate(p.row)}
              />,
            ]
          : []),
        ...(canWrite
          ? [
              <GridActionsCellItem
                key="del"
                icon={<DeleteIcon />}
                label="删除 OAuth 应用"
                onClick={() => void handleDelete(p.row)}
              />,
            ]
          : []),
      ],
    },
  ];

  const baseOrigin = window.location.origin;

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1.5} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Typography variant="h5">{selfServiceMode ? '我的 OAuth 应用' : 'OAuth 应用管理'}</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            创建并管理 OAuth 2.0 / OIDC 应用，支持生成一次性授权码。
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
          {canWrite && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={openCreateDialog}>
              创建 OAuth 应用
            </Button>
          )}
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
            <Chip size="small" variant="outlined" label={`发现文档：${baseOrigin}/.well-known/openid-configuration`} />
            <Chip size="small" variant="outlined" label={`公钥集合：${baseOrigin}/.well-known/jwks.json`} />
            <Chip size="small" variant="outlined" label={`授权端点：${baseOrigin}/oauth2/authorize`} />
            <Chip size="small" variant="outlined" label={`令牌端点：${baseOrigin}/oauth2/token`} />
            <Chip size="small" variant="outlined" label={`用户信息：${baseOrigin}/oauth2/userinfo`} />
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

      {/* 创建 / 编辑 OAuth 应用弹窗 */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editingClient ? `编辑 OAuth 应用：${editingClient.name}` : `创建 OAuth 应用（${currentDomain}）`}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {dialogError && (
              <Alert severity="error" onClose={() => setDialogError('')}>
                {dialogError}
              </Alert>
            )}
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
              label="回调地址白名单（每行一个地址）"
              placeholder="https://app.example.com/callback"
              size="small"
              multiline
              rows={3}
              required
              value={form.redirect_uris_text}
              onChange={(e) => setForm({ ...form, redirect_uris_text: e.target.value })}
            />
            <TextField
              label="允许的授权范围（空格分隔）"
              size="small"
              value={form.scopes_text}
              onChange={(e) => setForm({ ...form, scopes_text: e.target.value })}
            />
            {editingClient && !selfServiceMode && (
              <FormControl size="small" fullWidth>
                <InputLabel>应用状态</InputLabel>
                <Select
                  label="应用状态"
                  value={form.status}
                  onChange={(e) => setForm({ ...form, status: e.target.value })}
                >
                  <MenuItem value="active">启用</MenuItem>
                  <MenuItem value="disabled">停用</MenuItem>
                </Select>
              </FormControl>
            )}
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={form.is_confidential ? form.require_pkce : true}
                    disabled={!form.is_confidential}
                    onChange={(e) => setForm({ ...form, require_pkce: e.target.checked })}
                  />
                }
                label="强制启用 PKCE"
              />
              <FormControlLabel
                control={
                  <Checkbox
                    checked={form.is_confidential}
                    onChange={(e) => void handleToggleConfidential(e.target.checked)}
                  />
                }
                label="机密客户端（使用密钥）"
              />
            </Stack>
            {!selfServiceMode && (
              <FormControl component="fieldset" variant="standard">
                <Typography variant="subtitle2" mb={0.5}>
                  允许的授权方式
                </Typography>
                <FormGroup>
                  {GRANT_TYPE_OPTIONS.map((opt) => {
                    const isClientCreds = opt.value === 'client_credentials';
                    const disabled = isClientCreds && !form.is_confidential;
                    return (
                      <FormControlLabel
                        key={opt.value}
                        control={
                          <Checkbox
                            size="small"
                            checked={!disabled && form.grant_types.includes(opt.value)}
                            disabled={disabled}
                            onChange={() => handleToggleGrantType(opt.value)}
                          />
                        }
                        label={opt.label}
                      />
                    );
                  })}
                </FormGroup>
                {!form.is_confidential && (
                  <FormHelperText>
                    公开客户端无法安全保管密钥，必须强制启用 PKCE，且不可选择客户端凭证（client_credentials）授权方式。
                  </FormHelperText>
                )}
              </FormControl>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={saving}>
            取消
          </Button>
          <Button variant="contained" onClick={handleSaveApp} disabled={saving}>
            {saving ? '保存中...' : editingClient ? '保存修改' : '创建应用'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 一次性密钥展示弹窗：禁止点击遮罩或按 Esc 关闭 */}
      <Dialog
        open={Boolean(secretModal)}
        disableEscapeKeyDown
        onClose={(_, reason) => {
          if (reason === 'backdropClick' || reason === 'escapeKeyDown') return;
          setSecretModal(null);
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>请妥善保存应用密钥</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            应用密钥仅展示一次，关闭窗口后系统不再明文保存。如遗失，请使用「轮换密钥」重新生成。
          </Alert>
          <Stack spacing={1.5}>
            <TextField
              label="应用标识（Client ID）"
              size="small"
              value={secretModal?.client_id || ''}
              InputProps={{ readOnly: true }}
            />
            <TextField
              label="应用密钥（Client Secret）"
              size="small"
              value={secretModal?.client_secret || ''}
              InputProps={{ readOnly: true }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<CopyIcon />}
            onClick={() => {
              if (secretModal) {
                void navigator.clipboard.writeText(
                  `Client ID: ${secretModal.client_id}\nClient Secret: ${secretModal.client_secret}`,
                );
                setSecretCopied(true);
              }
            }}
          >
            {secretCopied ? '已复制凭证' : '复制凭证'}
          </Button>
          <Button variant="contained" onClick={() => setSecretModal(null)}>
            我已妥善保存
          </Button>
        </DialogActions>
      </Dialog>

      {/* 生成 OAuth 2.0 授权码弹窗 */}
      <Dialog open={Boolean(codeModal)} onClose={() => setCodeModal(null)} maxWidth="sm" fullWidth>
        <DialogTitle>生成授权码：{codeModal?.client.name}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {codeModal?.error && (
              <Alert severity="error" onClose={() => setCodeModal({ ...codeModal, error: '' })}>
                {codeModal.error}
              </Alert>
            )}
            {(codeModal?.client.require_pkce || !codeModal?.client.is_confidential) && (
              <Alert severity="info">
                该应用要求启用 PKCE（S256），生成授权码时将自动生成对应的 PKCE 校验码（code_verifier），换取令牌时需一并提交。
              </Alert>
            )}
            <TextField
              label="回调地址"
              size="small"
              value={codeModal?.redirect_uri || ''}
              onChange={(e) => codeModal && setCodeModal({ ...codeModal, redirect_uri: e.target.value })}
              fullWidth
            />
            <TextField
              label="授权范围"
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
                <Stack spacing={1}>
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
                  {codeModal.generated.code_verifier && (
                    <Box>
                      <Typography variant="caption" color="text.secondary" display="block">
                        PKCE 校验码（code_verifier，换取令牌时使用）：
                      </Typography>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
                          {codeModal.generated.code_verifier}
                        </Typography>
                        <Tooltip title="复制 PKCE 校验码">
                          <IconButton
                            size="small"
                            onClick={() => navigator.clipboard.writeText(codeModal.generated?.code_verifier || '')}
                          >
                            <CopyIcon fontSize="inherit" />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </Box>
                  )}
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
