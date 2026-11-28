import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Grid2 as Grid,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Delete as DeleteIcon, Edit as EditIcon, Extension as PluginIcon } from '@mui/icons-material';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { useAuth } from '../context/AuthContext';
import { OAuthPluginMeta, OAuthProvider } from '../types/api';

export const IdentityProvidersPage: React.FC = () => {
  const { hasCap } = useAuth();
  const confirm = useConfirm();
  const canWrite = hasCap('plugins:write');

  const [plugins, setPlugins] = useState<OAuthPluginMeta[]>([]);
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [selectedPlugin, setSelectedPlugin] = useState<OAuthPluginMeta | null>(null);
  const [form, setForm] = useState({
    name: '',
    display_name: '',
    client_id: '',
    client_secret: '',
    scopes: '',
    auto_register: true,
    enabled: true,
    extra_config: {} as Record<string, string>,
  });

  const loadData = async () => {
    try {
      const [plugRes, provRes] = await Promise.all([api.oauthProviders.listPlugins(), api.oauthProviders.list()]);
      setPlugins(plugRes || []);
      setProviders(provRes || []);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const openCreateForPlugin = (meta: OAuthPluginMeta) => {
    setDialogError('');
    setEditingId(null);
    setSelectedPlugin(meta);
    setForm({
      name: meta.type,
      display_name: meta.display_name,
      client_id: '',
      client_secret: '',
      scopes: meta.default_scopes,
      auto_register: true,
      enabled: true,
      extra_config: {},
    });
    setDialogOpen(true);
  };

  const openEditProvider = (prov: OAuthProvider) => {
    const meta = plugins.find((p) => p.type === prov.plugin_type) || null;
    setDialogError('');
    setEditingId(prov.id);
    setSelectedPlugin(meta);
    setForm({
      name: prov.name,
      display_name: prov.display_name,
      client_id: prov.client_id,
      client_secret: '',
      scopes: prov.scopes,
      auto_register: prov.auto_register,
      enabled: prov.enabled,
      extra_config: prov.extra_config || {},
    });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!selectedPlugin) return;
    setDialogError('');
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        plugin_type: selectedPlugin.type,
        display_name: form.display_name.trim(),
        client_id: form.client_id.trim(),
        client_secret: form.client_secret,
        scopes: form.scopes.trim(),
        auto_register: form.auto_register,
        enabled: form.enabled,
        extra_config: form.extra_config,
      };
      if (editingId) {
        await api.oauthProviders.update(editingId, payload);
        setSuccess(`已更新身份源「${payload.display_name}」。`);
      } else {
        await api.oauthProviders.create(payload);
        setSuccess(`已接入身份源「${payload.display_name}」。`);
      }
      setDialogOpen(false);
      await loadData();
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleToggleEnabled = async (prov: OAuthProvider) => {
    setError('');
    setSuccess('');
    try {
      await api.oauthProviders.update(prov.id, {
        name: prov.name,
        plugin_type: prov.plugin_type,
        display_name: prov.display_name,
        client_id: prov.client_id,
        scopes: prov.scopes,
        extra_config: prov.extra_config,
        auto_register: prov.auto_register,
        enabled: !prov.enabled,
      });
      setSuccess(`已${prov.enabled ? '停用' : '启用'}身份源「${prov.display_name}」。`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (prov: OAuthProvider) => {
    const ok = await confirm({
      title: '删除身份源',
      content: `确认删除第三方登录身份源「${prov.display_name}」？删除后用户将无法通过该方式登录。`,
      confirmText: '确认删除',
      danger: true,
    });
    if (!ok) return;

    setError('');
    setSuccess('');
    try {
      await api.oauthProviders.delete(prov.id);
      setSuccess(`已删除身份源「${prov.display_name}」。`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Box>
      <Typography variant="h5" mb={0.5}>
        第三方登录
      </Typography>
      <Typography variant="body2" color="text.secondary" mb={3}>
        配置 GitHub、Google、飞书、企业微信或通用 OIDC 身份源。
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
          {success}
        </Alert>
      )}

      <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
        已配置的身份源（{providers.length}）
      </Typography>
      <Grid container spacing={2} mb={4}>
        {providers.length === 0 ? (
          <Grid size={{ xs: 12 }}>
            <Alert severity="info">尚未配置任何第三方登录身份源，请从下方可用类型中选择并接入。</Alert>
          </Grid>
        ) : (
          providers.map((prov) => (
            <Grid key={prov.id} size={{ xs: 12, md: 6, lg: 4 }}>
              <Card>
                <CardContent>
                  <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                    <Typography variant="h6">{prov.display_name}</Typography>
                    {canWrite && (
                      <Switch checked={prov.enabled} onChange={() => void handleToggleEnabled(prov)} />
                    )}
                  </Stack>
                  <Stack direction="row" spacing={1} mb={1.5} flexWrap="wrap" useFlexGap>
                    <Chip size="small" label={prov.plugin_type} color="primary" variant="outlined" />
                    <Chip size="small" label={prov.enabled ? '已启用' : '已停用'} color={prov.enabled ? 'success' : 'default'} />
                    {prov.auto_register && <Chip size="small" label="自动创建账号" />}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" display="block">
                    标识：{prov.name} · Client ID：{prov.client_id}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                    回调地址：{window.location.origin}/oauth/callback/{prov.name}
                  </Typography>
                </CardContent>
                {canWrite && (
                  <CardActions>
                    <Button size="small" startIcon={<EditIcon />} onClick={() => openEditProvider(prov)}>
                      配置
                    </Button>
                    <Button size="small" color="error" startIcon={<DeleteIcon />} onClick={() => void handleDelete(prov)}>
                      删除
                    </Button>
                  </CardActions>
                )}
              </Card>
            </Grid>
          ))
        )}
      </Grid>

      <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
        添加身份源（{plugins.length}）
      </Typography>
      <Grid container spacing={2}>
        {plugins.map((plug) => (
          <Grid key={plug.type} size={{ xs: 12, md: 6, lg: 4 }}>
            <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <CardContent>
                <Stack direction="row" spacing={1} alignItems="center" mb={1}>
                  <PluginIcon color="primary" />
                  <Typography variant="subtitle1" fontWeight={600}>
                    {plug.display_name}
                  </Typography>
                </Stack>
                <Typography variant="body2" color="text.secondary" mb={1.5}>
                  {plug.description}
                </Typography>
                <Chip size="small" variant="outlined" label={`类型：${plug.type}`} />
              </CardContent>
              {canWrite && (
                <CardActions>
                  <Button size="small" startIcon={<AddIcon />} onClick={() => openCreateForPlugin(plug)}>
                    接入此身份源
                  </Button>
                </CardActions>
              )}
            </Card>
          </Grid>
        ))}
      </Grid>

      {canWrite && (
        <Dialog open={dialogOpen} onClose={() => { if (!saving) setDialogOpen(false); }} maxWidth="sm" fullWidth>
          <DialogTitle>
            {editingId ? '配置身份源' : `接入${selectedPlugin?.display_name || ''}身份源`}
          </DialogTitle>
          <DialogContent>
            <Stack spacing={2} mt={1}>
              {dialogError && (
                <Alert severity="error" onClose={() => setDialogError('')}>
                  {dialogError}
                </Alert>
              )}

              <TextField
                label="唯一标识（英文，例如：github、feishu_corp）"
                size="small"
                required
                disabled={Boolean(editingId)}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
              <TextField
                label="登录页按钮展示名称"
                size="small"
                required
                value={form.display_name}
                onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              />
              <TextField
                label={selectedPlugin?.type === 'wecom' ? '企业 CorpID（Client ID）' : 'Client ID / App ID'}
                size="small"
                required
                value={form.client_id}
                onChange={(e) => setForm({ ...form, client_id: e.target.value })}
              />
              <TextField
                label={editingId ? 'Client Secret（留空保持不变）' : 'Client Secret / App Secret'}
                type="password"
                size="small"
                required={!editingId}
                value={form.client_secret}
                onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
              />
              <TextField
                label="授权范围"
                size="small"
                value={form.scopes}
                onChange={(e) => setForm({ ...form, scopes: e.target.value })}
              />

              {selectedPlugin?.config_fields?.map((field) => (
                <TextField
                  key={field.key}
                  label={field.label}
                  type={field.type === 'password' ? 'password' : 'text'}
                  size="small"
                  required={field.required}
                  placeholder={field.placeholder}
                  helperText={field.description}
                  value={form.extra_config[field.key] || ''}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      extra_config: { ...form.extra_config, [field.key]: e.target.value },
                    })
                  }
                />
              ))}

              <Stack direction="row" spacing={2}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={form.auto_register}
                      onChange={(e) => setForm({ ...form, auto_register: e.target.checked })}
                    />
                  }
                  label="首次登录自动创建账号"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={form.enabled}
                      onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    />
                  }
                  label="立即启用"
                />
              </Stack>
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setDialogOpen(false)} disabled={saving}>取消</Button>
            <Button variant="contained" onClick={() => void handleSave()} disabled={saving}>
              {saving ? '保存中…' : '保存配置'}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};
