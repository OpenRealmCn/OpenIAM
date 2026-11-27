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
import { OAuthPluginMeta, OAuthProvider } from '../types/api';

export const IdentityProvidersPage: React.FC = () => {
  const [plugins, setPlugins] = useState<OAuthPluginMeta[]>([]);
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [error, setError] = useState('');

  const [dialogOpen, setDialogOpen] = useState(false);
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
    loadData();
  }, []);

  const openCreateForPlugin = (meta: OAuthPluginMeta) => {
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
    try {
      const payload = {
        name: form.name,
        plugin_type: selectedPlugin.type,
        display_name: form.display_name,
        client_id: form.client_id,
        client_secret: form.client_secret,
        scopes: form.scopes,
        auto_register: form.auto_register,
        enabled: form.enabled,
        extra_config: form.extra_config,
      };
      if (editingId) {
        await api.oauthProviders.update(editingId, payload);
      } else {
        await api.oauthProviders.create(payload);
      }
      setDialogOpen(false);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleToggleEnabled = async (prov: OAuthProvider) => {
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
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.oauthProviders.delete(id);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Box>
      <Typography variant="h5" mb={0.5}>
        OAuth 联合登录插件中心
      </Typography>
      <Typography variant="body2" color="text.secondary" mb={3}>
        基于 Go OAuthProviderPlugin 插件接口注册外部身份源，支持动态表单配置与自动建号
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
        已配置的联合登录实例 ({providers.length})
      </Typography>
      <Grid container spacing={2} mb={4}>
        {providers.length === 0 ? (
          <Grid size={{ xs: 12 }}>
            <Alert severity="info">尚未配置任何联合登录实例，请从下方可用插件模板中选择并接入。</Alert>
          </Grid>
        ) : (
          providers.map((prov) => (
            <Grid key={prov.id} size={{ xs: 12, md: 6, lg: 4 }}>
              <Card>
                <CardContent>
                  <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                    <Typography variant="h6">{prov.display_name}</Typography>
                    <Switch checked={prov.enabled} onChange={() => handleToggleEnabled(prov)} />
                  </Stack>
                  <Stack direction="row" spacing={1} mb={1.5}>
                    <Chip size="small" label={prov.plugin_type} color="primary" variant="outlined" />
                    <Chip size="small" label={prov.enabled ? '已启用' : '已停用'} color={prov.enabled ? 'success' : 'default'} />
                    {prov.auto_register && <Chip size="small" label="自动建号" />}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" display="block">
                    标识: {prov.name} · Client ID: {prov.client_id}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                    回调地址: {window.location.origin}/oauth/callback/{prov.name}
                  </Typography>
                </CardContent>
                <CardActions>
                  <Button size="small" startIcon={<EditIcon />} onClick={() => openEditProvider(prov)}>
                    配置
                  </Button>
                  <Button size="small" color="error" startIcon={<DeleteIcon />} onClick={() => handleDelete(prov.id)}>
                    删除
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))
        )}
      </Grid>

      <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
        已注册插件适配器 ({plugins.length})
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
                <Chip size="small" variant="outlined" label={`插件类型: ${plug.type}`} />
              </CardContent>
              <CardActions>
                <Button size="small" startIcon={<AddIcon />} onClick={() => openCreateForPlugin(plug)}>
                  接入此身份源
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editingId ? '编辑联合登录配置' : `接入 ${selectedPlugin?.display_name} 插件`}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="配置唯一标识 (英文，如 github / feishu_corp)"
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
              label={selectedPlugin?.type === 'wecom' ? '企业 CorpID (Client ID)' : 'Client ID / App ID'}
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
              label="Scopes"
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
                label="首次登录自动创建 OpenIAM 账号"
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
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleSave}>
            保存配置
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
