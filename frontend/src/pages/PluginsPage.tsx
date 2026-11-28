import React, { useCallback, useEffect, useMemo, useState } from 'react';
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
  Divider,
  FormControl,
  FormControlLabel,
  Grid2 as Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  ContentCopy as CopyIcon,
  Delete as DeleteIcon,
  Extension as PluginIcon,
  HealthAndSafety as TestIcon,
  Settings as EditIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { OAuthPluginMeta, OAuthProvider, PluginDriverMeta, PluginInstance } from '../types/api';

const SLOT_LABELS: Record<string, string> = {
  oauth: '第三方登录',
  captcha: '人机验证',
  sms: '短信',
  notification: '通知扩展',
  risk: '风控扩展',
};

const VALID_SLOTS = Object.keys(SLOT_LABELS);

const HEALTH_LABELS: Record<string, { label: string; color: 'success' | 'error' | 'default' }> = {
  healthy: { label: '正常', color: 'success' },
  unhealthy: { label: '异常', color: 'error' },
  unknown: { label: '未检测', color: 'default' },
};

export const PluginsPage: React.FC = () => {
  const { hasCap } = useAuth();
  const confirm = useConfirm();
  const canWrite = hasCap('plugins:write');

  const [searchParams, setSearchParams] = useSearchParams();
  const initialSlot = searchParams.get('slot');
  const [slot, setSlot] = useState<string>(
    initialSlot && VALID_SLOTS.includes(initialSlot) ? initialSlot : 'oauth',
  );

  const [drivers, setDrivers] = useState<PluginDriverMeta[]>([]);
  const [instances, setInstances] = useState<PluginInstance[]>([]);
  const [oauthPlugins, setOAuthPlugins] = useState<OAuthPluginMeta[]>([]);
  const [oauthProviders, setOAuthProviders] = useState<OAuthProvider[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 通用插件新建或编辑弹窗
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [savingPlugin, setSavingPlugin] = useState(false);
  const [editing, setEditing] = useState<PluginInstance | null>(null);
  const [selectedType, setSelectedType] = useState('');
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [priority, setPriority] = useState(100);
  const [enabled, setEnabled] = useState(false);
  const [configDraft, setConfigDraft] = useState<Record<string, string>>({});

  // 第三方登录配置弹窗
  const [oauthDialogOpen, setOAuthDialogOpen] = useState(false);
  const [oauthDialogError, setOAuthDialogError] = useState('');
  const [savingOAuth, setSavingOAuth] = useState(false);
  const [editingProviderId, setEditingProviderId] = useState<number | null>(null);
  const [selectedOAuthPlugin, setSelectedOAuthPlugin] = useState<OAuthPluginMeta | null>(null);
  const [oauthForm, setOAuthForm] = useState({
    name: '',
    display_name: '',
    client_id: '',
    client_secret: '',
    scopes: '',
    auto_register: true,
    enabled: true,
    extra_config: {} as Record<string, string>,
  });

  useEffect(() => {
    const qSlot = searchParams.get('slot');
    if (qSlot && VALID_SLOTS.includes(qSlot) && qSlot !== slot) {
      setSlot(qSlot);
    }
  }, [searchParams, slot]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [drvList, instList, plugRes, provRes] = await Promise.all([
        api.plugins.drivers(),
        api.plugins.list(),
        api.oauthProviders.listPlugins(),
        api.oauthProviders.list(),
      ]);
      setDrivers(drvList || []);
      setInstances(instList || []);
      setOAuthPlugins(plugRes || []);
      setOAuthProviders(provRes || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleSlotChange = (_: React.SyntheticEvent, nextSlot: string) => {
    setSlot(nextSlot);
    setError('');
    setSuccess('');
    setSearchParams({ slot: nextSlot }, { replace: true });
  };

  const slotDrivers = useMemo(() => drivers.filter((d) => d.slot === slot), [drivers, slot]);
  const slotInstances = useMemo(() => instances.filter((i) => i.slot === slot), [instances, slot]);
  const activeDriver = useMemo(() => drivers.find((d) => d.type === selectedType), [drivers, selectedType]);

  const confirmDisableLastCriticalPlugin = async (inst: PluginInstance): Promise<boolean> => {
    if (inst.slot !== 'captcha' && inst.slot !== 'sms') {
      return true;
    }
    const enabledCount = instances.filter((i) => i.slot === inst.slot && i.enabled).length;
    if (enabledCount > 1) {
      return true;
    }
    const slotName = inst.slot === 'captcha' ? '人机验证' : '短信';
    const impact =
      inst.slot === 'captcha'
        ? '停用后，已开启人机验证保护的登录、注册与验证码场景将无法完成人机验证。'
        : '停用后，短信验证码登录、注册与安全通知将无法发送。';
    return confirm({
      title: `停用唯一的${slotName}插件`,
      content: `「${inst.display_name}」是当前唯一已启用的${slotName}插件。${impact}确认停用吗？`,
      confirmText: '确认停用',
      danger: true,
    });
  };

  // 通用插件逻辑
  const openCreate = () => {
    const first = slotDrivers[0];
    setDialogError('');
    setEditing(null);
    setSelectedType(first?.type || '');
    setName('');
    setDisplayName(first?.display_name || '');
    setPriority(100);
    setEnabled(true);
    const initialCfg: Record<string, string> = {};
    for (const f of first?.fields || []) {
      if (f.default) initialCfg[f.key] = f.default;
    }
    setConfigDraft(initialCfg);
    setDialogOpen(true);
  };

  const openEdit = (inst: PluginInstance) => {
    setDialogError('');
    setEditing(inst);
    setSelectedType(inst.plugin_type);
    setName(inst.name);
    setDisplayName(inst.display_name);
    setPriority(inst.priority);
    setEnabled(inst.enabled);
    const nextCfg: Record<string, string> = {};
    for (const [k, v] of Object.entries(inst.config || {})) {
      if (!k.startsWith('has_')) {
        nextCfg[k] = String(v ?? '');
      }
    }
    setConfigDraft(nextCfg);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    setDialogError('');
    if (editing && editing.enabled && !enabled) {
      const ok = await confirmDisableLastCriticalPlugin(editing);
      if (!ok) return;
    }
    setSavingPlugin(true);
    try {
      if (editing) {
        await api.plugins.update(editing.id, {
          display_name: displayName.trim(),
          priority: Number(priority) || 100,
          enabled,
          config: configDraft,
        });
        setSuccess(`已更新插件「${displayName.trim()}」。`);
      } else {
        await api.plugins.create({
          name: name.trim(),
          slot,
          plugin_type: selectedType,
          display_name: displayName.trim(),
          priority: Number(priority) || 100,
          enabled,
          config: configDraft,
        });
        setSuccess(`已添加插件「${displayName.trim()}」。`);
      }
      setDialogOpen(false);
      await loadData();
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setSavingPlugin(false);
    }
  };

  const handleToggle = async (inst: PluginInstance) => {
    if (inst.enabled) {
      const ok = await confirmDisableLastCriticalPlugin(inst);
      if (!ok) return;
    }
    setError('');
    setSuccess('');
    try {
      await api.plugins.update(inst.id, { enabled: !inst.enabled });
      setSuccess(`已${inst.enabled ? '停用' : '启用'}插件「${inst.display_name}」。`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleTest = async (inst: PluginInstance) => {
    setError('');
    setSuccess('');
    try {
      const res = await api.plugins.test(inst.id);
      const statusText = HEALTH_LABELS[res.status]?.label || res.status;
      setSuccess(`插件「${inst.display_name}」连通性检查通过（状态：${statusText}）。`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  // 第三方登录逻辑
  const openCreateOAuthForPlugin = (meta: OAuthPluginMeta) => {
    setOAuthDialogError('');
    setEditingProviderId(null);
    setSelectedOAuthPlugin(meta);
    setOAuthForm({
      name: meta.type,
      display_name: meta.display_name,
      client_id: '',
      client_secret: '',
      scopes: meta.default_scopes,
      auto_register: true,
      enabled: true,
      extra_config: {},
    });
    setOAuthDialogOpen(true);
  };

  const openEditOAuthProvider = (prov: OAuthProvider) => {
    const meta = oauthPlugins.find((p) => p.type === prov.plugin_type) || null;
    setOAuthDialogError('');
    setEditingProviderId(prov.id);
    setSelectedOAuthPlugin(meta);
    setOAuthForm({
      name: prov.name,
      display_name: prov.display_name,
      client_id: prov.client_id,
      client_secret: '',
      scopes: prov.scopes,
      auto_register: prov.auto_register,
      enabled: prov.enabled,
      extra_config: prov.extra_config || {},
    });
    setOAuthDialogOpen(true);
  };

  const handleSaveOAuthProvider = async () => {
    if (!selectedOAuthPlugin) return;
    setOAuthDialogError('');
    setSavingOAuth(true);
    try {
      const payload = {
        name: oauthForm.name.trim(),
        plugin_type: selectedOAuthPlugin.type,
        display_name: oauthForm.display_name.trim(),
        client_id: oauthForm.client_id.trim(),
        client_secret: oauthForm.client_secret,
        scopes: oauthForm.scopes.trim(),
        auto_register: oauthForm.auto_register,
        enabled: oauthForm.enabled,
        extra_config: oauthForm.extra_config,
      };
      if (editingProviderId) {
        await api.oauthProviders.update(editingProviderId, payload);
        setSuccess(`已更新身份源「${payload.display_name}」。`);
      } else {
        await api.oauthProviders.create(payload);
        setSuccess(`已接入身份源「${payload.display_name}」。`);
      }
      setOAuthDialogOpen(false);
      await loadData();
    } catch (err) {
      setOAuthDialogError((err as Error).message);
    } finally {
      setSavingOAuth(false);
    }
  };

  const handleToggleOAuthEnabled = async (prov: OAuthProvider) => {
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

  const handleDeleteOAuthProvider = async (prov: OAuthProvider) => {
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
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <PluginIcon color="primary" />
            <Typography variant="h5">插件中心</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            统一管理第三方登录、人机验证、短信、通知扩展与风控扩展插件。
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.5}>
          <Button
            variant="outlined"
            startIcon={<AnimatedRefreshIcon spinning={loading} spinCount={refreshCount} />}
            onClick={() => {
              setRefreshCount((c) => c + 1);
              void loadData();
            }}
          >
            刷新
          </Button>
          {canWrite && slot !== 'oauth' && slotDrivers.length > 0 && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={openCreate}>
              新增插件
            </Button>
          )}
        </Stack>
      </Stack>

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

      <Card>
        <Tabs value={slot} onChange={handleSlotChange} variant="scrollable" scrollButtons="auto" sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}>
          {Object.entries(SLOT_LABELS).map(([k, label]) => (
            <Tab key={k} value={k} label={label} />
          ))}
        </Tabs>

        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          {slot === 'oauth' ? (
            <Box>
              <Alert severity="info" sx={{ mb: 2.5 }}>
                在此配置 GitHub、Google、飞书、企业微信或通用 OIDC 身份源。启用后将在登录页与个人中心「第三方账号」中展示。
              </Alert>

              <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
                已接入的身份源（{oauthProviders.length}）
              </Typography>
              <Grid container spacing={2} mb={3.5}>
                {oauthProviders.length === 0 ? (
                  <Grid size={{ xs: 12 }}>
                    <Alert severity="info">尚未配置任何第三方登录身份源，请从下方可用类型中选择并接入。</Alert>
                  </Grid>
                ) : (
                  oauthProviders.map((prov) => {
                    const callbackUrl = `${window.location.origin}/oauth/callback/${prov.name}`;
                    return (
                      <Grid key={prov.id} size={{ xs: 12, md: 6, lg: 4 }}>
                        <Card variant="outlined" sx={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                          <CardContent>
                            <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
                              <Typography variant="subtitle1" fontWeight={700}>
                                {prov.display_name}
                              </Typography>
                              {canWrite && (
                                <Switch checked={prov.enabled} onChange={() => void handleToggleOAuthEnabled(prov)} />
                              )}
                            </Stack>
                            <Stack direction="row" spacing={1} mb={1.2} flexWrap="wrap" useFlexGap>
                              <Chip size="small" label={prov.plugin_type} color="primary" variant="outlined" />
                              <Chip size="small" label={prov.enabled ? '已启用' : '已停用'} color={prov.enabled ? 'success' : 'default'} />
                              {prov.auto_register && <Chip size="small" label="自动创建账号" />}
                            </Stack>
                            <Typography variant="caption" color="text.secondary" display="block">
                              标识：{prov.name} · Client ID：{prov.client_id}
                            </Typography>
                            <Stack direction="row" spacing={0.5} alignItems="center" mt={0.5}>
                              <Typography variant="caption" color="text.secondary" noWrap sx={{ flex: 1 }}>
                                回调地址：{callbackUrl}
                              </Typography>
                              <Tooltip title="复制回调地址">
                                <IconButton size="small" onClick={() => void navigator.clipboard.writeText(callbackUrl)}>
                                  <CopyIcon sx={{ fontSize: 14 }} />
                                </IconButton>
                              </Tooltip>
                            </Stack>
                          </CardContent>
                          {canWrite && (
                            <CardActions>
                              <Button size="small" startIcon={<EditIcon />} onClick={() => openEditOAuthProvider(prov)}>
                                配置
                              </Button>
                              <Button size="small" color="error" startIcon={<DeleteIcon />} onClick={() => void handleDeleteOAuthProvider(prov)}>
                                删除
                              </Button>
                            </CardActions>
                          )}
                        </Card>
                      </Grid>
                    );
                  })
                )}
              </Grid>

              <Divider sx={{ mb: 2.5 }} />

              <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
                可用的第三方登录类型（{oauthPlugins.length}）
              </Typography>
              <Grid container spacing={2}>
                {oauthPlugins.map((plug) => (
                  <Grid key={plug.type} size={{ xs: 12, md: 6, lg: 4 }}>
                    <Card variant="outlined" sx={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                      <CardContent>
                        <Stack direction="row" spacing={1} alignItems="center" mb={1}>
                          <PluginIcon color="primary" fontSize="small" />
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
                          <Button size="small" startIcon={<AddIcon />} onClick={() => openCreateOAuthForPlugin(plug)}>
                            接入此身份源
                          </Button>
                        </CardActions>
                      )}
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          ) : (
            <>
              {slot === 'captcha' && (
                <Alert severity="info" sx={{ mb: 2.5 }}>
                  人机验证支持<strong>本地模式（内置计算校验，无需外部服务）</strong>与<strong>远端模式（对接独立部署的验证服务）</strong>。启用后请在「系统设置 → 人机验证策略」中选择需要保护的业务场景。
                </Alert>
              )}

              {slotInstances.length === 0 ? (
                <Alert severity="info">
                  {canWrite ? '当前分类下暂无已配置的插件，请点击右上角「新增插件」进行接入。' : '当前分类下暂无已配置的插件。'}
                </Alert>
              ) : (
                <Stack spacing={2}>
                  {slotInstances.map((inst) => (
                    <Card key={inst.id} variant="outlined">
                      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2}>
                          <Box>
                            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                              <Typography variant="subtitle1" fontWeight={700}>{inst.display_name}</Typography>
                              <Chip size="small" label={inst.name} sx={{ fontFamily: 'monospace' }} />
                              {inst.slot === 'captcha' && Boolean(inst.config?.mode) && (
                                <Chip
                                  size="small"
                                  color="primary"
                                  variant="outlined"
                                  label={inst.config.mode === 'remote' ? '远端服务模式' : '本地内置模式'}
                                />
                              )}
                              <Chip
                                size="small"
                                color={(HEALTH_LABELS[inst.health_status] || HEALTH_LABELS.unknown).color}
                                label={`健康状态：${(HEALTH_LABELS[inst.health_status] || HEALTH_LABELS.unknown).label}`}
                              />
                              {!canWrite && (
                                <Chip
                                  size="small"
                                  color={inst.enabled ? 'success' : 'default'}
                                  label={inst.enabled ? '已启用' : '已停用'}
                                />
                              )}
                            </Stack>
                            <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                              优先级：{inst.priority} · 最近更新：{dayjs(inst.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                            </Typography>
                          </Box>

                          {canWrite && (
                            <Stack direction="row" spacing={1} alignItems="center">
                              <FormControlLabel
                                control={<Switch checked={inst.enabled} onChange={() => void handleToggle(inst)} />}
                                label={inst.enabled ? '已启用' : '已停用'}
                              />
                              <Button size="small" variant="outlined" startIcon={<TestIcon />} onClick={() => void handleTest(inst)}>
                                测试
                              </Button>
                              <Button size="small" variant="contained" startIcon={<EditIcon />} onClick={() => openEdit(inst)}>
                                配置
                              </Button>
                            </Stack>
                          )}
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* 通用插件实例弹窗 */}
      {canWrite && (
        <Dialog open={dialogOpen} onClose={() => { if (!savingPlugin) setDialogOpen(false); }} maxWidth="sm" fullWidth>
          <DialogTitle>{editing ? `配置插件：${editing.display_name}` : `新增${SLOT_LABELS[slot] || slot}插件`}</DialogTitle>
          <DialogContent>
            <Stack spacing={2} mt={1}>
              {dialogError && (
                <Alert severity="error" onClose={() => setDialogError('')}>
                  {dialogError}
                </Alert>
              )}

              {!editing && (
                <>
                  <FormControl size="small" fullWidth>
                    <InputLabel>插件类型</InputLabel>
                    <Select
                      label="插件类型"
                      value={selectedType}
                      onChange={(e) => {
                        const next = drivers.find((d) => d.type === e.target.value);
                        setSelectedType(e.target.value);
                        if (next) {
                          setDisplayName(next.display_name);
                          const cfg: Record<string, string> = {};
                          for (const f of next.fields) {
                            if (f.default) cfg[f.key] = f.default;
                          }
                          setConfigDraft(cfg);
                        }
                      }}
                    >
                      {slotDrivers.map((d) => (
                        <MenuItem key={d.type} value={d.type}>{d.display_name}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <TextField
                    label="插件标识（仅限英文、数字与短横线）"
                    size="small"
                    fullWidth
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="例如：cap-prod"
                  />
                </>
              )}

              <TextField label="显示名称" size="small" fullWidth value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
              <TextField label="优先级（数值越小越优先）" type="number" size="small" fullWidth value={priority} onChange={(e) => setPriority(Number(e.target.value))} />

              {activeDriver?.fields.map((f) => {
                const val = configDraft[f.key] ?? f.default ?? '';
                if (f.type === 'select') {
                  return (
                    <FormControl key={f.key} size="small" fullWidth>
                      <InputLabel>{f.label}</InputLabel>
                      <Select label={f.label} value={val} onChange={(e) => setConfigDraft({ ...configDraft, [f.key]: e.target.value })}>
                        {(f.options || []).map((opt) => (
                          <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  );
                }
                if (f.type === 'bool') {
                  return (
                    <FormControlLabel
                      key={f.key}
                      control={
                        <Switch
                          checked={val === 'true'}
                          onChange={(e) => setConfigDraft({ ...configDraft, [f.key]: e.target.checked ? 'true' : 'false' })}
                        />
                      }
                      label={`${f.label}${f.description ? `（${f.description}）` : ''}`}
                    />
                  );
                }
                return (
                  <TextField
                    key={f.key}
                    label={f.label}
                    type={f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text'}
                    size="small"
                    fullWidth
                    placeholder={f.placeholder}
                    helperText={f.description}
                    value={val}
                    onChange={(e) => setConfigDraft({ ...configDraft, [f.key]: e.target.value })}
                  />
                );
              })}

              <FormControlLabel control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />} label="保存后立即启用" />
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setDialogOpen(false)} disabled={savingPlugin}>取消</Button>
            <Button variant="contained" onClick={() => void handleSave()} disabled={savingPlugin}>
              {savingPlugin ? '保存中…' : '保存配置'}
            </Button>
          </DialogActions>
        </Dialog>
      )}

      {/* 第三方登录配置弹窗 */}
      {canWrite && (
        <Dialog open={oauthDialogOpen} onClose={() => { if (!savingOAuth) setOAuthDialogOpen(false); }} maxWidth="sm" fullWidth>
          <DialogTitle>
            {editingProviderId ? '配置身份源' : `接入${selectedOAuthPlugin?.display_name || ''}身份源`}
          </DialogTitle>
          <DialogContent>
            <Stack spacing={2} mt={1}>
              {oauthDialogError && (
                <Alert severity="error" onClose={() => setOAuthDialogError('')}>
                  {oauthDialogError}
                </Alert>
              )}

              <TextField
                label="唯一标识（英文，例如：github、feishu_corp）"
                size="small"
                required
                disabled={Boolean(editingProviderId)}
                value={oauthForm.name}
                onChange={(e) => setOAuthForm({ ...oauthForm, name: e.target.value })}
              />
              <TextField
                label="登录页按钮展示名称"
                size="small"
                required
                value={oauthForm.display_name}
                onChange={(e) => setOAuthForm({ ...oauthForm, display_name: e.target.value })}
              />
              <TextField
                label={selectedOAuthPlugin?.type === 'wecom' ? '企业 CorpID（Client ID）' : 'Client ID / App ID'}
                size="small"
                required
                value={oauthForm.client_id}
                onChange={(e) => setOAuthForm({ ...oauthForm, client_id: e.target.value })}
              />
              <TextField
                label={editingProviderId ? 'Client Secret（留空保持不变）' : 'Client Secret / App Secret'}
                type="password"
                size="small"
                required={!editingProviderId}
                value={oauthForm.client_secret}
                onChange={(e) => setOAuthForm({ ...oauthForm, client_secret: e.target.value })}
              />
              <TextField
                label="授权范围"
                size="small"
                value={oauthForm.scopes}
                onChange={(e) => setOAuthForm({ ...oauthForm, scopes: e.target.value })}
              />

              {selectedOAuthPlugin?.config_fields?.map((field) => (
                <TextField
                  key={field.key}
                  label={field.label}
                  type={field.type === 'password' ? 'password' : 'text'}
                  size="small"
                  required={field.required}
                  placeholder={field.placeholder}
                  helperText={field.description}
                  value={oauthForm.extra_config[field.key] || ''}
                  onChange={(e) =>
                    setOAuthForm({
                      ...oauthForm,
                      extra_config: { ...oauthForm.extra_config, [field.key]: e.target.value },
                    })
                  }
                />
              ))}

              <Stack direction="row" spacing={2}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={oauthForm.auto_register}
                      onChange={(e) => setOAuthForm({ ...oauthForm, auto_register: e.target.checked })}
                    />
                  }
                  label="首次登录自动创建账号"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={oauthForm.enabled}
                      onChange={(e) => setOAuthForm({ ...oauthForm, enabled: e.target.checked })}
                    />
                  }
                  label="立即启用"
                />
              </Stack>
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={() => setOAuthDialogOpen(false)} disabled={savingOAuth}>取消</Button>
            <Button variant="contained" onClick={() => void handleSaveOAuthProvider()} disabled={savingOAuth}>
              {savingOAuth ? '保存中…' : '保存配置'}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};
