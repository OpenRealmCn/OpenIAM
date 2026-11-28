import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  Extension as PluginIcon,
  HealthAndSafety as TestIcon,
  Settings as EditIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { PluginDriverMeta, PluginInstance } from '../types/api';

const SLOT_LABELS: Record<string, string> = {
  captcha: '人机验证',
  sms: '短信通道',
  notification: '通知扩展',
  risk: '风控扩展',
};

const HEALTH_LABELS: Record<string, { label: string; color: 'success' | 'error' | 'default' }> = {
  healthy: { label: '正常', color: 'success' },
  unhealthy: { label: '异常', color: 'error' },
  unknown: { label: '未检测', color: 'default' },
};

export const PluginsPage: React.FC = () => {
  const [slot, setSlot] = useState<string>('captcha');
  const [drivers, setDrivers] = useState<PluginDriverMeta[]>([]);
  const [instances, setInstances] = useState<PluginInstance[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 新建或编辑弹窗
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<PluginInstance | null>(null);
  const [selectedType, setSelectedType] = useState('');
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [priority, setPriority] = useState(100);
  const [enabled, setEnabled] = useState(false);
  const [configDraft, setConfigDraft] = useState<Record<string, string>>({});

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [drvList, instList] = await Promise.all([api.plugins.drivers(), api.plugins.list()]);
      setDrivers(drvList || []);
      setInstances(instList || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const slotDrivers = useMemo(() => drivers.filter((d) => d.slot === slot), [drivers, slot]);
  const slotInstances = useMemo(() => instances.filter((i) => i.slot === slot), [instances, slot]);
  const activeDriver = useMemo(() => drivers.find((d) => d.type === selectedType), [drivers, selectedType]);

  const openCreate = () => {
    const first = slotDrivers[0];
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
    setError('');
    setSuccess('');
    try {
      if (editing) {
        await api.plugins.update(editing.id, {
          display_name: displayName.trim(),
          priority: Number(priority) || 100,
          enabled,
          config: configDraft,
        });
        setSuccess(`已更新插件「${displayName}」`);
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
        setSuccess(`已添加插件「${displayName}」`);
      }
      setDialogOpen(false);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleToggle = async (inst: PluginInstance) => {
    setError('');
    try {
      await api.plugins.update(inst.id, { enabled: !inst.enabled });
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
      setSuccess(`插件「${inst.display_name}」连通性检查通过（状态：${statusText}）`);
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
            <Typography variant="h5">统一插件中心</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            管理人机验证、短信网关、告警通知与风控扩展插件
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
          {slotDrivers.length > 0 && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={openCreate}>
              新增插件
            </Button>
          )}
        </Stack>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

      <Card>
        <Tabs value={slot} onChange={(_, v) => setSlot(v)} variant="scrollable" scrollButtons="auto" sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}>
          {Object.entries(SLOT_LABELS).map(([k, label]) => (
            <Tab key={k} value={k} label={label} />
          ))}
        </Tabs>

        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          {slot === 'captcha' && (
            <Alert severity="info" sx={{ mb: 2.5 }}>
              Cap 人机验证支持<strong>本地模式（内置计算校验，无需外部服务）</strong>与<strong>远端模式（对接独立部署的 Cap 验证服务）</strong>；启用后请在「系统设置 → 人机验证策略」中选择需要保护的业务场景。
            </Alert>
          )}

          {slotInstances.length === 0 ? (
            <Alert severity="info">当前分类下暂无已配置的插件，点击右上角「新增插件」即可接入。</Alert>
          ) : (
            <Stack spacing={2}>
              {slotInstances.map((inst) => (
                <Card key={inst.id} variant="outlined">
                  <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                    <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2}>
                      <Box>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
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
                        </Stack>
                        <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                          优先级：{inst.priority} · 最近更新：{dayjs(inst.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                        </Typography>
                      </Box>

                      <Stack direction="row" spacing={1} alignItems="center">
                        <FormControlLabel
                          control={<Switch checked={inst.enabled} onChange={() => handleToggle(inst)} />}
                          label={inst.enabled ? '已启用' : '已停用'}
                        />
                        <Button size="small" variant="outlined" startIcon={<TestIcon />} onClick={() => handleTest(inst)}>
                          测试
                        </Button>
                        <Button size="small" variant="contained" startIcon={<EditIcon />} onClick={() => openEdit(inst)}>
                          配置
                        </Button>
                      </Stack>
                    </Stack>
                  </CardContent>
                </Card>
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{editing ? `配置插件：${editing.display_name}` : `新增 ${SLOT_LABELS[slot] || slot} 插件`}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {!editing && (
              <>
                <FormControl size="small" fullWidth>
                  <InputLabel>插件驱动</InputLabel>
                  <Select
                    label="插件驱动"
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
                <TextField label="插件标识（仅限英文、数字与短横线）" size="small" fullWidth value={name} onChange={(e) => setName(e.target.value)} placeholder="如 cap-prod" />
              </>
            )}

            <TextField label="显示名称" size="small" fullWidth value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            <TextField label="优先级（越小越优先）" type="number" size="small" fullWidth value={priority} onChange={(e) => setPriority(Number(e.target.value))} />

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
          <Button onClick={() => setDialogOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleSave}>保存配置</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
