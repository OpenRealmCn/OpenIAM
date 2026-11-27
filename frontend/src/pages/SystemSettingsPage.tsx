import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  FormControlLabel,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
import { Save as SaveIcon, Tune as TuneIcon } from '@mui/icons-material';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { SystemSetting } from '../types/api';

const categoryMeta: Record<string, { label: string; desc: string }> = {
  security: { label: '登录与安全', desc: '管理账号锁定阈值、锁定时长及用户注册开关' },
  jwt: { label: '令牌设置', desc: '配置访问令牌与刷新令牌的签发方及有效期' },
  ratelimit: { label: '请求限流', desc: '配置按来源 IP 的接口频率保护规则' },
  oauth_server: { label: 'OAuth / OIDC 服务', desc: '配置对外授权服务的标识、确认页与令牌有效期' },
  oauth_plugin: { label: '第三方登录回调', desc: '配置外部登录方式的默认回调地址前缀' },
  server: { label: '跨域设置', desc: '配置允许访问平台接口的前端来源域名' },
};

const categoryOrder = ['security', 'jwt', 'ratelimit', 'oauth_server', 'oauth_plugin', 'server'];

export const SystemSettingsPage: React.FC = () => {
  const [items, setItems] = useState<SystemSetting[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<string>('security');
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshCount, setRefreshCount] = useState<number>(0);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');

  const loadSettings = async () => {
    setLoading(true);
    setError('');
    try {
      const list: SystemSetting[] = await api.system.getSettings();
      setItems(list || []);
      const initial: Record<string, string> = {};
      for (const s of list || []) {
        initial[s.setting_key] = s.value;
      }
      setDraft(initial);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const categories = useMemo(() => {
    const present = new Set(items.map((i) => i.category));
    return categoryOrder.filter((c) => present.has(c));
  }, [items]);

  const currentItems = useMemo(
    () => items.filter((i) => i.category === activeTab),
    [items, activeTab],
  );

  const dirtyCount = useMemo(() => {
    let n = 0;
    for (const item of items) {
      if ((draft[item.setting_key] ?? '') !== item.value) {
        n++;
      }
    }
    return n;
  }, [items, draft]);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const changed: Record<string, string> = {};
      for (const item of items) {
        const val = draft[item.setting_key] ?? '';
        if (val !== item.value) {
          changed[item.setting_key] = val;
        }
      }
      if (Object.keys(changed).length === 0) {
        setSuccess('当前没有需要保存的更改');
        setSaving(false);
        return;
      }
      const updated: SystemSetting[] = await api.system.updateSettings(changed);
      setItems(updated || []);
      const nextDraft: Record<string, string> = {};
      for (const s of updated || []) {
        nextDraft[s.setting_key] = s.value;
      }
      setDraft(nextDraft);
      setSuccess(`已保存 ${Object.keys(changed).length} 项系统设置并立即生效`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        justifyContent="space-between"
        alignItems={{ sm: 'center' }}
        spacing={2}
        mb={2.5}
      >
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <TuneIcon color="primary" />
            <Typography variant="h5">系统设置</Typography>
            {dirtyCount > 0 && <Chip size="small" color="warning" label={`${dirtyCount} 项未保存`} />}
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.5}>
            调整安全策略、登录限制与 OAuth 参数，保存后立即生效
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.5}>
          <Button
            variant="outlined"
            startIcon={<AnimatedRefreshIcon spinning={loading} spinCount={refreshCount} />}
            onClick={() => {
              setRefreshCount((c) => c + 1);
              loadSettings();
            }}
            disabled={loading || saving}
          >
            刷新
          </Button>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSave}
            disabled={loading || saving || dirtyCount === 0}
          >
            {saving ? '保存中...' : '保存更改'}
          </Button>
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

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
          <CircularProgress />
        </Box>
      ) : (
        <Card>
          <Tabs
            value={activeTab}
            onChange={(_, v) => setActiveTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}
          >
            {categories.map((cat) => (
              <Tab key={cat} value={cat} label={categoryMeta[cat]?.label || cat} />
            ))}
          </Tabs>

          <CardContent sx={{ p: 3 }}>
            <Typography variant="subtitle1" fontWeight={600}>
              {categoryMeta[activeTab]?.label || activeTab}
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={2.5}>
              {categoryMeta[activeTab]?.desc}
            </Typography>

            <Stack spacing={2.5} divider={<Divider flexItem />}>
              {currentItems.map((item) => {
                const currentVal = draft[item.setting_key] ?? item.value;
                const isModified = currentVal !== item.value;
                return (
                  <Box key={item.setting_key}>
                    <Stack
                      direction={{ xs: 'column', md: 'row' }}
                      justifyContent="space-between"
                      alignItems={{ md: 'center' }}
                      spacing={2}
                    >
                      <Box sx={{ flex: 1 }}>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography variant="subtitle2" fontWeight={600}>
                            {item.label || item.setting_key}
                          </Typography>
                          <Chip size="small" variant="outlined" label={item.setting_key} sx={{ fontFamily: 'monospace' }} />
                          {isModified && <Chip size="small" color="warning" label="已修改" />}
                        </Stack>
                        <Typography variant="body2" color="text.secondary" mt={0.5}>
                          {item.description}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          最近更新: {dayjs(item.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                        </Typography>
                      </Box>

                      <Box sx={{ minWidth: { xs: '100%', md: 340 } }}>
                        {item.value_type === 'bool' ? (
                          <FormControlLabel
                            control={
                              <Switch
                                checked={currentVal === 'true'}
                                onChange={(e) =>
                                  setDraft({ ...draft, [item.setting_key]: e.target.checked ? 'true' : 'false' })
                                }
                              />
                            }
                            label={currentVal === 'true' ? '已开启' : '已关闭'}
                          />
                        ) : (
                          <TextField
                            fullWidth
                            size="small"
                            type={item.value_type === 'int' ? 'number' : 'text'}
                            value={currentVal}
                            onChange={(e) => setDraft({ ...draft, [item.setting_key]: e.target.value })}
                          />
                        )}
                      </Box>
                    </Stack>
                  </Box>
                );
              })}
            </Stack>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};
