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
  FormControl,
  FormControlLabel,
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
  MarkEmailRead as MailTestIcon,
  Save as SaveIcon,
  Tune as TuneIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useSite } from '../context/SiteContext';
import { SystemSetting } from '../types/api';

const categoryMeta: Record<string, { label: string; desc: string }> = {
  site: { label: '站点与公告', desc: '配置站点名称、全局图标、浏览器标签图标、页脚版权与全站首页公告' },
  smtp: { label: '邮件服务', desc: '配置 SMTP 发件服务器，用于发送测试邮件与找回密码验证码' },
  security: { label: '登录与安全', desc: '管理账号锁定阈值、锁定时长及用户公开注册开关' },
  jwt: { label: '令牌设置', desc: '配置访问令牌与刷新令牌的签发方及有效期' },
  ratelimit: { label: '请求限流', desc: '配置按来源 IP 的接口频率保护规则' },
  oauth_server: { label: 'OAuth / OIDC 服务', desc: '配置对外授权服务的标识、确认页与令牌有效期' },
  oauth_plugin: { label: '第三方登录回调', desc: '配置外部登录方式的默认回调地址前缀' },
  server: { label: '跨域设置', desc: '配置允许访问平台接口的前端来源域名' },
};

const categoryOrder = ['site', 'smtp', 'security', 'jwt', 'ratelimit', 'oauth_server', 'oauth_plugin', 'server'];

const SELECT_OPTIONS: Record<string, { value: string; label: string }[]> = {
  'site.announcement_type': [
    { value: 'info', label: '普通通知（蓝色）' },
    { value: 'success', label: '积极提示（绿色）' },
    { value: 'warning', label: '维护警告（橙色）' },
    { value: 'error', label: '重要告警（红色）' },
  ],
  'smtp.encryption': [
    { value: 'starttls', label: 'STARTTLS（推荐，常用端口 587）' },
    { value: 'tls', label: '隐式 SSL/TLS（常用端口 465）' },
    { value: 'none', label: '明文无加密（仅限内网中继）' },
  ],
};

export const SystemSettingsPage: React.FC = () => {
  const { refreshSiteInfo } = useSite();
  const [items, setItems] = useState<SystemSetting[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<string>('site');
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshCount, setRefreshCount] = useState<number>(0);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');

  // SMTP 测试邮件状态
  const [testEmailTo, setTestEmailTo] = useState<string>('');
  const [sendingTest, setSendingTest] = useState<boolean>(false);

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

  useEffect(() => {
    if (categories.length > 0 && !categories.includes(activeTab)) {
      setActiveTab(categories[0]);
    }
  }, [categories, activeTab]);

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
      await refreshSiteInfo();
      setSuccess(`已保存 ${Object.keys(changed).length} 项系统设置并立即生效`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleSendTestEmail = async () => {
    setError('');
    setSuccess('');
    if (!testEmailTo.trim()) {
      setError('请先填写测试收件人邮箱');
      return;
    }
    if (dirtyCount > 0) {
      setError('请先点击右上角「保存更改」，再发送测试邮件以使用最新配置');
      return;
    }
    setSendingTest(true);
    try {
      await api.system.testSMTP(testEmailTo.trim());
      setSuccess(`测试邮件已成功发送至 ${testEmailTo.trim()}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSendingTest(false);
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
            配置站点品牌、首页公告、邮件发信服务及全局安全策略，保存后立即生效
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

          <CardContent sx={{ p: { xs: 2.5, sm: 3 } }}>
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
                const selectOpts = SELECT_OPTIONS[item.setting_key];
                const isLogoField = item.setting_key === 'site.logo_url' || item.setting_key === 'site.favicon_url';

                return (
                  <Box key={item.setting_key}>
                    <Stack
                      direction={{ xs: 'column', md: 'row' }}
                      justifyContent="space-between"
                      alignItems={{ md: 'center' }}
                      spacing={2}
                    >
                      <Box sx={{ flex: 1 }}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
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

                      <Box sx={{ minWidth: { xs: '100%', md: 360 } }}>
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
                        ) : selectOpts ? (
                          <FormControl fullWidth size="small">
                            <Select
                              value={currentVal || selectOpts[0].value}
                              onChange={(e) => setDraft({ ...draft, [item.setting_key]: e.target.value })}
                            >
                              {selectOpts.map((opt) => (
                                <MenuItem key={opt.value} value={opt.value}>
                                  {opt.label}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        ) : item.value_type === 'text' ? (
                          <TextField
                            fullWidth
                            size="small"
                            multiline
                            minRows={2}
                            maxRows={5}
                            value={currentVal}
                            onChange={(e) => setDraft({ ...draft, [item.setting_key]: e.target.value })}
                          />
                        ) : item.value_type === 'secret' ? (
                          <TextField
                            fullWidth
                            size="small"
                            type="password"
                            placeholder="留空则保持当前密码不变"
                            autoComplete="new-password"
                            value={currentVal}
                            onChange={(e) => setDraft({ ...draft, [item.setting_key]: e.target.value })}
                          />
                        ) : (
                          <Stack direction="row" spacing={1.2} alignItems="center">
                            {isLogoField && currentVal && (
                              <Box
                                component="img"
                                src={currentVal}
                                alt="预览"
                                sx={{
                                  width: 32,
                                  height: 32,
                                  borderRadius: 1,
                                  objectFit: 'contain',
                                  border: 1,
                                  borderColor: 'divider',
                                  flexShrink: 0,
                                }}
                              />
                            )}
                            <TextField
                              fullWidth
                              size="small"
                              type={item.value_type === 'int' ? 'number' : 'text'}
                              value={currentVal}
                              onChange={(e) => setDraft({ ...draft, [item.setting_key]: e.target.value })}
                            />
                          </Stack>
                        )}
                      </Box>
                    </Stack>
                  </Box>
                );
              })}
            </Stack>

            {/* SMTP 连通性测试面板 */}
            {activeTab === 'smtp' && (
              <Box
                sx={{
                  mt: 3.5,
                  p: 2.5,
                  borderRadius: 2,
                  border: 1,
                  borderColor: 'divider',
                  bgcolor: 'background.default',
                }}
              >
                <Typography variant="subtitle2" fontWeight={600} mb={0.5}>
                  发送测试邮件
                </Typography>
                <Typography variant="body2" color="text.secondary" mb={2}>
                  验证当前已保存的 SMTP 服务器、端口、加密方式与账号密码是否能够正常投递邮件
                </Typography>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
                  <TextField
                    size="small"
                    type="email"
                    placeholder="输入测试收件人邮箱，例如 admin@example.com"
                    value={testEmailTo}
                    onChange={(e) => setTestEmailTo(e.target.value)}
                    sx={{ flex: 1, maxWidth: 360 }}
                  />
                  <Button
                    variant="contained"
                    startIcon={<MailTestIcon />}
                    onClick={handleSendTestEmail}
                    disabled={sendingTest || saving}
                  >
                    {sendingTest ? '发送中...' : '发送测试邮件'}
                  </Button>
                </Stack>
              </Box>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};
