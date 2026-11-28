import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  alpha,
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
  Radio,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Language as NetworkIcon,
  MarkEmailRead as MailTestIcon,
  Save as SaveIcon,
  Tune as TuneIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useSite } from '../context/SiteContext';
import { ClientIPMethodPreview, ClientIPPreviewResult, SystemSetting } from '../types/api';

const categoryMeta: Record<string, { label: string; desc: string }> = {
  site: { label: '站点与公告', desc: '配置站点名称、全局图标、浏览器标签图标、页脚版权与全站首页公告' },
  smtp: { label: '邮件服务', desc: '配置 SMTP 发件服务器，用于发送测试邮件、邮箱验证码与找回密码' },
  otp: { label: '验证码与防刷', desc: '配置短信与邮件验证码的频控阈值、单条成本折算、日预算告警及异常降级策略' },
  risk: { label: '风险自适应认证', desc: '配置 IP 信誉、异地、设备变化等维度的风险阈值与处置动作' },
  captcha: { label: '人机验证策略', desc: '配置登录、注册、发送验证码场景是否启用人机验证（在插件中心配置验证服务）' },
  security: { label: '登录与安全', desc: '管理账号锁定阈值、锁定时长及用户公开注册开关' },
  jwt: { label: '令牌设置', desc: '配置访问令牌与刷新令牌的签发方及有效期' },
  ratelimit: { label: '请求限流', desc: '配置按来源 IP 的接口频率保护规则' },
  oauth_server: { label: 'OAuth / OIDC 服务', desc: '配置对外授权服务的标识、确认页与令牌有效期' },
  oauth_plugin: { label: '第三方登录回调', desc: '配置外部登录方式的默认回调地址前缀' },
  server: { label: '网络与真实 IP', desc: '配置客户端真实 IP 获取方式、可信反向代理网段及跨域来源白名单' },
};

const categoryOrder = ['site', 'smtp', 'otp', 'risk', 'captcha', 'security', 'jwt', 'ratelimit', 'oauth_server', 'oauth_plugin', 'server'];

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
  'risk.high_action': [
    { value: 'challenge_mfa', label: '强制二次身份验证（推荐）' },
    { value: 'notify', label: '仅写入风险日志并发送安全提醒' },
    { value: 'block', label: '直接阻断该次登录请求' },
  ],
  'server.client_ip_method': [
    { value: 'remote_addr', label: '直连来源 IP（TCP RemoteAddr）' },
    { value: 'x_forwarded_for', label: '反向代理链（X-Forwarded-For，默认）' },
    { value: 'x_real_ip', label: '单层反代头（X-Real-IP）' },
    { value: 'cf_connecting_ip', label: 'Cloudflare CDN（CF-Connecting-IP）' },
    { value: 'true_client_ip', label: '通用 CDN / WAF（True-Client-IP）' },
    { value: 'custom_header', label: '自定义请求头（Custom Header）' },
  ],
  'security.register_email_mode': [
    { value: 'disabled', label: '关闭（注册时不收集邮箱）' },
    { value: 'optional', label: '选填（允许不填邮箱）' },
    { value: 'required', label: '必填（默认，必须提供邮箱）' },
  ],
  'security.register_phone_mode': [
    { value: 'disabled', label: '关闭（注册时不收集手机号）' },
    { value: 'optional', label: '选填（允许填写手机号）' },
    { value: 'required', label: '必填（必须提供手机号）' },
  ],
  'security.register_verify_mode': [
    { value: 'none', label: '无需验证码（直接注册）' },
    { value: 'email', label: '需验证邮箱验证码' },
    { value: 'sms', label: '需验证手机短信验证码' },
    { value: 'either', label: '邮箱或短信验证码二选一' },
    { value: 'both', label: '邮箱与短信验证码均需验证' },
  ],
};

const IP_PREVIEW_STATUS_META: Record<
  ClientIPMethodPreview['status'],
  { label: string; color: 'success' | 'info' | 'warning' | 'error' | 'default' }
> = {
  matched: { label: '已命中请求头', color: 'success' },
  direct: { label: '直连获取', color: 'info' },
  fallback_no_header: { label: '未携带该请求头（已回退直连）', color: 'default' },
  fallback_untrusted: { label: '直连来源不在可信代理中（已拒绝采信）', color: 'warning' },
  fallback_invalid: { label: '请求头 IP 格式无效（已回退直连）', color: 'error' },
  not_configured: { label: '请先填写自定义请求头名称', color: 'default' },
};

export const SystemSettingsPage: React.FC = () => {
  const theme = useTheme();
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

  // 真实 IP 获取方式实时预览状态
  const [ipPreview, setIpPreview] = useState<ClientIPPreviewResult | null>(null);
  const [ipPreviewLoading, setIpPreviewLoading] = useState<boolean>(false);
  const [ipPreviewError, setIpPreviewError] = useState<string>('');

  const loadClientIPPreview = useCallback(
    async (overrideDraft?: Record<string, string>) => {
      setIpPreviewLoading(true);
      setIpPreviewError('');
      const src = overrideDraft || draft;
      try {
        const res = await api.system.previewClientIP({
          custom_header: src['server.client_ip_custom_header'] ?? '',
          trusted_proxies: src['server.trusted_proxies'] ?? '',
        });
        setIpPreview(res);
      } catch (err) {
        setIpPreviewError((err as Error).message);
      } finally {
        setIpPreviewLoading(false);
      }
    },
    [draft],
  );

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

  useEffect(() => {
    if (activeTab === 'server' && !loading) {
      void loadClientIPPreview();
    }
    // 仅在切换到网络与真实 IP 标签页或刚加载完成时自动拉取一次实时预览，避免编辑输入框时频繁请求
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, loading]);

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
      if (activeTab === 'server') {
        void loadClientIPPreview(nextDraft);
      }
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

            {/* 真实客户端 IP 获取方式选择与实时预览卡片 */}
            {activeTab === 'server' && (
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
                <Stack
                  direction={{ xs: 'column', sm: 'row' }}
                  justifyContent="space-between"
                  alignItems={{ sm: 'center' }}
                  spacing={1.5}
                  mb={2}
                >
                  <Box>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <NetworkIcon color="primary" fontSize="small" />
                      <Typography variant="subtitle2" fontWeight={700}>
                        真实 IP 获取方式选择与实时预览
                      </Typography>
                    </Stack>
                    <Typography variant="body2" color="text.secondary" mt={0.4}>
                      以下是基于您当前浏览器发起的这次真实请求，各获取方式实时解析出的客户端 IP；请对照您的实际出口 IP 核对后再点击「保存更改」。
                    </Typography>
                  </Box>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<AnimatedRefreshIcon spinning={ipPreviewLoading} />}
                    onClick={() => void loadClientIPPreview()}
                    disabled={ipPreviewLoading}
                    sx={{ flexShrink: 0 }}
                  >
                    {ipPreviewLoading ? '检测中...' : '重新检测预览'}
                  </Button>
                </Stack>

                {ipPreviewError && (
                  <Alert severity="error" sx={{ mb: 2 }} onClose={() => setIpPreviewError('')}>
                    {ipPreviewError}
                  </Alert>
                )}

                {ipPreview && (
                  <>
                    <Alert
                      severity={ipPreview.active_is_public ? 'success' : 'info'}
                      sx={{ mb: 2 }}
                    >
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography variant="body2">
                          当前线上生效方式解析 IP：
                          <Box component="span" sx={{ fontFamily: 'monospace', fontWeight: 700, mx: 0.5 }}>
                            {ipPreview.active_ip || '未知'}
                          </Box>
                        </Typography>
                        <Chip
                          size="small"
                          color={ipPreview.active_is_public ? 'success' : 'default'}
                          label={ipPreview.active_is_public ? '公网 IP' : '内网 / 本地 IP'}
                        />
                        <Typography variant="caption" color="text.secondary">
                          TCP 直连来源：{ipPreview.remote_addr || '未知'}（
                          {ipPreview.trusted_proxy_matched ? '命中可信代理' : '未命中可信代理'}）
                        </Typography>
                      </Stack>
                    </Alert>

                    <Stack spacing={1.25}>
                      {ipPreview.options.map((opt) => {
                        const selectedMethod = draft['server.client_ip_method'] || ipPreview.active_method || 'x_forwarded_for';
                        const isSelected = selectedMethod === opt.method;
                        const statusMeta = IP_PREVIEW_STATUS_META[opt.status] || {
                          label: opt.status,
                          color: 'default' as const,
                        };
                        return (
                          <Card
                            key={opt.method}
                            variant="outlined"
                            onClick={() =>
                              setDraft((prev) => ({
                                ...prev,
                                'server.client_ip_method': opt.method,
                              }))
                            }
                            sx={{
                              cursor: 'pointer',
                              borderColor: isSelected ? 'primary.main' : 'divider',
                              bgcolor: isSelected ? alpha(theme.palette.primary.main, 0.05) : 'background.paper',
                              transition: 'border-color 0.15s ease, background-color 0.15s ease',
                              '&:hover': {
                                borderColor: isSelected ? 'primary.main' : alpha(theme.palette.primary.main, 0.45),
                              },
                            }}
                          >
                            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                              <Stack
                                direction={{ xs: 'column', md: 'row' }}
                                justifyContent="space-between"
                                alignItems={{ md: 'center' }}
                                spacing={1.5}
                              >
                                <Stack direction="row" spacing={1} alignItems="flex-start" sx={{ flex: 1, minWidth: 0 }}>
                                  <Radio
                                    size="small"
                                    checked={isSelected}
                                    onChange={() =>
                                      setDraft((prev) => ({
                                        ...prev,
                                        'server.client_ip_method': opt.method,
                                      }))
                                    }
                                    sx={{ mt: -0.4 }}
                                  />
                                  <Box sx={{ minWidth: 0 }}>
                                    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                                      <Typography variant="subtitle2" fontWeight={700}>
                                        {opt.label}
                                      </Typography>
                                      <Chip size="small" variant="outlined" label={`来源：${opt.source}`} />
                                      {opt.is_active && <Chip size="small" color="primary" label="当前已保存生效" />}
                                      {isSelected && !opt.is_active && (
                                        <Chip size="small" color="warning" label="待保存选择" />
                                      )}
                                    </Stack>
                                    <Typography variant="body2" color="text.secondary" mt={0.4}>
                                      {opt.description}
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary" display="block" mt={0.35}>
                                      {opt.note}
                                      {opt.raw_header && opt.method !== 'remote_addr'
                                        ? `（原始请求头值：${opt.raw_header}）`
                                        : ''}
                                    </Typography>
                                  </Box>
                                </Stack>

                                <Stack
                                  direction="column"
                                  alignItems={{ xs: 'flex-start', md: 'flex-end' }}
                                  spacing={0.6}
                                  sx={{ flexShrink: 0 }}
                                >
                                  <Stack direction="row" spacing={0.8} alignItems="center">
                                    <Typography variant="caption" color="text.secondary">
                                      预览 IP：
                                    </Typography>
                                    <Chip
                                      size="small"
                                      color={opt.is_public ? 'success' : 'default'}
                                      variant={opt.from_header || opt.method === 'remote_addr' ? 'filled' : 'outlined'}
                                      label={opt.resolved_ip || '无'}
                                      sx={{ fontFamily: 'monospace', fontWeight: 700 }}
                                    />
                                    <Chip
                                      size="small"
                                      variant="outlined"
                                      color={opt.is_public ? 'success' : 'default'}
                                      label={opt.is_public ? '公网' : '内网/本地'}
                                    />
                                  </Stack>
                                  <Chip size="small" color={statusMeta.color} variant="outlined" label={statusMeta.label} />
                                </Stack>
                              </Stack>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </Stack>
                  </>
                )}
              </Box>
            )}

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
