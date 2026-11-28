import React, { useCallback, useEffect, useState } from 'react';
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
  Divider,
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
  Campaign as AnnounceIcon,
  DoneAll as DoneAllIcon,
  Edit as EditIcon,
  NotificationsActive as NotifIcon,
  ReportProblem as BounceIcon,
  Visibility as PreviewIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { NotificationDelivery, NotificationItem, NotificationTemplate } from '../types/api';

const CATEGORY_LABELS: Record<string, string> = {
  system_message: '系统消息',
  announcement: '系统公告',
  system_notice: '系统通知',
};

export const NotificationsPage: React.FC = () => {
  const { adminTier, refreshUnreadCount } = useAuth();
  const isPlatformAdmin = adminTier === 'platform_admin';

  const [tab, setTab] = useState<'inbox' | 'templates' | 'deliveries'>('inbox');
  const [catFilter, setCatFilter] = useState<string>('all');
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [templates, setTemplates] = useState<NotificationTemplate[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 发布全员公告弹窗
  const [annOpen, setAnnOpen] = useState(false);
  const [annForm, setAnnForm] = useState({ title: '', content: '', level: 'info' });

  // 模板编辑与预览弹窗
  const [tplOpen, setTplOpen] = useState(false);
  const [editingTpl, setEditingTpl] = useState<NotificationTemplate | null>(null);
  const [tplForm, setTplForm] = useState({
    code: '',
    name: '',
    channel: 'email',
    subject: '',
    body: '',
    variablesText: '',
    enabled: true,
  });
  const [previewResult, setPreviewResult] = useState<{ subject: string; body: string } | null>(null);

  const loadInbox = useCallback(async () => {
    try {
      const list = await api.notifications.list(catFilter === 'all' ? undefined : { category: catFilter });
      setItems(list || []);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [catFilter]);

  const loadTemplates = useCallback(async () => {
    if (!isPlatformAdmin) return;
    try {
      setTemplates((await api.notifications.listTemplates()) || []);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [isPlatformAdmin]);

  const loadDeliveries = useCallback(async () => {
    if (!isPlatformAdmin) return;
    try {
      setDeliveries((await api.notifications.listDeliveries()) || []);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [isPlatformAdmin]);

  useEffect(() => {
    void loadInbox();
    void loadTemplates();
    void loadDeliveries();
  }, [loadInbox, loadTemplates, loadDeliveries]);

  const handleMarkRead = async (id: number) => {
    await api.notifications.markRead(id);
    await Promise.all([loadInbox(), refreshUnreadCount()]);
  };

  const handleReadAll = async () => {
    await api.notifications.markAllRead();
    await Promise.all([loadInbox(), refreshUnreadCount()]);
  };

  const handlePublishAnnouncement = async () => {
    setError('');
    try {
      await api.notifications.createAnnouncement(annForm);
      setAnnOpen(false);
      setAnnForm({ title: '', content: '', level: 'info' });
      setSuccess('已发布全员系统公告');
      await Promise.all([loadInbox(), refreshUnreadCount()]);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const openEditTemplate = (tpl?: NotificationTemplate) => {
    setPreviewResult(null);
    if (tpl) {
      setEditingTpl(tpl);
      setTplForm({
        code: tpl.code,
        name: tpl.name,
        channel: tpl.channel,
        subject: tpl.subject,
        body: tpl.body,
        variablesText: (tpl.variables || []).join(', '),
        enabled: tpl.enabled,
      });
    } else {
      setEditingTpl(null);
      setTplForm({ code: '', name: '', channel: 'email', subject: '', body: '', variablesText: 'username, code', enabled: true });
    }
    setTplOpen(true);
  };

  const handleSaveTemplate = async () => {
    const vars = tplForm.variablesText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const payload = {
      code: tplForm.code.trim(),
      name: tplForm.name.trim(),
      channel: tplForm.channel,
      subject: tplForm.subject,
      body: tplForm.body,
      variables: vars,
      enabled: tplForm.enabled,
    };
    try {
      if (editingTpl) {
        await api.notifications.updateTemplate(editingTpl.id, payload);
      } else {
        await api.notifications.createTemplate(payload);
      }
      setTplOpen(false);
      setSuccess('消息模板已保存');
      await loadTemplates();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handlePreviewTemplate = async () => {
    const vars: Record<string, string> = {};
    for (const k of tplForm.variablesText.split(',').map((s) => s.trim()).filter(Boolean)) {
      vars[k] = k === 'code' ? '824619' : `[示例_${k}]`;
    }
    const res = await api.notifications.previewTemplate({ subject: tplForm.subject, body: tplForm.body, vars });
    setPreviewResult(res);
  };

  const handleMarkBounced = async (row: NotificationDelivery) => {
    const reason = window.prompt('请输入退信原因（如 550 User unknown）：', '收件地址不存在或拒收');
    if (reason === null) return;
    try {
      await api.notifications.markBounced(row.id, reason);
      setSuccess('已标记退信并触发管理员通知');
      await Promise.all([loadDeliveries(), loadInbox(), refreshUnreadCount()]);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const deliveryColumns: GridColDef<NotificationDelivery>[] = [
    { field: 'channel', headerName: '通道', width: 90 },
    { field: 'template_code', headerName: '模板', width: 130 },
    { field: 'recipient', headerName: '接收方', width: 200 },
    {
      field: 'status',
      headerName: '状态',
      width: 110,
      renderCell: (p) => {
        const val = p.value as string;
        const color = val === 'sent' ? 'success' : val === 'bounced' ? 'error' : val === 'degraded' ? 'warning' : 'default';
        return <Chip size="small" color={color} label={val} />;
      },
    },
    { field: 'provider_name', headerName: '驱动节点', width: 130 },
    { field: 'cost_cents', headerName: '费用(分)', width: 90 },
    { field: 'bounce_reason', headerName: '错误/退信原因', flex: 1, minWidth: 180, valueGetter: (_, r) => r.bounce_reason || r.error_message || '-' },
    {
      field: 'created_at',
      headerName: '时间',
      width: 155,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '-'),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '退信',
      width: 70,
      getActions: (p) =>
        p.row.status !== 'bounced'
          ? [<GridActionsCellItem key="bounce" icon={<BounceIcon color="warning" />} label="标记退信" onClick={() => handleMarkBounced(p.row)} />]
          : [],
    },
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <NotifIcon color="primary" />
            <Typography variant="h5">通知中心与模板管理</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            统一管理个人系统消息、平台系统公告与运维系统通知，支持多通道消息模板与退信追踪
          </Typography>
        </Box>
        {isPlatformAdmin && (
          <Stack direction="row" spacing={1.2}>
            <Button variant="outlined" startIcon={<AnnounceIcon />} onClick={() => setAnnOpen(true)}>
              发布系统公告
            </Button>
            {tab === 'templates' && (
              <Button variant="contained" startIcon={<AddIcon />} onClick={() => openEditTemplate()}>
                新建模板
              </Button>
            )}
          </Stack>
        )}
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

      <Card>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Tab value="inbox" label="站内消息与公告" />
          {isPlatformAdmin && <Tab value="templates" label="消息模板管理" />}
          {isPlatformAdmin && <Tab value="deliveries" label="发送记录与退信处理" />}
        </Tabs>

        <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
          {tab === 'inbox' && (
            <Box>
              <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1} mb={2}>
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  {[
                    { key: 'all', label: '全部' },
                    { key: 'system_message', label: '系统消息' },
                    { key: 'announcement', label: '系统公告' },
                    ...(adminTier !== 'user' ? [{ key: 'system_notice', label: '系统通知' }] : []),
                  ].map((c) => (
                    <Chip
                      key={c.key}
                      label={c.label}
                      color={catFilter === c.key ? 'primary' : 'default'}
                      variant={catFilter === c.key ? 'filled' : 'outlined'}
                      onClick={() => setCatFilter(c.key)}
                    />
                  ))}
                </Stack>
                <Button size="small" startIcon={<DoneAllIcon />} onClick={handleReadAll}>
                  全部标为已读
                </Button>
              </Stack>

              {items.length === 0 ? (
                <Alert severity="info">当前分类暂无通知记录</Alert>
              ) : (
                <Stack spacing={1.5}>
                  {items.map((item) => (
                    <Card key={item.id} variant="outlined" sx={{ opacity: item.is_read ? 0.72 : 1 }}>
                      <CardContent sx={{ py: 1.6, '&:last-child': { pb: 1.6 } }}>
                        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
                          <Box>
                            <Stack direction="row" spacing={1} alignItems="center" mb={0.5}>
                              <Chip
                                size="small"
                                label={CATEGORY_LABELS[item.category] || item.category}
                                color={item.level === 'security' || item.level === 'error' ? 'error' : item.level === 'warning' ? 'warning' : 'primary'}
                              />
                              <Typography variant="subtitle2" fontWeight={700}>{item.title}</Typography>
                              {!item.is_read && <Chip size="small" color="error" variant="outlined" label="未读" />}
                            </Stack>
                            <Typography variant="body2" color="text.secondary">{item.content}</Typography>
                            <Typography variant="caption" color="text.disabled" display="block" mt={0.5}>
                              {dayjs(item.created_at).format('YYYY-MM-DD HH:mm:ss')}
                            </Typography>
                          </Box>
                          {!item.is_read && (
                            <Button size="small" onClick={() => handleMarkRead(item.id)}>标为已读</Button>
                          )}
                        </Stack>
                      </CardContent>
                    </Card>
                  ))}
                </Stack>
              )}
            </Box>
          )}

          {tab === 'templates' && isPlatformAdmin && (
            <Stack spacing={2}>
              {templates.map((tpl) => (
                <Card key={tpl.id} variant="outlined">
                  <CardContent sx={{ py: 1.8, '&:last-child': { pb: 1.8 } }}>
                    <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={1.5}>
                      <Box>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography variant="subtitle2" fontWeight={700}>{tpl.name}</Typography>
                          <Chip size="small" label={tpl.code} sx={{ fontFamily: 'monospace' }} />
                          <Chip size="small" color="info" variant="outlined" label={tpl.channel} />
                          <Chip size="small" color={tpl.enabled ? 'success' : 'default'} label={tpl.enabled ? '启用' : '停用'} />
                        </Stack>
                        <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                          变量：{(tpl.variables || []).map((v) => `{{${v}}}`).join(' ') || '无'}
                        </Typography>
                      </Box>
                      <Button size="small" startIcon={<EditIcon />} variant="outlined" onClick={() => openEditTemplate(tpl)}>
                        编辑与预览
                      </Button>
                    </Stack>
                  </CardContent>
                </Card>
              ))}
            </Stack>
          )}

          {tab === 'deliveries' && isPlatformAdmin && (
            <Box sx={{ height: 500 }}>
              <DataGrid rows={deliveries} columns={deliveryColumns} disableRowSelectionOnClick />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* 发布系统公告弹窗 */}
      <Dialog open={annOpen} onClose={() => setAnnOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>发布全员系统公告</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField label="公告标题" size="small" fullWidth value={annForm.title} onChange={(e) => setAnnForm({ ...annForm, title: e.target.value })} />
            <FormControl size="small" fullWidth>
              <InputLabel>级别</InputLabel>
              <Select label="级别" value={annForm.level} onChange={(e) => setAnnForm({ ...annForm, level: e.target.value })}>
                <MenuItem value="info">普通通知</MenuItem>
                <MenuItem value="warning">维护警告</MenuItem>
                <MenuItem value="security">安全公告</MenuItem>
              </Select>
            </FormControl>
            <TextField label="公告正文" size="small" fullWidth multiline minRows={4} value={annForm.content} onChange={(e) => setAnnForm({ ...annForm, content: e.target.value })} />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setAnnOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handlePublishAnnouncement}>立即发布</Button>
        </DialogActions>
      </Dialog>

      {/* 模板编辑与变量预览弹窗 */}
      <Dialog open={tplOpen} onClose={() => setTplOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{editingTpl ? `编辑模板：${editingTpl.code}` : '新建消息模板'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField label="模板编码" size="small" fullWidth disabled={Boolean(editingTpl)} value={tplForm.code} onChange={(e) => setTplForm({ ...tplForm, code: e.target.value })} />
            <TextField label="模板名称" size="small" fullWidth value={tplForm.name} onChange={(e) => setTplForm({ ...tplForm, name: e.target.value })} />
            <FormControl size="small" fullWidth>
              <InputLabel>通道</InputLabel>
              <Select label="通道" value={tplForm.channel} onChange={(e) => setTplForm({ ...tplForm, channel: e.target.value })}>
                <MenuItem value="email">邮件 (email)</MenuItem>
                <MenuItem value="sms">短信 (sms)</MenuItem>
                <MenuItem value="in_app">站内信 (in_app)</MenuItem>
              </Select>
            </FormControl>
            <TextField label="主题 / 标题" size="small" fullWidth value={tplForm.subject} onChange={(e) => setTplForm({ ...tplForm, subject: e.target.value })} />
            <TextField label="正文（支持 {{变量名}} 占位符）" size="small" fullWidth multiline minRows={4} value={tplForm.body} onChange={(e) => setTplForm({ ...tplForm, body: e.target.value })} />
            <TextField label="变量清单（逗号分隔）" size="small" fullWidth value={tplForm.variablesText} onChange={(e) => setTplForm({ ...tplForm, variablesText: e.target.value })} />
            <FormControlLabel control={<Switch checked={tplForm.enabled} onChange={(e) => setTplForm({ ...tplForm, enabled: e.target.checked })} />} label="启用模板" />
            {previewResult && (
              <>
                <Divider />
                <Alert severity="info">
                  <Typography variant="subtitle2" fontWeight={700}>{previewResult.subject}</Typography>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', mt: 0.5 }}>{previewResult.body}</Typography>
                </Alert>
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button startIcon={<PreviewIcon />} onClick={handlePreviewTemplate}>变量渲染预览</Button>
          <Box sx={{ flex: 1 }} />
          <Button onClick={() => setTplOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleSaveTemplate}>保存模板</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
