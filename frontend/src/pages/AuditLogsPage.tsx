import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Drawer,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Visibility as DetailIcon } from '@mui/icons-material';
import {
  DataGrid,
  GridActionsCellItem,
  GridColDef,
  GridPaginationModel,
  GridToolbar,
} from '@mui/x-data-grid';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import dayjs, { Dayjs } from 'dayjs';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { AuditLog } from '../types/api';

const STATUS_LABELS: Record<string, { label: string; color: 'success' | 'error' }> = {
  success: { label: '成功', color: 'success' },
  failed: { label: '失败', color: 'error' },
};

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  role: '角色',
  role_policy: '角色权限',
  user_role: '用户角色',
  permission: '权限项',
  casbin_policy: '访问策略',
  user: '用户与认证',
  oauth_client: 'OAuth 应用',
  oauth_provider: '第三方登录',
  system_setting: '系统设置',
  temp_role_grant: '临时权限',
  plugin: '插件配置',
  domain: '域',
};

export const AuditLogsPage: React.FC = () => {
  const { currentDomain } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [actor, setActor] = useState('');
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [status, setStatus] = useState('');
  const [startTime, setStartTime] = useState<Dayjs | null>(null);
  const [endTime, setEndTime] = useState<Dayjs | null>(null);
  const [paginationModel, setPaginationModel] = useState<GridPaginationModel>({
    page: 0,
    pageSize: 20,
  });
  const [detailLog, setDetailLog] = useState<AuditLog | null>(null);

  const resetToFirstPage = () => {
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  };

  useEffect(() => {
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  }, [currentDomain]);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.audit.list({
        page: paginationModel.page + 1,
        page_size: paginationModel.pageSize,
        actor: actor.trim() || undefined,
        action: action.trim() || undefined,
        resource_type: resourceType || undefined,
        status: status || undefined,
        start_time: startTime ? startTime.toISOString() : undefined,
        end_time: endTime ? endTime.toISOString() : undefined,
      });
      setLogs(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [
    currentDomain,
    paginationModel.page,
    paginationModel.pageSize,
    actor,
    action,
    resourceType,
    status,
    startTime,
    endTime,
  ]);

  useEffect(() => {
    void loadLogs();
  }, [loadLogs]);

  const columns: GridColDef<AuditLog>[] = [
    {
      field: 'created_at',
      headerName: '时间',
      width: 165,
      valueFormatter: (v) => dayjs(v as string).format('YYYY-MM-DD HH:mm:ss'),
    },
    { field: 'actor_username', headerName: '操作人', width: 120 },
    { field: 'domain_code', headerName: '域', width: 100 },
    {
      field: 'action',
      headerName: '事件动作',
      width: 190,
      renderCell: (p) => (
        <Chip
          size="small"
          color={String(p.value).startsWith('rbac.') ? 'secondary' : 'primary'}
          variant="outlined"
          label={p.value}
        />
      ),
    },
    {
      field: 'resource_type',
      headerName: '资源类型',
      width: 120,
      valueFormatter: (v) => RESOURCE_TYPE_LABELS[v as string] || String(v || '-'),
    },
    { field: 'resource_id', headerName: '资源标识', width: 160 },
    { field: 'ip_address', headerName: '来源 IP', width: 130 },
    {
      field: 'status',
      headerName: '状态',
      width: 90,
      renderCell: (p) => {
        const meta = STATUS_LABELS[p.value as string] || { label: String(p.value || '-'), color: 'error' as const };
        return <Chip size="small" color={meta.color} label={meta.label} />;
      },
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '详情',
      width: 75,
      getActions: (p) => [
        <GridActionsCellItem
          key="view"
          icon={<DetailIcon />}
          label="查看变更详情"
          onClick={() => setDetailLog(p.row)}
        />,
      ],
    },
  ];

  return (
    <LocalizationProvider dateAdapter={AdapterDayjs} adapterLocale="zh-cn">
      <Box>
        <Typography variant="h5" mb={0.5}>
          审计日志
        </Typography>
        <Typography variant="body2" color="text.secondary" mb={2.5}>
          查看登录记录与用户、角色、权限变更历史（共 {total} 条）。
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} mb={2} flexWrap="wrap" useFlexGap>
          <TextField
            size="small"
            label="操作人"
            value={actor}
            onChange={(e) => {
              setActor(e.target.value);
              resetToFirstPage();
            }}
            sx={{ width: 140 }}
          />
          <TextField
            size="small"
            label="事件动作关键词"
            value={action}
            onChange={(e) => {
              setAction(e.target.value);
              resetToFirstPage();
            }}
            sx={{ width: 180 }}
          />
          <FormControl size="small" sx={{ width: 150 }}>
            <InputLabel>资源类型</InputLabel>
            <Select
              value={resourceType}
              label="资源类型"
              onChange={(e) => {
                setResourceType(e.target.value);
                resetToFirstPage();
              }}
            >
              <MenuItem value="">全部</MenuItem>
              <MenuItem value="role">角色</MenuItem>
              <MenuItem value="role_policy">角色权限</MenuItem>
              <MenuItem value="user_role">用户角色</MenuItem>
              <MenuItem value="permission">权限项</MenuItem>
              <MenuItem value="casbin_policy">访问策略</MenuItem>
              <MenuItem value="user">用户与认证</MenuItem>
              <MenuItem value="oauth_client">OAuth 应用</MenuItem>
              <MenuItem value="oauth_provider">第三方登录</MenuItem>
              <MenuItem value="system_setting">系统设置</MenuItem>
              <MenuItem value="temp_role_grant">临时权限</MenuItem>
              <MenuItem value="domain">域</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ width: 110 }}>
            <InputLabel>状态</InputLabel>
            <Select
              value={status}
              label="状态"
              onChange={(e) => {
                setStatus(e.target.value);
                resetToFirstPage();
              }}
            >
              <MenuItem value="">全部</MenuItem>
              <MenuItem value="success">成功</MenuItem>
              <MenuItem value="failed">失败</MenuItem>
            </Select>
          </FormControl>
          <DateTimePicker
            label="开始时间"
            value={startTime}
            onChange={(v) => {
              setStartTime(v);
              resetToFirstPage();
            }}
            slotProps={{ textField: { size: 'small', sx: { width: 205 } } }}
          />
          <DateTimePicker
            label="结束时间"
            value={endTime}
            onChange={(v) => {
              setEndTime(v);
              resetToFirstPage();
            }}
            slotProps={{ textField: { size: 'small', sx: { width: 205 } } }}
          />
          <Button
            variant="outlined"
            onClick={() => {
              setActor('');
              setAction('');
              setResourceType('');
              setStatus('');
              setStartTime(null);
              setEndTime(null);
              resetToFirstPage();
            }}
          >
            重置
          </Button>
        </Stack>

        <Box sx={{ height: 560 }}>
          <DataGrid
            rows={logs}
            columns={columns}
            loading={loading}
            disableRowSelectionOnClick
            paginationMode="server"
            rowCount={total}
            paginationModel={paginationModel}
            onPaginationModelChange={setPaginationModel}
            pageSizeOptions={[10, 20, 50]}
            slots={{ toolbar: GridToolbar }}
          />
        </Box>

        <Drawer anchor="right" open={Boolean(detailLog)} onClose={() => setDetailLog(null)}>
          <Box sx={{ width: { xs: 340, sm: 500 }, p: 3 }}>
            <Typography variant="h6" mb={1}>
              审计事件详情（#{detailLog?.id}）
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={2}>
              {detailLog?.action} · {detailLog?.actor_username || '系统'} · {detailLog?.ip_address || '-'}
            </Typography>
            {detailLog?.error_message && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {detailLog.error_message}
              </Alert>
            )}

            <Typography variant="subtitle2" fontWeight={700} mt={2} mb={0.5}>
              变更前数据
            </Typography>
            <Box
              component="pre"
              sx={{
                p: 1.5,
                borderRadius: 2,
                bgcolor: 'action.hover',
                fontSize: '0.78rem',
                overflowX: 'auto',
              }}
            >
              {detailLog?.before_state ? JSON.stringify(detailLog.before_state, null, 2) : '无（新增或无前置状态）'}
            </Box>

            <Typography variant="subtitle2" fontWeight={700} mt={2.5} mb={0.5}>
              变更后数据
            </Typography>
            <Box
              component="pre"
              sx={{
                p: 1.5,
                borderRadius: 2,
                bgcolor: 'action.hover',
                fontSize: '0.78rem',
                overflowX: 'auto',
              }}
            >
              {detailLog?.after_state ? JSON.stringify(detailLog.after_state, null, 2) : '无（删除或无后置状态）'}
            </Box>
          </Box>
        </Drawer>
      </Box>
    </LocalizationProvider>
  );
};
