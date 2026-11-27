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
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import dayjs, { Dayjs } from 'dayjs';
import { api } from '../api/client';
import { AuditLog } from '../types/api';

export const AuditLogsPage: React.FC = () => {
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
  const [detailLog, setDetailLog] = useState<AuditLog | null>(null);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.audit.list({
        page: 1,
        page_size: 100,
        actor: actor || undefined,
        action: action || undefined,
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
  }, [actor, action, resourceType, status, startTime, endTime]);

  useEffect(() => {
    loadLogs();
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
    { field: 'resource_type', headerName: '资源类型', width: 120 },
    { field: 'resource_id', headerName: '资源标识', width: 160 },
    { field: 'ip_address', headerName: '来源 IP', width: 130 },
    {
      field: 'status',
      headerName: '状态',
      width: 90,
      renderCell: (p) => (
        <Chip size="small" color={p.value === 'success' ? 'success' : 'error'} label={p.value} />
      ),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '快照',
      width: 75,
      getActions: (p) => [
        <GridActionsCellItem key="view" icon={<DetailIcon />} label="查看变更快照" onClick={() => setDetailLog(p.row)} />,
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
          查看登录记录与用户、角色、权限变更历史（共 {total} 条）
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} mb={2} flexWrap="wrap" useFlexGap>
          <TextField
            size="small"
            label="操作人"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            sx={{ width: 140 }}
          />
          <TextField
            size="small"
            label="动作 (如 rbac. / auth.)"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            sx={{ width: 180 }}
          />
          <FormControl size="small" sx={{ width: 150 }}>
            <InputLabel>资源类型</InputLabel>
            <Select value={resourceType} label="资源类型" onChange={(e) => setResourceType(e.target.value)}>
              <MenuItem value="">全部</MenuItem>
              <MenuItem value="role">role (角色)</MenuItem>
              <MenuItem value="role_policy">role_policy (角色权限)</MenuItem>
              <MenuItem value="user_role">user_role (用户角色)</MenuItem>
              <MenuItem value="permission">permission (权限点)</MenuItem>
              <MenuItem value="casbin_policy">casbin_policy (策略)</MenuItem>
              <MenuItem value="user">user (用户/认证)</MenuItem>
              <MenuItem value="oauth_client">oauth_client (OAuth 应用)</MenuItem>
              <MenuItem value="oauth_provider">oauth_provider (联合登录)</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ width: 110 }}>
            <InputLabel>状态</InputLabel>
            <Select value={status} label="状态" onChange={(e) => setStatus(e.target.value)}>
              <MenuItem value="">全部</MenuItem>
              <MenuItem value="success">success</MenuItem>
              <MenuItem value="failed">failed</MenuItem>
            </Select>
          </FormControl>
          <DateTimePicker
            label="开始时间"
            value={startTime}
            onChange={setStartTime}
            slotProps={{ textField: { size: 'small', sx: { width: 205 } } }}
          />
          <DateTimePicker
            label="结束时间"
            value={endTime}
            onChange={setEndTime}
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
            slots={{ toolbar: GridToolbar }}
          />
        </Box>

        <Drawer anchor="right" open={Boolean(detailLog)} onClose={() => setDetailLog(null)}>
          <Box sx={{ width: { xs: 340, sm: 500 }, p: 3 }}>
            <Typography variant="h6" mb={1}>
              审计事件快照 #{detailLog?.id}
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={2}>
              {detailLog?.action} · {detailLog?.actor_username || 'system'} @ {detailLog?.ip_address}
            </Typography>
            {detailLog?.error_message && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {detailLog.error_message}
              </Alert>
            )}

            <Typography variant="subtitle2" fontWeight={700} mt={2} mb={0.5}>
              变更前状态 (Before State)
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
              {detailLog?.before_state ? JSON.stringify(detailLog.before_state, null, 2) : '无 (新增或无前置状态)'}
            </Box>

            <Typography variant="subtitle2" fontWeight={700} mt={2.5} mb={0.5}>
              变更后状态 (After State)
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
              {detailLog?.after_state ? JSON.stringify(detailLog.after_state, null, 2) : '无 (删除或无后置状态)'}
            </Box>
          </Box>
        </Drawer>
      </Box>
    </LocalizationProvider>
  );
};
