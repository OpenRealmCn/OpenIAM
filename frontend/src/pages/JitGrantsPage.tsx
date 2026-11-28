import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Block as RevokeIcon, MoreTime as JitIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { Role, TempRoleGrant, User } from '../types/api';

const STATUS_MAP: Record<string, { label: string; color: 'success' | 'warning' | 'default' | 'error' }> = {
  active: { label: '生效中', color: 'success' },
  pending: { label: '待生效', color: 'warning' },
  expired: { label: '已到期回收', color: 'default' },
  revoked: { label: '已撤销', color: 'error' },
};

export const JitGrantsPage: React.FC = () => {
  const { currentDomain, hasCap } = useAuth();
  const canWrite = hasCap('jit:write');
  const [grants, setGrants] = useState<TempRoleGrant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [open, setOpen] = useState(false);
  const [userId, setUserId] = useState<number>(0);
  const [roleCode, setRoleCode] = useState('');
  const [ttlMinutes, setTtlMinutes] = useState(120);
  const [startsAtLocal, setStartsAtLocal] = useState('');
  const [reason, setReason] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [gList, uRes, rList] = await Promise.all([
        api.jit.list({ domain: currentDomain }),
        api.users.list({ page: 1, page_size: 100 }).catch(() => ({ items: [] })),
        api.roles.list(currentDomain).catch(() => []),
      ]);
      setGrants(gList || []);
      setUsers(uRes?.items || []);
      setRoles(rList || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleCreate = async () => {
    setError('');
    setSuccess('');
    if (!userId || !roleCode) {
      setError('请选择目标用户和临时角色');
      return;
    }
    try {
      const payload: {
        user_id: number;
        domain_code: string;
        role_code: string;
        reason: string;
        ttl_minutes: number;
        starts_at?: string;
      } = {
        user_id: userId,
        domain_code: currentDomain,
        role_code: roleCode,
        reason: reason.trim(),
        ttl_minutes: Number(ttlMinutes) || 120,
      };
      if (startsAtLocal) {
        payload.starts_at = new Date(startsAtLocal).toISOString();
      }
      await api.jit.create(payload);
      setOpen(false);
      setReason('');
      setStartsAtLocal('');
      setSuccess('已创建临时权限授权，到期后将由后台任务自动回收');
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRevoke = async (row: TempRoleGrant) => {
    if (!window.confirm(`确认提前撤销用户 ${row.username || row.user_id} 的临时角色「${row.role_code}」？`)) return;
    try {
      await api.jit.revoke(row.id);
      setSuccess('已提前撤销该临时权限');
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<TempRoleGrant>[] = [
    { field: 'username', headerName: '用户', width: 130, valueGetter: (_, r) => r.username || `#${r.user_id}` },
    { field: 'domain_code', headerName: '业务域', width: 110 },
    { field: 'role_code', headerName: '临时角色', width: 130 },
    {
      field: 'status',
      headerName: '状态',
      width: 120,
      renderCell: (p) => {
        const meta = STATUS_MAP[p.value as string] || { label: p.value, color: 'default' as const };
        return <Chip size="small" color={meta.color} label={meta.label} />;
      },
    },
    { field: 'reason', headerName: '授权原因', flex: 1, minWidth: 160 },
    {
      field: 'starts_at',
      headerName: '生效时间',
      width: 155,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '-'),
    },
    {
      field: 'expires_at',
      headerName: '到期自动回收',
      width: 155,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '-'),
    },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions',
            headerName: '撤销',
            width: 75,
            getActions: (p: { row: TempRoleGrant }) =>
              p.row.status === 'active' || p.row.status === 'pending'
                ? [<GridActionsCellItem key="rev" icon={<RevokeIcon color="error" />} label="提前撤销" onClick={() => handleRevoke(p.row)} />]
                : [],
          } as GridColDef<TempRoleGrant>,
        ]
      : []),
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <JitIcon color="primary" />
            <Typography variant="h5">临时权限（JIT）</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            为应急运维或临时协作授予限时角色，支持预约生效并由定时调度器到期自动回收
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
          {canWrite && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
              授予临时权限
            </Button>
          )}
        </Stack>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

      <Box sx={{ height: 520 }}>
        <DataGrid
          rows={grants}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>授予临时角色（域：{currentDomain}）</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <FormControl size="small" fullWidth>
              <InputLabel>目标用户</InputLabel>
              <Select label="目标用户" value={userId || ''} onChange={(e) => setUserId(Number(e.target.value))}>
                {users.map((u) => (
                  <MenuItem key={u.id} value={u.id}>
                    {u.username} ({u.display_name || u.email})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl size="small" fullWidth>
              <InputLabel>临时角色</InputLabel>
              <Select label="临时角色" value={roleCode} onChange={(e) => setRoleCode(e.target.value)}>
                {roles.map((r) => (
                  <MenuItem key={r.id} value={r.code}>
                    {r.name} ({r.code})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              label="预约生效时间（留空则立即生效）"
              type="datetime-local"
              size="small"
              fullWidth
              InputLabelProps={{ shrink: true }}
              value={startsAtLocal}
              onChange={(e) => setStartsAtLocal(e.target.value)}
            />

            <TextField
              label="有效时长（分钟）"
              type="number"
              size="small"
              fullWidth
              value={ttlMinutes}
              onChange={(e) => setTtlMinutes(Number(e.target.value))}
            />

            <TextField
              label="授权理由（写入审计日志）"
              size="small"
              fullWidth
              multiline
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleCreate}>确认授权</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
