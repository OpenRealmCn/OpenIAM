import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Stack,
  Typography,
} from '@mui/material';
import { Computer as SessionIcon, Logout as KickIcon, PersonOff as KickAllIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { UserSession } from '../types/api';

export const SessionsPage: React.FC = () => {
  const { hasCap, currentDomain } = useAuth();
  const canWrite = hasCap('sessions:write');
  const [rows, setRows] = useState<UserSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setRows((await api.sessions.listAll()) || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, currentDomain]);

  const handleKickOne = async (s: UserSession) => {
    if (!window.confirm(`确认强制下线用户 ${s.username || s.user_id} 在「${s.device_name}」上的会话？`)) return;
    try {
      await api.sessions.revoke(s.session_id);
      setSuccess('已踢下线该设备会话');
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleKickUserAll = async (s: UserSession) => {
    if (!window.confirm(`确认将用户 ${s.username || s.user_id} 的全部在线会话下线？`)) return;
    try {
      await api.sessions.revokeUserAll(s.user_id);
      setSuccess(`已下线用户 ${s.username || s.user_id} 的全部设备会话`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<UserSession>[] = [
    {
      field: 'username',
      headerName: '账号',
      width: 140,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.8} alignItems="center">
          <Typography variant="body2" fontWeight={600}>{p.value || `#${p.row.user_id}`}</Typography>
          {p.row.is_current && <Chip size="small" color="success" label="本机" />}
        </Stack>
      ),
    },
    { field: 'device_name', headerName: '设备/终端', width: 170 },
    { field: 'ip_address', headerName: 'IP 地址', width: 140 },
    { field: 'location', headerName: '登录地点', width: 140 },
    {
      field: 'last_active_at',
      headerName: '最近活跃时间',
      width: 170,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '-'),
    },
    {
      field: 'expires_at',
      headerName: '会话过期时间',
      width: 170,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '-'),
    },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions',
            headerName: '操作',
            width: 100,
            getActions: (p: { row: UserSession }) => [
              <GridActionsCellItem key="kick" icon={<KickIcon color="warning" />} label="单会话下线" onClick={() => handleKickOne(p.row)} />,
              <GridActionsCellItem key="kickall" icon={<KickAllIcon color="error" />} label="全部下线" onClick={() => handleKickUserAll(p.row)} />,
            ],
          } as GridColDef<UserSession>,
        ]
      : []),
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <SessionIcon color="primary" />
            <Typography variant="h5">会话与设备管理中心</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            实时监控在线设备、登录 IP 与地理位置，支持单设备精确踢下线及全账号会话强制注销
          </Typography>
        </Box>
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
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

      <Box sx={{ height: 540 }}>
        <DataGrid
          rows={rows}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>
    </Box>
  );
};
