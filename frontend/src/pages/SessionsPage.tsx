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
import { useConfirm } from '../components/ConfirmDialog';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { UserSession } from '../types/api';

export const SessionsPage: React.FC = () => {
  const { hasCap, currentDomain, sessionId, user } = useAuth();
  const confirm = useConfirm();
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

  const isOwnCurrentSession = (s: UserSession): boolean =>
    Boolean(s.is_current) || (Boolean(sessionId) && s.session_id === sessionId);

  const handleRevokeOne = async (s: UserSession) => {
    const isSelf = isOwnCurrentSession(s);
    const targetName = s.username || `#${s.user_id}`;
    const ok = await confirm({
      title: isSelf ? '下线当前会话' : '下线单个会话',
      content: isSelf
        ? '这是你当前正在使用的会话，下线后需要重新登录。确认继续下线吗？'
        : `确认强制下线用户「${targetName}」在「${s.device_name || '未知设备'}」上的会话？`,
      confirmText: '确认下线',
      danger: true,
    });
    if (!ok) return;

    setError('');
    setSuccess('');
    try {
      await api.sessions.revoke(s.session_id);
      setSuccess('已将该设备会话下线。');
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRevokeUserAll = async (s: UserSession) => {
    const affectsSelf = isOwnCurrentSession(s) || (Boolean(user?.id) && s.user_id === user?.id);
    const targetName = s.username || `#${s.user_id}`;
    const ok = await confirm({
      title: affectsSelf ? '下线本人全部会话' : '下线用户全部会话',
      content: affectsSelf
        ? '这是你当前正在使用的会话所属账号，全部下线后需要重新登录。确认将全部在线会话下线吗？'
        : `确认将用户「${targetName}」的全部在线会话下线？下线后该用户在所有设备上均需重新登录。`,
      confirmText: '全部下线',
      danger: true,
    });
    if (!ok) return;

    setError('');
    setSuccess('');
    try {
      await api.sessions.revokeUserAll(s.user_id);
      setSuccess(`已下线用户「${targetName}」的全部设备会话。`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<UserSession>[] = [
    {
      field: 'username',
      headerName: '账号',
      width: 160,
      renderCell: (p) => (
        <Stack direction="row" spacing={0.8} alignItems="center">
          <Typography variant="body2" fontWeight={600}>
            {p.value || `#${p.row.user_id}`}
          </Typography>
          {isOwnCurrentSession(p.row) && <Chip size="small" color="success" label="当前会话" />}
        </Stack>
      ),
    },
    { field: 'device_name', headerName: '设备 / 终端', width: 170 },
    { field: 'ip_address', headerName: 'IP 地址', width: 140 },
    { field: 'location', headerName: '登录地点', width: 140 },
    {
      field: 'last_active_at',
      headerName: '最近活跃时间',
      width: 170,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '—'),
    },
    {
      field: 'expires_at',
      headerName: '会话过期时间',
      width: 170,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '—'),
    },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions',
            headerName: '操作',
            width: 100,
            getActions: (p: { row: UserSession }) => [
              <GridActionsCellItem
                key="kick"
                icon={<KickIcon color="warning" />}
                label="下线该会话"
                onClick={() => void handleRevokeOne(p.row)}
              />,
              <GridActionsCellItem
                key="kickall"
                icon={<KickAllIcon color="error" />}
                label="下线全部会话"
                onClick={() => void handleRevokeUserAll(p.row)}
              />,
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
            <Typography variant="h5">会话管理</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            查看在线设备、来源 IP 与登录地点，支持将单个会话或账号全部会话强制下线。
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
