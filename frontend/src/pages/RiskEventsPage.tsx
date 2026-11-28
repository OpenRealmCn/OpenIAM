import React, { useCallback, useEffect, useState } from 'react';
import { Alert, Box, Button, Chip, Stack, Typography } from '@mui/material';
import { Shield as RiskIcon } from '@mui/icons-material';
import { DataGrid, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { RiskEvent } from '../types/api';

const RISK_LEVEL_LABELS: Record<string, { label: string; color: 'error' | 'warning' | 'success' }> = {
  high: { label: '高风险', color: 'error' },
  medium: { label: '中风险', color: 'warning' },
  low: { label: '低风险', color: 'success' },
};

const ACTION_LABELS: Record<string, string> = {
  allow: '正常放行',
  notify: '风险提醒',
  challenge_mfa: '二次身份验证',
  block: '已拦截',
};

export const RiskEventsPage: React.FC = () => {
  const { currentDomain } = useAuth();
  const [rows, setRows] = useState<RiskEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setRows((await api.risk.list()) || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData, currentDomain]);

  const columns: GridColDef<RiskEvent>[] = [
    { field: 'username', headerName: '账号', width: 130 },
    {
      field: 'risk_level',
      headerName: '风险等级',
      width: 135,
      renderCell: (p) => {
        const lvl = p.value as string;
        const meta = RISK_LEVEL_LABELS[lvl] || { label: lvl, color: 'success' as const };
        return <Chip size="small" color={meta.color} label={`${meta.label} (${p.row.risk_score}分)`} />;
      },
    },
    { field: 'ip_address', headerName: '来源 IP', width: 140 },
    { field: 'location', headerName: '地点', width: 130 },
    {
      field: 'reasons',
      headerName: '风险命中因子',
      flex: 1,
      minWidth: 240,
      valueGetter: (_, r) => (r.reasons || []).join('；'),
    },
    {
      field: 'action_taken',
      headerName: '处置策略',
      width: 135,
      valueFormatter: (v) => ACTION_LABELS[v as string] || String(v || '-'),
    },
    {
      field: 'created_at',
      headerName: '发生时间',
      width: 170,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '-'),
    },
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <RiskIcon color="primary" />
            <Typography variant="h5">风险自适应认证事件</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            基于 IP 信誉、异地位置、设备指纹变动与非常用时间段的实时登录风险评分记录
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

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

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
