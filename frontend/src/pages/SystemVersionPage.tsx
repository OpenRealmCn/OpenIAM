import React, { useEffect, useState } from 'react';
import { Alert, Box, Card, CardContent, Chip, Grid2 as Grid, Stack, Typography } from '@mui/material';
import { DataGrid, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { VersionHistoryItem, VersionStatus } from '../types/api';

export const SystemVersionPage: React.FC = () => {
  const [status, setStatus] = useState<VersionStatus | null>(null);
  const [history, setHistory] = useState<VersionHistoryItem[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api.system
      .version()
      .then((res) => {
        setStatus(res.status);
        setHistory(res.history || []);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  const columns: GridColDef<VersionHistoryItem>[] = [
    { field: 'id', headerName: '编号', width: 80 },
    { field: 'app_version', headerName: '系统版本', width: 120 },
    {
      field: 'schema_version',
      headerName: '数据库结构版本',
      width: 140,
      valueFormatter: (v) => `v${v}`,
    },
    { field: 'action', headerName: '操作类型', width: 150 },
    {
      field: 'status',
      headerName: '状态',
      width: 110,
      renderCell: (p) => (
        <Chip
          size="small"
          color={p.value === 'success' ? 'success' : 'warning'}
          label={p.value === 'success' ? '成功' : '异常'}
        />
      ),
    },
    { field: 'details', headerName: '详情', flex: 1, minWidth: 220 },
    {
      field: 'created_at',
      headerName: '执行时间',
      width: 180,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm:ss') : '—'),
    },
  ];

  return (
    <Box>
      <Typography variant="h5" mb={0.5}>
        版本信息
      </Typography>
      <Typography variant="body2" color="text.secondary" mb={3}>
        查看当前系统版本、数据库结构状态及升级记录。
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {status && (
        <Grid container spacing={2} mb={3}>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card>
              <CardContent>
                <Typography variant="caption" color="text.secondary">
                  系统版本
                </Typography>
                <Typography variant="h5" mt={0.5}>
                  v{status.app_version}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card>
              <CardContent>
                <Typography variant="caption" color="text.secondary">
                  当前数据库版本
                </Typography>
                <Typography variant="h5" mt={0.5}>
                  v{status.current_schema_version}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card>
              <CardContent>
                <Typography variant="caption" color="text.secondary">
                  目标数据库版本
                </Typography>
                <Typography variant="h5" mt={0.5}>
                  v{status.expected_schema_version}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <Card>
              <CardContent>
                <Typography variant="caption" color="text.secondary">
                  版本校验状态
                </Typography>
                <Stack direction="row" spacing={1} mt={1}>
                  <Chip
                    size="small"
                    color={status.up_to_date ? 'success' : 'warning'}
                    label={status.up_to_date ? '版本一致' : '存在差异'}
                  />
                  {status.dirty && <Chip size="small" color="error" label="升级异常" />}
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Box sx={{ height: 460 }}>
        <DataGrid
          rows={history}
          columns={columns}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
        />
      </Box>
    </Box>
  );
};
