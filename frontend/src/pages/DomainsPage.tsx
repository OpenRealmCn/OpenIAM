import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Delete as DeleteIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { useAuth } from '../context/AuthContext';
import { Domain } from '../types/api';

export const DomainsPage: React.FC = () => {
  const { refreshDomains, hasCap } = useAuth();
  const confirm = useConfirm();
  const [rows, setRows] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [form, setForm] = useState({ code: '', name: '', description: '' });

  const canWrite = hasCap('domains:write');

  const load = async () => {
    setLoading(true);
    try {
      const list = await api.domains.list();
      setRows(list || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const openCreateDialog = () => {
    setDialogError('');
    setForm({ code: '', name: '', description: '' });
    setOpen(true);
  };

  const handleCreate = async () => {
    setDialogError('');
    try {
      await api.domains.create({
        code: form.code.trim(),
        name: form.name.trim(),
        description: form.description.trim(),
      });
      setOpen(false);
      setForm({ code: '', name: '', description: '' });
      await load();
      await refreshDomains();
    } catch (err) {
      setDialogError((err as Error).message);
    }
  };

  const handleDelete = async (row: Domain) => {
    const ok = await confirm({
      title: '确认删除域',
      content: `确定要删除域「${row.name}」（${row.code}）吗？删除后该域下的角色与授权关系将一并失效。`,
      confirmText: '确认删除',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.domains.delete(row.id);
      await load();
      await refreshDomains();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<Domain>[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'code', headerName: '域标识', width: 190 },
    { field: 'name', headerName: '域名称', width: 200 },
    { field: 'description', headerName: '描述', flex: 1, minWidth: 220 },
    {
      field: 'status',
      headerName: '状态',
      width: 110,
      renderCell: (p) => (
        <Chip
          size="small"
          color={p.value === 'active' ? 'success' : 'default'}
          label={p.value === 'active' ? '启用' : '停用'}
        />
      ),
    },
    {
      field: 'created_at',
      headerName: '创建时间',
      width: 170,
      valueFormatter: (v) => dayjs(v as string).format('YYYY-MM-DD HH:mm'),
    },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions' as const,
            headerName: '操作',
            width: 90,
            getActions: (p: { row: Domain }) =>
              p.row.code === 'openiam'
                ? []
                : [
                    <GridActionsCellItem
                      key="del"
                      icon={<DeleteIcon />}
                      label="删除域"
                      onClick={() => void handleDelete(p.row)}
                    />,
                  ],
          },
        ]
      : []),
  ];

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">域管理</Typography>
          <Typography variant="body2" color="text.secondary">
            按业务系统或团队隔离角色、权限点与授权策略。
          </Typography>
        </Box>
        {canWrite && (
          <Button variant="contained" startIcon={<AddIcon />} onClick={openCreateDialog}>
            新建域
          </Button>
        )}
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Box sx={{ height: 520 }}>
        <DataGrid
          rows={rows}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>新建域</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {dialogError && (
              <Alert severity="error" onClose={() => setDialogError('')}>
                {dialogError}
              </Alert>
            )}
            <TextField
              label="域标识（如 billing、cms）"
              size="small"
              required
              value={form.code}
              onChange={(e) => setForm({ ...form, code: e.target.value })}
            />
            <TextField
              label="域名称"
              size="small"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <TextField
              label="描述"
              size="small"
              multiline
              rows={2}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleCreate}>
            创建
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
