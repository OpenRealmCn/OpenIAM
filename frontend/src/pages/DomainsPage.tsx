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
import { useAuth } from '../context/AuthContext';
import { Domain } from '../types/api';

export const DomainsPage: React.FC = () => {
  const { refreshDomains } = useAuth();
  const [rows, setRows] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ code: '', name: '', description: '' });

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

  const handleCreate = async () => {
    try {
      await api.domains.create(form);
      setOpen(false);
      setForm({ code: '', name: '', description: '' });
      await load();
      await refreshDomains();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (row: Domain) => {
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
    { field: 'code', headerName: '域标识 (Domain Code)', width: 190 },
    { field: 'name', headerName: '域名称', width: 200 },
    { field: 'description', headerName: '描述', flex: 1, minWidth: 220 },
    {
      field: 'status',
      headerName: '状态',
      width: 110,
      renderCell: (p) => <Chip size="small" color={p.value === 'active' ? 'success' : 'default'} label={p.value} />,
    },
    {
      field: 'created_at',
      headerName: '创建时间',
      width: 170,
      valueFormatter: (v) => dayjs(v as string).format('YYYY-MM-DD HH:mm'),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 90,
      getActions: (p) =>
        p.row.code === 'openiam'
          ? []
          : [<GridActionsCellItem key="del" icon={<DeleteIcon />} label="删除" onClick={() => handleDelete(p.row)} />],
    },
  ];

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">OpenRealm 域 / 租户管理</Typography>
          <Typography variant="body2" color="text.secondary">
            每个 OpenRealm 子应用或租户拥有独立的 Casbin 角色与权限策略隔离空间
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>
          新建域
        </Button>
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
        <DialogTitle>新建 OpenRealm 域</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="域标识 (如 billing, cms)"
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
