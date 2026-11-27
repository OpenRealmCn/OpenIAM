import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Delete as DeleteIcon, Tune as PermIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Permission, Role } from '../types/api';

export const RolesPage: React.FC = () => {
  const { currentDomain } = useAuth();
  const [roles, setRoles] = useState<Role[]>([]);
  const [allPerms, setAllPerms] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ code: '', name: '', description: '' });

  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [selectedPolicies, setSelectedPolicies] = useState<{ resource: string; action: string }[]>([]);
  const [customRes, setCustomRes] = useState('');
  const [customAct, setCustomAct] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [rRes, pRes] = await Promise.all([api.roles.list(currentDomain), api.permissions.list(currentDomain)]);
      setRoles(rRes || []);
      setAllPerms(pRes || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreate = async () => {
    try {
      await api.roles.create({ domain_code: currentDomain, ...form });
      setCreateOpen(false);
      setForm({ code: '', name: '', description: '' });
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDelete = async (role: Role) => {
    try {
      await api.roles.delete(role.id);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const openPermEditor = (role: Role) => {
    setEditingRole(role);
    setSelectedPolicies((role.permissions || []).map((p) => ({ resource: p.resource, action: p.action })));
  };

  const hasPolicy = (res: string, act: string) =>
    selectedPolicies.some((p) => p.resource === res && p.action === act);

  const togglePolicy = (res: string, act: string) => {
    if (hasPolicy(res, act)) {
      setSelectedPolicies(selectedPolicies.filter((p) => !(p.resource === res && p.action === act)));
    } else {
      setSelectedPolicies([...selectedPolicies, { resource: res, action: act }]);
    }
  };

  const handleSavePermissions = async () => {
    if (!editingRole) return;
    try {
      await api.roles.setPermissions(editingRole.id, selectedPolicies);
      setEditingRole(null);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<Role>[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'domain_code', headerName: '所属域', width: 120 },
    { field: 'code', headerName: '角色标识', width: 150 },
    { field: 'name', headerName: '角色名称', width: 160 },
    {
      field: 'permissions',
      headerName: '关联 Casbin 策略数',
      width: 170,
      renderCell: (p) => <Chip size="small" label={`${(p.row.permissions || []).length} 条策略`} color="primary" variant="outlined" />,
    },
    { field: 'member_count', headerName: '成员数', width: 100 },
    { field: 'description', headerName: '描述', flex: 1, minWidth: 180 },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 120,
      getActions: (p) => [
        <GridActionsCellItem
          key="perm"
          icon={<PermIcon />}
          label="配置权限策略"
          onClick={() => openPermEditor(p.row)}
        />,
        ...(!p.row.is_system
          ? [
              <GridActionsCellItem
                key="del"
                icon={<DeleteIcon />}
                label="删除角色"
                onClick={() => handleDelete(p.row)}
              />,
            ]
          : []),
      ],
    },
  ];

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">角色管理 ({currentDomain})</Typography>
          <Typography variant="body2" color="text.secondary">
            管理域内角色并配置 Casbin 权限策略，每次权限变更均会生成前后状态审计快照
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          新建角色
        </Button>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Box sx={{ height: 540 }}>
        <DataGrid
          rows={roles}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>在域 [{currentDomain}] 新建角色</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="角色标识 (如 developer)"
              size="small"
              required
              value={form.code}
              onChange={(e) => setForm({ ...form, code: e.target.value })}
            />
            <TextField
              label="角色名称"
              size="small"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <TextField
              label="描述"
              size="small"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleCreate}>
            创建
          </Button>
        </DialogActions>
      </Dialog>

      {/* 配置角色权限矩阵弹窗 */}
      <Dialog open={Boolean(editingRole)} onClose={() => setEditingRole(null)} maxWidth="sm" fullWidth>
        <DialogTitle>
          配置角色权限 — {editingRole?.name} ({editingRole?.domain_code}:{editingRole?.code})
        </DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} mt={1}>
            <Typography variant="subtitle2">从域权限点目录勾选：</Typography>
            <Box sx={{ maxHeight: 240, overflowY: 'auto', border: 1, borderColor: 'divider', borderRadius: 2, p: 1.5 }}>
              {allPerms.map((p) => (
                <FormControlLabel
                  key={p.id}
                  control={
                    <Checkbox
                      checked={hasPolicy(p.resource, p.action)}
                      onChange={() => togglePolicy(p.resource, p.action)}
                    />
                  }
                  label={`${p.name} — [${p.resource} : ${p.action}]`}
                />
              ))}
            </Box>

            <Typography variant="subtitle2">或追加自定义资源策略（支持 * 或路径通配）：</Typography>
            <Stack direction="row" spacing={1}>
              <TextField
                size="small"
                label="资源 (如 orders/*)"
                value={customRes}
                onChange={(e) => setCustomRes(e.target.value)}
                fullWidth
              />
              <TextField
                size="small"
                label="动作 (如 read / write / *)"
                value={customAct}
                onChange={(e) => setCustomAct(e.target.value)}
                fullWidth
              />
              <Button
                variant="outlined"
                onClick={() => {
                  if (customRes && customAct && !hasPolicy(customRes, customAct)) {
                    setSelectedPolicies([...selectedPolicies, { resource: customRes, action: customAct }]);
                    setCustomRes('');
                    setCustomAct('');
                  }
                }}
              >
                添加
              </Button>
            </Stack>

            <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
              {selectedPolicies.map((sp) => (
                <Chip
                  key={`${sp.resource}:${sp.action}`}
                  size="small"
                  label={`${sp.resource} : ${sp.action}`}
                  onDelete={() => togglePolicy(sp.resource, sp.action)}
                />
              ))}
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingRole(null)}>取消</Button>
          <Button variant="contained" onClick={handleSavePermissions}>
            保存策略并记录审计
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
