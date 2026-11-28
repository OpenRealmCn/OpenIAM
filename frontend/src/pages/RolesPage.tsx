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
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Delete as DeleteIcon, Tune as PermIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { useAuth } from '../context/AuthContext';
import { Permission, Role } from '../types/api';

function isProtectedSuperAdminWildcard(role: Role | null, resource: string, action: string): boolean {
  return role?.code === 'super_admin' && role?.domain_code === 'openiam' && resource === '*' && action === '*';
}

export const RolesPage: React.FC = () => {
  const { currentDomain, domains, adminTier, hasCap } = useAuth();
  const confirm = useConfirm();
  const [roles, setRoles] = useState<Role[]>([]);
  const [allPerms, setAllPerms] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [createError, setCreateError] = useState('');
  const [form, setForm] = useState({ domain_code: currentDomain, code: '', name: '', description: '' });

  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [permError, setPermError] = useState('');
  const [selectedPolicies, setSelectedPolicies] = useState<{ resource: string; action: string }[]>([]);
  const [customRes, setCustomRes] = useState('');
  const [customAct, setCustomAct] = useState('');

  const isPlatformAdmin = adminTier === 'platform_admin';
  const canWrite = hasCap('roles:write');

  const domainOptions = domains.some((d) => d.code === currentDomain)
    ? domains
    : [{ code: currentDomain, name: currentDomain }, ...domains];

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

  const openCreateDialog = () => {
    setCreateError('');
    setForm({ domain_code: currentDomain, code: '', name: '', description: '' });
    setCreateOpen(true);
  };

  const handleCreate = async () => {
    setCreateError('');
    try {
      await api.roles.create({
        domain_code: isPlatformAdmin ? form.domain_code : currentDomain,
        code: form.code.trim(),
        name: form.name.trim(),
        description: form.description.trim(),
      });
      setCreateOpen(false);
      setForm({ domain_code: currentDomain, code: '', name: '', description: '' });
      await loadData();
    } catch (err) {
      setCreateError((err as Error).message);
    }
  };

  const handleDelete = async (role: Role) => {
    if (role.is_system) return;
    const ok = await confirm({
      title: '确认删除角色',
      content: `确定要删除角色「${role.name}」（${role.code}）吗？删除后，已分配该角色的成员将失去由此角色授予的全部权限。`,
      confirmText: '确认删除',
      danger: true,
    });
    if (!ok) return;
    try {
      await api.roles.delete(role.id);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const openPermEditor = (role: Role) => {
    setPermError('');
    setEditingRole(role);
    setSelectedPolicies((role.permissions || []).map((p) => ({ resource: p.resource, action: p.action })));
  };

  const hasPolicy = (res: string, act: string) =>
    selectedPolicies.some((p) => p.resource === res && p.action === act);

  const togglePolicy = (res: string, act: string) => {
    if (hasPolicy(res, act)) {
      if (isProtectedSuperAdminWildcard(editingRole, res, act)) {
        return;
      }
      setSelectedPolicies(selectedPolicies.filter((p) => !(p.resource === res && p.action === act)));
    } else {
      setSelectedPolicies([...selectedPolicies, { resource: res, action: act }]);
    }
  };

  const handleSavePermissions = async () => {
    if (!editingRole) return;
    setPermError('');
    try {
      await api.roles.setPermissions(editingRole.id, selectedPolicies);
      setEditingRole(null);
      await loadData();
    } catch (err) {
      setPermError((err as Error).message);
    }
  };

  const columns: GridColDef<Role>[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'domain_code', headerName: '所属域', width: 120 },
    { field: 'code', headerName: '角色标识', width: 150 },
    { field: 'name', headerName: '角色名称', width: 160 },
    {
      field: 'permissions',
      headerName: '关联策略数',
      width: 170,
      renderCell: (p) => <Chip size="small" label={`${(p.row.permissions || []).length} 条策略`} color="primary" variant="outlined" />,
    },
    { field: 'member_count', headerName: '成员数', width: 100 },
    { field: 'description', headerName: '描述', flex: 1, minWidth: 180 },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions' as const,
            headerName: '操作',
            width: 120,
            getActions: (p: { row: Role }) => [
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
                      onClick={() => void handleDelete(p.row)}
                    />,
                  ]
                : []),
            ],
          },
        ]
      : []),
  ];

  const isEditingSuperAdmin = editingRole?.code === 'super_admin' && editingRole?.domain_code === 'openiam';

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">角色管理（{currentDomain}）</Typography>
          <Typography variant="body2" color="text.secondary">
            管理域内角色及关联权限策略，变更将自动记入审计日志。
          </Typography>
        </Box>
        {canWrite && (
          <Button variant="contained" startIcon={<AddIcon />} onClick={openCreateDialog}>
            新建角色
          </Button>
        )}
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
        <DialogTitle>新建角色</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {createError && (
              <Alert severity="error" onClose={() => setCreateError('')}>
                {createError}
              </Alert>
            )}
            <FormControl size="small" fullWidth disabled={!isPlatformAdmin}>
              <InputLabel>所属域</InputLabel>
              <Select
                label="所属域"
                value={isPlatformAdmin ? form.domain_code : currentDomain}
                onChange={(e) => setForm({ ...form, domain_code: e.target.value })}
              >
                {domainOptions.map((d) => (
                  <MenuItem key={d.code} value={d.code}>
                    {d.name ? `${d.name}（${d.code}）` : d.code}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="角色标识（如 developer）"
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
          配置角色权限：{editingRole?.name}（{editingRole?.domain_code}:{editingRole?.code}）
        </DialogTitle>
        <DialogContent>
          <Stack spacing={1.5} mt={1}>
            {permError && (
              <Alert severity="error" onClose={() => setPermError('')}>
                {permError}
              </Alert>
            )}
            {isEditingSuperAdmin && (
              <Alert severity="info">
                超级管理员在平台域（openiam）中的全局授权规则「* : *」受系统保护，不可移除。
              </Alert>
            )}
            <Typography variant="subtitle2">从域权限点目录勾选：</Typography>
            <Box sx={{ maxHeight: 240, overflowY: 'auto', border: 1, borderColor: 'divider', borderRadius: 2, p: 1.5 }}>
              {allPerms.map((p) => {
                const locked = isProtectedSuperAdminWildcard(editingRole, p.resource, p.action);
                const control = (
                  <FormControlLabel
                    key={p.id}
                    control={
                      <Checkbox
                        checked={hasPolicy(p.resource, p.action)}
                        disabled={locked}
                        onChange={() => togglePolicy(p.resource, p.action)}
                      />
                    }
                    label={`${p.name}（${p.resource} : ${p.action}）`}
                  />
                );
                return locked ? (
                  <Tooltip key={p.id} title="超级管理员的全局授权规则不可删除">
                    <span>{control}</span>
                  </Tooltip>
                ) : (
                  control
                );
              })}
            </Box>

            <Typography variant="subtitle2">追加自定义资源策略（支持 * 或路径通配）：</Typography>
            <Stack direction="row" spacing={1}>
              <TextField
                size="small"
                label="资源（如 orders/*）"
                value={customRes}
                onChange={(e) => setCustomRes(e.target.value)}
                fullWidth
              />
              <TextField
                size="small"
                label="动作（如 read / write / *）"
                value={customAct}
                onChange={(e) => setCustomAct(e.target.value)}
                fullWidth
              />
              <Button
                variant="outlined"
                onClick={() => {
                  const res = customRes.trim();
                  const act = customAct.trim();
                  if (res && act && !hasPolicy(res, act)) {
                    setSelectedPolicies([...selectedPolicies, { resource: res, action: act }]);
                    setCustomRes('');
                    setCustomAct('');
                  }
                }}
              >
                添加
              </Button>
            </Stack>

            <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
              {selectedPolicies.map((sp) => {
                const locked = isProtectedSuperAdminWildcard(editingRole, sp.resource, sp.action);
                const chip = (
                  <Chip
                    key={`${sp.resource}:${sp.action}`}
                    size="small"
                    label={`${sp.resource} : ${sp.action}`}
                    onDelete={locked ? undefined : () => togglePolicy(sp.resource, sp.action)}
                  />
                );
                return locked ? (
                  <Tooltip key={`${sp.resource}:${sp.action}`} title="超级管理员的全局授权规则不可删除">
                    <span>{chip}</span>
                  </Tooltip>
                ) : (
                  chip
                );
              })}
            </Stack>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingRole(null)}>取消</Button>
          <Button variant="contained" onClick={handleSavePermissions}>
            保存
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
