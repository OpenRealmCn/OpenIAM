import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid2 as Grid,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import {
  AccountTree as TreeIcon,
  Add as AddIcon,
  CheckCircle as CheckIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { SimpleTreeView } from '@mui/x-tree-view/SimpleTreeView';
import { TreeItem } from '@mui/x-tree-view/TreeItem';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Permission, PolicyRule } from '../types/api';

export const PermissionsPage: React.FC = () => {
  const { currentDomain, user } = useAuth();
  const [perms, setPerms] = useState<Permission[]>([]);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ code: '', name: '', resource: '', action: 'read', description: '' });

  // 实时权限仿真校验
  const [checkForm, setCheckForm] = useState({
    user_id: String(user?.id || 1),
    domain: currentDomain,
    resource: 'users',
    action: 'read',
  });
  const [checkResult, setCheckResult] = useState<{ allowed: boolean; roles: string[] } | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [pRes, polRes] = await Promise.all([
        api.permissions.list(currentDomain),
        api.permissions.listPolicies({ domain: currentDomain }),
      ]);
      setPerms(pRes || []);
      setPolicies(polRes || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    loadData();
    setCheckForm((prev) => ({ ...prev, domain: currentDomain }));
  }, [loadData, currentDomain]);

  // 按角色分组构建 MUI X TreeView 数据结构（域 -> 角色 -> Casbin 策略）
  const rolePolicyTree = useMemo(() => {
    const grouped: Record<string, PolicyRule[]> = {};
    for (const rule of policies) {
      if (!grouped[rule.role]) grouped[rule.role] = [];
      grouped[rule.role].push(rule);
    }
    return Object.entries(grouped);
  }, [policies]);

  const handleCreatePerm = async () => {
    try {
      await api.permissions.create({ domain_code: currentDomain, ...form });
      setCreateOpen(false);
      setForm({ code: '', name: '', resource: '', action: 'read', description: '' });
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDeletePerm = async (id: number) => {
    try {
      await api.permissions.delete(id);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRemovePolicy = async (rule: PolicyRule) => {
    try {
      await api.permissions.removePolicy(rule);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleCheck = async () => {
    try {
      const res = await api.permissions.checkPolicy({
        user_id: Number(checkForm.user_id),
        domain: checkForm.domain,
        resource: checkForm.resource,
        action: checkForm.action,
      });
      setCheckResult(res);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const permColumns: GridColDef<Permission>[] = [
    { field: 'code', headerName: '权限编码', width: 160 },
    { field: 'name', headerName: '权限名称', width: 150 },
    { field: 'resource', headerName: '资源 (obj)', width: 130 },
    { field: 'action', headerName: '动作 (act)', width: 95 },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 70,
      getActions: (p) => [
        <GridActionsCellItem key="del" icon={<DeleteIcon />} label="删除" onClick={() => handleDeletePerm(p.row.id)} />,
      ],
    },
  ];

  const policyRows = policies.map((p, idx) => ({ id: `${p.role}-${p.domain}-${p.resource}-${p.action}-${idx}`, ...p }));
  const policyColumns: GridColDef<PolicyRule & { id: string }>[] = [
    { field: 'role', headerName: '角色 (sub)', width: 135 },
    { field: 'domain', headerName: '域 (dom)', width: 105 },
    { field: 'resource', headerName: '资源 (obj)', width: 145 },
    { field: 'action', headerName: '动作 (act)', width: 95 },
    {
      field: 'actions',
      type: 'actions',
      headerName: '移除',
      width: 70,
      getActions: (p) => [
        <GridActionsCellItem key="del" icon={<DeleteIcon />} label="移除策略" onClick={() => handleRemovePolicy(p.row)} />,
      ],
    },
  ];

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2.5}>
        <Box>
          <Typography variant="h5">权限点目录与 Casbin 策略 ({currentDomain})</Typography>
          <Typography variant="body2" color="text.secondary">
            基于 Casbin RBAC with Domains 模型实时校验，并通过 MUI X TreeView & DataGrid 可视化呈现
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          新增权限点
        </Button>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* 权限校验仿真测试 */}
      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Typography variant="subtitle1" fontWeight={600} mb={1.5}>
            Casbin 实时权限仿真校验
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems="center">
            <TextField
              size="small"
              label="用户 ID"
              value={checkForm.user_id}
              onChange={(e) => setCheckForm({ ...checkForm, user_id: e.target.value })}
              sx={{ width: { xs: '100%', md: 120 } }}
            />
            <TextField
              size="small"
              label="域 (dom)"
              value={checkForm.domain}
              onChange={(e) => setCheckForm({ ...checkForm, domain: e.target.value })}
              sx={{ width: { xs: '100%', md: 150 } }}
            />
            <TextField
              size="small"
              label="资源 (obj)"
              value={checkForm.resource}
              onChange={(e) => setCheckForm({ ...checkForm, resource: e.target.value })}
              sx={{ width: { xs: '100%', md: 180 } }}
            />
            <TextField
              size="small"
              label="动作 (act)"
              value={checkForm.action}
              onChange={(e) => setCheckForm({ ...checkForm, action: e.target.value })}
              sx={{ width: { xs: '100%', md: 140 } }}
            />
            <Button variant="contained" startIcon={<CheckIcon />} onClick={handleCheck}>
              执行校验
            </Button>
            {checkResult && (
              <Chip
                color={checkResult.allowed ? 'success' : 'error'}
                label={
                  checkResult.allowed
                    ? `允许放行 (角色: ${checkResult.roles?.join(', ') || 'super_admin'})`
                    : '拒绝访问 (Deny)'
                }
              />
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* MUI X TreeView 多域 RBAC 权限层级树 */}
      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Stack direction="row" spacing={1} alignItems="center" mb={1.5}>
            <TreeIcon color="primary" fontSize="small" />
            <Typography variant="subtitle1" fontWeight={600}>
              域权限拓扑树（MUI X Tree View）
            </Typography>
          </Stack>
          {rolePolicyTree.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              当前域暂无已绑定的 Casbin 策略。
            </Typography>
          ) : (
            <SimpleTreeView defaultExpandedItems={[`domain:${currentDomain}`, ...rolePolicyTree.slice(0, 2).map(([r]) => `role:${r}`)]}>
              <TreeItem itemId={`domain:${currentDomain}`} label={`业务域: ${currentDomain} (${rolePolicyTree.length} 个角色)`}>
                {rolePolicyTree.map(([roleCode, rules]) => (
                  <TreeItem
                    key={roleCode}
                    itemId={`role:${roleCode}`}
                    label={`角色: ${roleCode} (${rules.length} 条策略)`}
                  >
                    {rules.map((rule, i) => (
                      <TreeItem
                        key={`${roleCode}-${i}`}
                        itemId={`rule:${roleCode}:${i}`}
                        label={`${rule.resource}  →  ${rule.action}`}
                      />
                    ))}
                  </TreeItem>
                ))}
              </TreeItem>
            </SimpleTreeView>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, lg: 6 }}>
          <Typography variant="subtitle1" fontWeight={600} mb={1}>
            权限点目录
          </Typography>
          <Box sx={{ height: 440 }}>
            <DataGrid
              rows={perms}
              columns={permColumns}
              loading={loading}
              disableRowSelectionOnClick
              slots={{ toolbar: GridToolbar }}
              slotProps={{ toolbar: { showQuickFilter: true } }}
            />
          </Box>
        </Grid>
        <Grid size={{ xs: 12, lg: 6 }}>
          <Typography variant="subtitle1" fontWeight={600} mb={1}>
            生效中的 Casbin 策略 (casbin_rule)
          </Typography>
          <Box sx={{ height: 440 }}>
            <DataGrid
              rows={policyRows}
              columns={policyColumns}
              loading={loading}
              disableRowSelectionOnClick
              slots={{ toolbar: GridToolbar }}
              slotProps={{ toolbar: { showQuickFilter: true } }}
            />
          </Box>
        </Grid>
      </Grid>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>新增域权限点 ({currentDomain})</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="权限编码 (如 order:read)"
              size="small"
              required
              value={form.code}
              onChange={(e) => setForm({ ...form, code: e.target.value })}
            />
            <TextField
              label="权限名称"
              size="small"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <TextField
              label="资源路径/标识 (如 orders)"
              size="small"
              required
              value={form.resource}
              onChange={(e) => setForm({ ...form, resource: e.target.value })}
            />
            <TextField
              label="动作 (如 read / write / *)"
              size="small"
              required
              value={form.action}
              onChange={(e) => setForm({ ...form, action: e.target.value })}
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
          <Button variant="contained" onClick={handleCreatePerm}>
            创建
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
