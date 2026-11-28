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
  Delete as DeleteIcon,
  Science as SimIcon,
} from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import { SimpleTreeView } from '@mui/x-tree-view/SimpleTreeView';
import { TreeItem } from '@mui/x-tree-view/TreeItem';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Permission, PolicyRule, SimulationResult } from '../types/api';

export const PermissionsPage: React.FC = () => {
  const { currentDomain, user } = useAuth();
  const [perms, setPerms] = useState<Permission[]>([]);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ code: '', name: '', resource: '', action: 'read', description: '' });

  // 实时权限模拟器与策略变更预演
  const [checkForm, setCheckForm] = useState({
    user_id: String(user?.id || 1),
    domain: currentDomain,
    resource: 'users',
    action: 'read',
  });
  const [draftAddPolicy, setDraftAddPolicy] = useState({ role: '', resource: '', action: '' });
  const [draftAddPolicies, setDraftAddPolicies] = useState<PolicyRule[]>([]);
  const [draftRemovePolicies, setDraftRemovePolicies] = useState<PolicyRule[]>([]);
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);

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

  // 按角色分组构建权限拓扑树（域 -> 角色 -> 访问策略）
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
    setError('');
    try {
      const res = await api.permissions.simulatePolicy({
        user_id: Number(checkForm.user_id),
        domain: checkForm.domain,
        resource: checkForm.resource,
        action: checkForm.action,
        draft: {
          add_policies: draftAddPolicies,
          remove_policies: draftRemovePolicies,
          add_roles: [],
          remove_roles: [],
        },
      });
      setSimResult(res);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleAddDraftPolicy = () => {
    if (!draftAddPolicy.role.trim() || !draftAddPolicy.resource.trim() || !draftAddPolicy.action.trim()) return;
    setDraftAddPolicies((prev) => [
      ...prev,
      {
        role: draftAddPolicy.role.trim(),
        domain: checkForm.domain,
        resource: draftAddPolicy.resource.trim(),
        action: draftAddPolicy.action.trim(),
      },
    ]);
    setDraftAddPolicy({ role: '', resource: '', action: '' });
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
          <Typography variant="h5">权限 ({currentDomain})</Typography>
          <Typography variant="body2" color="text.secondary">
            配置权限项、查看角色授权关系并测试权限
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          新建权限
        </Button>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* 权限模拟器与策略变更预演 */}
      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Stack direction="row" spacing={1} alignItems="center" mb={1.5}>
            <SimIcon color="primary" fontSize="small" />
            <Typography variant="subtitle1" fontWeight={600}>
              权限模拟器与变更预演（沙盒测算，不改动线上策略）
            </Typography>
          </Stack>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems="center" mb={2}>
            <TextField
              size="small"
              label="用户 ID"
              value={checkForm.user_id}
              onChange={(e) => setCheckForm({ ...checkForm, user_id: e.target.value })}
              sx={{ width: { xs: '100%', md: 110 } }}
            />
            <TextField
              size="small"
              label="域"
              value={checkForm.domain}
              onChange={(e) => setCheckForm({ ...checkForm, domain: e.target.value })}
              sx={{ width: { xs: '100%', md: 140 } }}
            />
            <TextField
              size="small"
              label="资源"
              value={checkForm.resource}
              onChange={(e) => setCheckForm({ ...checkForm, resource: e.target.value })}
              sx={{ width: { xs: '100%', md: 160 } }}
            />
            <TextField
              size="small"
              label="动作"
              value={checkForm.action}
              onChange={(e) => setCheckForm({ ...checkForm, action: e.target.value })}
              sx={{ width: { xs: '100%', md: 130 } }}
            />
            <Button variant="contained" startIcon={<SimIcon />} onClick={handleCheck}>
              运行预演
            </Button>
          </Stack>

          {/* 假设策略变更草稿 */}
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.2} alignItems="center" mb={1.5}>
            <TextField
              size="small"
              label="预演追加：角色"
              placeholder="如 viewer"
              value={draftAddPolicy.role}
              onChange={(e) => setDraftAddPolicy({ ...draftAddPolicy, role: e.target.value })}
              sx={{ width: { xs: '100%', md: 140 } }}
            />
            <TextField
              size="small"
              label="资源"
              placeholder="如 orders"
              value={draftAddPolicy.resource}
              onChange={(e) => setDraftAddPolicy({ ...draftAddPolicy, resource: e.target.value })}
              sx={{ width: { xs: '100%', md: 150 } }}
            />
            <TextField
              size="small"
              label="动作"
              placeholder="如 read"
              value={draftAddPolicy.action}
              onChange={(e) => setDraftAddPolicy({ ...draftAddPolicy, action: e.target.value })}
              sx={{ width: { xs: '100%', md: 120 } }}
            />
            <Button size="small" variant="outlined" startIcon={<AddIcon />} onClick={handleAddDraftPolicy}>
              加入假设授权
            </Button>
            {(draftAddPolicies.length > 0 || draftRemovePolicies.length > 0) && (
              <Button
                size="small"
                color="inherit"
                onClick={() => {
                  setDraftAddPolicies([]);
                  setDraftRemovePolicies([]);
                }}
              >
                清空草稿
              </Button>
            )}
          </Stack>

          {(draftAddPolicies.length > 0 || draftRemovePolicies.length > 0) && (
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap mb={1.5}>
              {draftAddPolicies.map((p, idx) => (
                <Chip
                  key={`add-${idx}`}
                  size="small"
                  color="success"
                  variant="outlined"
                  label={`+ ${p.role} -> ${p.resource}:${p.action}`}
                  onDelete={() => setDraftAddPolicies((prev) => prev.filter((_, i) => i !== idx))}
                />
              ))}
              {draftRemovePolicies.map((p, idx) => (
                <Chip
                  key={`rm-${idx}`}
                  size="small"
                  color="error"
                  variant="outlined"
                  label={`- ${p.role} -> ${p.resource}:${p.action}`}
                  onDelete={() => setDraftRemovePolicies((prev) => prev.filter((_, i) => i !== idx))}
                />
              ))}
            </Stack>
          )}

          {simResult && (
            <Alert severity={simResult.effect === 'granted' ? 'success' : simResult.effect === 'revoked' ? 'warning' : 'info'}>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }} flexWrap="wrap">
                <Chip
                  size="small"
                  color={simResult.current ? 'success' : 'error'}
                  label={`当前真实结果：${simResult.current ? '允许' : '拒绝'}`}
                />
                <Typography variant="body2">→</Typography>
                <Chip
                  size="small"
                  color={simResult.simulated ? 'success' : 'error'}
                  label={`预演变更后：${simResult.simulated ? '允许' : '拒绝'}`}
                />
                <Chip
                  size="small"
                  variant="outlined"
                  label={
                    simResult.effect === 'granted'
                      ? '变更影响：新获得该权限'
                      : simResult.effect === 'revoked'
                        ? '变更影响：将失去该权限'
                        : '变更影响：结果保持不变'
                  }
                />
                <Typography variant="caption" color="text.secondary">
                  命中角色：{simResult.roles_after?.join(', ') || '无'}
                </Typography>
              </Stack>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* 多域 RBAC 权限层级树 */}
      <Card sx={{ mb: 2.5 }}>
        <CardContent>
          <Stack direction="row" spacing={1} alignItems="center" mb={1.5}>
            <TreeIcon color="primary" fontSize="small" />
            <Typography variant="subtitle1" fontWeight={600}>
              权限树
            </Typography>
          </Stack>
          {rolePolicyTree.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              当前域暂无已绑定的访问策略。
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
            权限列表
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
            角色授权策略
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
