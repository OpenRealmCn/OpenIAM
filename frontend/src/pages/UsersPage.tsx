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
  Typography,
} from '@mui/material';
import { Add as AddIcon, Edit as EditIcon, Key as KeyIcon, Security as RoleIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Role, User } from '../types/api';

export const UsersPage: React.FC = () => {
  const { domains, currentDomain } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [error, setError] = useState('');

  // 新建用户弹窗
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ username: '', email: '', phone: '', display_name: '', password: '', role_code: 'viewer' });

  // 编辑用户弹窗
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editForm, setEditForm] = useState({ display_name: '', email: '', phone: '', avatar_url: '', status: 'active' });

  // 分配角色弹窗
  const [roleDialogUser, setRoleDialogUser] = useState<User | null>(null);
  const [roleDomain, setRoleDomain] = useState(currentDomain);
  const [domainRoles, setDomainRoles] = useState<Role[]>([]);
  const [selectedRoleCodes, setSelectedRoleCodes] = useState<string[]>([]);

  // 重置密码弹窗
  const [pwdUser, setPwdUser] = useState<User | null>(null);
  const [newPwd, setNewPwd] = useState('');

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.users.list({ page: 1, page_size: 100, keyword: keyword || undefined });
      setUsers(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [keyword]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const openRoleDialog = async (user: User) => {
    setRoleDialogUser(user);
    setRoleDomain(currentDomain);
    setSelectedRoleCodes(user.roles?.[currentDomain] || []);
    try {
      const rList = await api.roles.list(currentDomain);
      setDomainRoles(rList || []);
    } catch {
      setDomainRoles([]);
    }
  };

  const handleRoleDomainChange = async (dom: string) => {
    setRoleDomain(dom);
    setSelectedRoleCodes(roleDialogUser?.roles?.[dom] || []);
    try {
      const rList = await api.roles.list(dom);
      setDomainRoles(rList || []);
    } catch {
      setDomainRoles([]);
    }
  };

  const handleSaveRoles = async () => {
    if (!roleDialogUser) return;
    try {
      await api.users.assignRoles(roleDialogUser.id, {
        domain_code: roleDomain,
        role_codes: selectedRoleCodes,
        replace: true,
      });
      setRoleDialogUser(null);
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const openEditUserDialog = (u: User) => {
    setEditUser(u);
    setEditForm({
      display_name: u.display_name || '',
      email: u.email || '',
      phone: u.phone || '',
      avatar_url: u.avatar_url || '',
      status: u.status || 'active',
    });
  };

  const handleSaveEditUser = async () => {
    if (!editUser) return;
    try {
      await api.users.update(editUser.id, {
        display_name: editForm.display_name.trim(),
        email: editForm.email.trim(),
        phone: editForm.phone.trim(),
        avatar_url: editForm.avatar_url.trim(),
        status: editForm.status,
      });
      setEditUser(null);
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleCreateUser = async () => {
    try {
      await api.users.create({
        username: form.username,
        email: form.email.trim(),
        phone: form.phone.trim(),
        display_name: form.display_name,
        password: form.password,
        domain_code: currentDomain,
        role_codes: form.role_code ? [form.role_code] : [],
      });
      setCreateOpen(false);
      setForm({ username: '', email: '', phone: '', display_name: '', password: '', role_code: 'viewer' });
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleToggleStatus = async (user: User) => {
    try {
      const nextStatus = user.status === 'active' ? 'disabled' : 'active';
      await api.users.update(user.id, { status: nextStatus });
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleResetPassword = async () => {
    if (!pwdUser || !newPwd) return;
    try {
      await api.users.resetPassword(pwdUser.id, newPwd);
      setPwdUser(null);
      setNewPwd('');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<User>[] = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'username', headerName: '用户名', width: 140 },
    { field: 'display_name', headerName: '显示名称', width: 140 },
    { field: 'email', headerName: '邮箱', width: 200, valueFormatter: (v) => (v ? String(v) : '-') },
    { field: 'phone', headerName: '手机号', width: 140, valueFormatter: (v) => (v ? String(v) : '-') },
    {
      field: 'roles',
      headerName: '域角色授权',
      flex: 1,
      minWidth: 220,
      sortable: false,
      renderCell: (params) => {
        const entries = Object.entries(params.row.roles || {});
        if (entries.length === 0) return <Typography variant="caption" color="text.secondary">无角色</Typography>;
        return (
          <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" sx={{ py: 0.5 }}>
            {entries.map(([dom, rCodes]) =>
              rCodes.map((rc) => <Chip key={`${dom}-${rc}`} size="small" label={`${dom}:${rc}`} variant="outlined" />),
            )}
          </Stack>
        );
      },
    },
    {
      field: 'status',
      headerName: '状态',
      width: 100,
      renderCell: (params) => (
        <Chip
          size="small"
          color={params.value === 'active' ? 'success' : 'default'}
          label={params.value === 'active' ? '正常' : '已禁用'}
        />
      ),
    },
    {
      field: 'last_login_at',
      headerName: '最近登录',
      width: 165,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '从未登录'),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: '操作',
      width: 175,
      getActions: (params) => [
        <GridActionsCellItem
          key="edit"
          icon={<EditIcon />}
          label="编辑用户"
          onClick={() => openEditUserDialog(params.row)}
          showInMenu={false}
        />,
        <GridActionsCellItem
          key="roles"
          icon={<RoleIcon />}
          label="分配域角色"
          onClick={() => openRoleDialog(params.row)}
          showInMenu={false}
        />,
        <GridActionsCellItem
          key="pwd"
          icon={<KeyIcon />}
          label="重置密码"
          onClick={() => setPwdUser(params.row)}
          showInMenu={false}
        />,
        <GridActionsCellItem
          key="toggle"
          label={params.row.status === 'active' ? '禁用账号' : '启用账号'}
          onClick={() => handleToggleStatus(params.row)}
          showInMenu
        />,
      ],
    },
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems="center" mb={2.5} spacing={2}>
        <Box>
          <Typography variant="h5">用户</Typography>
          <Typography variant="body2" color="text.secondary">
            共 {total} 位用户，支持按业务域分配角色
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.5}>
          <TextField
            size="small"
            placeholder="搜索用户名 / 邮箱"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
          />
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
            新建用户
          </Button>
        </Stack>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Box sx={{ height: 580 }}>
        <DataGrid
          rows={users}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
          pageSizeOptions={[10, 25, 50]}
          initialState={{ pagination: { paginationModel: { pageSize: 25 } } }}
        />
      </Box>

      {/* 新建用户弹窗 */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>新建平台用户</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField
              label="用户名"
              size="small"
              required
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
            />
            <TextField
              label="邮箱（选填）"
              size="small"
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
            <TextField
              label="手机号（选填）"
              size="small"
              value={form.phone}
              placeholder="例如：+8613800138000"
              onChange={(e) => setForm({ ...form, phone: e.target.value })}
            />
            <TextField
              label="显示名称"
              size="small"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            />
            <TextField
              label="初始密码"
              size="small"
              type="password"
              required
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
            <TextField
              label={`在域 [${currentDomain}] 授予初始角色`}
              size="small"
              value={form.role_code}
              onChange={(e) => setForm({ ...form, role_code: e.target.value })}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>取消</Button>
          <Button variant="contained" onClick={handleCreateUser}>
            创建
          </Button>
        </DialogActions>
      </Dialog>

      {/* 编辑用户弹窗 */}
      <Dialog open={Boolean(editUser)} onClose={() => setEditUser(null)} maxWidth="xs" fullWidth>
        <DialogTitle>编辑用户 — {editUser?.username}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField label="用户名" size="small" value={editUser?.username || ''} disabled />
            <TextField
              label="显示名称"
              size="small"
              value={editForm.display_name}
              onChange={(e) => setEditForm({ ...editForm, display_name: e.target.value })}
            />
            <TextField
              label="邮箱"
              type="email"
              size="small"
              value={editForm.email}
              onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
            />
            <TextField
              label="手机号"
              size="small"
              placeholder="例如：+8613800138000"
              value={editForm.phone}
              onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })}
            />
            <TextField
              label="头像地址"
              size="small"
              value={editForm.avatar_url}
              onChange={(e) => setEditForm({ ...editForm, avatar_url: e.target.value })}
            />
            <FormControl size="small" fullWidth>
              <InputLabel>账号状态</InputLabel>
              <Select
                label="账号状态"
                value={editForm.status}
                onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
              >
                <MenuItem value="active">正常</MenuItem>
                <MenuItem value="disabled">已禁用</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditUser(null)}>取消</Button>
          <Button variant="contained" onClick={handleSaveEditUser}>
            保存
          </Button>
        </DialogActions>
      </Dialog>

      {/* 分配域角色弹窗 */}
      <Dialog open={Boolean(roleDialogUser)} onClose={() => setRoleDialogUser(null)} maxWidth="sm" fullWidth>
        <DialogTitle>分配域角色 — {roleDialogUser?.username}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <FormControl size="small" fullWidth>
              <InputLabel>选择目标域</InputLabel>
              <Select value={roleDomain} label="选择目标域" onChange={(e) => handleRoleDomainChange(e.target.value)}>
                {domains.map((d) => (
                  <MenuItem key={d.code} value={d.code}>
                    {d.code} ({d.name})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Typography variant="subtitle2">选择要授予的角色：</Typography>
            {domainRoles.length === 0 ? (
              <Alert severity="info">该域下暂无自定义角色，可前往“角色管理”创建。</Alert>
            ) : (
              <Stack>
                {domainRoles.map((r) => (
                  <FormControlLabel
                    key={r.code}
                    control={
                      <Checkbox
                        checked={selectedRoleCodes.includes(r.code)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedRoleCodes([...selectedRoleCodes, r.code]);
                          } else {
                            setSelectedRoleCodes(selectedRoleCodes.filter((c) => c !== r.code));
                          }
                        }}
                      />
                    }
                    label={`${r.name} (${r.code})`}
                  />
                ))}
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRoleDialogUser(null)}>取消</Button>
          <Button variant="contained" onClick={handleSaveRoles}>
            保存
          </Button>
        </DialogActions>
      </Dialog>

      {/* 重置密码弹窗 */}
      <Dialog open={Boolean(pwdUser)} onClose={() => setPwdUser(null)} maxWidth="xs" fullWidth>
        <DialogTitle>重置密码 — {pwdUser?.username}</DialogTitle>
        <DialogContent>
          <TextField
            label="新密码（8 ~ 72 位）"
            type="password"
            size="small"
            fullWidth
            sx={{ mt: 1 }}
            value={newPwd}
            onChange={(e) => setNewPwd(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPwdUser(null)}>取消</Button>
          <Button variant="contained" onClick={handleResetPassword}>
            确认重置
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
