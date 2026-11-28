import React, { useCallback, useEffect, useMemo, useState } from 'react';
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
  FormHelperText,
  InputLabel,
  MenuItem,
  Select,
  Snackbar,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import {
  Add as AddIcon,
  DeleteOutline as DeleteIcon,
  Edit as EditIcon,
  Key as KeyIcon,
  LockOpen as UnlockIcon,
  PhonelinkErase as ResetMfaIcon,
  Security as RoleIcon,
} from '@mui/icons-material';
import {
  DataGrid,
  GridActionsCellItem,
  GridColDef,
  GridPaginationModel,
  GridToolbar,
} from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
import { Role, User } from '../types/api';
import { passwordHint, policyFromSite, validatePassword } from '../utils/password';

export const UsersPage: React.FC = () => {
  const { user: currentUser, domains, currentDomain, hasCap } = useAuth();
  const { siteInfo } = useSite();
  const confirm = useConfirm();

  const canWriteUsers = hasCap('users:write');
  const canAssignRoles = canWriteUsers && hasCap('roles:write');
  const passwordPolicy = useMemo(() => policyFromSite(siteInfo), [siteInfo]);
  const pwdHelperText = useMemo(() => passwordHint(passwordPolicy), [passwordPolicy]);

  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [paginationModel, setPaginationModel] = useState<GridPaginationModel>({
    page: 0,
    pageSize: 20,
  });
  const [error, setError] = useState('');
  const [toast, setToast] = useState('');

  // 新建用户弹窗
  const [createOpen, setCreateOpen] = useState(false);
  const [createRoles, setCreateRoles] = useState<Role[]>([]);
  const [createRolesLoading, setCreateRolesLoading] = useState(false);
  const [createError, setCreateError] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [form, setForm] = useState({
    username: '',
    email: '',
    phone: '',
    display_name: '',
    password: '',
    role_code: '',
  });

  // 编辑用户弹窗
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editForm, setEditForm] = useState({
    display_name: '',
    email: '',
    phone: '',
    avatar_url: '',
    status: 'active',
  });
  const [editError, setEditError] = useState('');
  const [editSubmitting, setEditSubmitting] = useState(false);

  // 分配角色弹窗
  const [roleDialogUser, setRoleDialogUser] = useState<User | null>(null);
  const [roleDomain, setRoleDomain] = useState(currentDomain);
  const [domainRoles, setDomainRoles] = useState<Role[]>([]);
  const [selectedRoleCodes, setSelectedRoleCodes] = useState<string[]>([]);
  const [roleError, setRoleError] = useState('');
  const [roleSubmitting, setRoleSubmitting] = useState(false);

  // 重置密码弹窗
  const [pwdUser, setPwdUser] = useState<User | null>(null);
  const [newPwd, setNewPwd] = useState('');
  const [pwdError, setPwdError] = useState('');
  const [pwdSubmitting, setPwdSubmitting] = useState(false);

  // 切换域时重置分页到第一页
  useEffect(() => {
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  }, [currentDomain]);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.users.list({
        page: paginationModel.page + 1,
        page_size: paginationModel.pageSize,
        keyword: keyword.trim() || undefined,
        status: statusFilter || undefined,
      });
      setUsers(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain, paginationModel.page, paginationModel.pageSize, keyword, statusFilter]);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const handleKeywordChange = (value: string) => {
    setKeyword(value);
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  };

  const handleStatusFilterChange = (value: string) => {
    setStatusFilter(value);
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  };

  const openCreateDialog = async () => {
    setCreateError('');
    setForm({
      username: '',
      email: '',
      phone: '',
      display_name: '',
      password: '',
      role_code: '',
    });
    setCreateOpen(true);
    setCreateRolesLoading(true);
    try {
      const rList: Role[] = (await api.roles.list(currentDomain)) || [];
      setCreateRoles(rList);
      if (rList.length > 0) {
        setForm((prev) => ({ ...prev, role_code: rList[0].code }));
      }
    } catch (err) {
      setCreateRoles([]);
      setCreateError((err as Error).message);
    } finally {
      setCreateRolesLoading(false);
    }
  };

  const handleCreateUser = async () => {
    setCreateError('');
    if (!form.username.trim()) {
      setCreateError('请输入用户名。');
      return;
    }
    const pwdErr = validatePassword(form.password, passwordPolicy);
    if (pwdErr) {
      setCreateError(pwdErr);
      return;
    }
    if (!form.role_code) {
      setCreateError('请选择初始角色。');
      return;
    }

    setCreateSubmitting(true);
    try {
      await api.users.create({
        username: form.username.trim(),
        email: form.email.trim(),
        phone: form.phone.trim(),
        display_name: form.display_name.trim(),
        password: form.password,
        domain_code: currentDomain,
        role_codes: [form.role_code],
      });
      setCreateOpen(false);
      setToast('已创建用户');
      await loadUsers();
    } catch (err) {
      setCreateError((err as Error).message);
    } finally {
      setCreateSubmitting(false);
    }
  };

  const openEditUserDialog = (u: User) => {
    setEditError('');
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
    setEditError('');

    const isSelf = editUser.id === currentUser?.id;
    if (isSelf && editForm.status === 'disabled') {
      setEditError('不能停用当前登录的账号。');
      return;
    }

    if (editUser.status === 'active' && editForm.status === 'disabled') {
      const ok = await confirm({
        title: '停用账号',
        content: `停用后，用户「${editUser.username}」将退出所有设备的登录状态，且无法再次登录。确定要停用吗？`,
        confirmText: '确认停用',
        danger: true,
      });
      if (!ok) return;
    }

    setEditSubmitting(true);
    try {
      await api.users.update(editUser.id, {
        display_name: editForm.display_name.trim(),
        email: editForm.email.trim(),
        phone: editForm.phone.trim(),
        avatar_url: editForm.avatar_url.trim(),
        status: isSelf ? editUser.status : editForm.status,
      });
      setEditUser(null);
      setToast('已保存用户信息');
      await loadUsers();
    } catch (err) {
      setEditError((err as Error).message);
    } finally {
      setEditSubmitting(false);
    }
  };

  const openRoleDialog = async (target: User) => {
    setRoleError('');
    setRoleDialogUser(target);
    setRoleDomain(currentDomain);
    setSelectedRoleCodes(target.roles?.[currentDomain] || []);
    try {
      const rList: Role[] = (await api.roles.list(currentDomain)) || [];
      setDomainRoles(rList);
    } catch (err) {
      setDomainRoles([]);
      setRoleError((err as Error).message);
    }
  };

  const handleRoleDomainChange = async (dom: string) => {
    setRoleError('');
    setRoleDomain(dom);
    setSelectedRoleCodes(roleDialogUser?.roles?.[dom] || []);
    try {
      const rList: Role[] = (await api.roles.list(dom)) || [];
      setDomainRoles(rList);
    } catch (err) {
      setDomainRoles([]);
      setRoleError((err as Error).message);
    }
  };

  const handleSaveRoles = async () => {
    if (!roleDialogUser) return;
    setRoleError('');
    setRoleSubmitting(true);
    try {
      await api.users.assignRoles(roleDialogUser.id, {
        domain_code: roleDomain,
        role_codes: selectedRoleCodes,
        replace: true,
      });
      setRoleDialogUser(null);
      setToast('已更新域角色');
      await loadUsers();
    } catch (err) {
      setRoleError((err as Error).message);
    } finally {
      setRoleSubmitting(false);
    }
  };

  const openResetPwdDialog = (target: User) => {
    setPwdError('');
    setNewPwd('');
    setPwdUser(target);
  };

  const handleResetPassword = async () => {
    if (!pwdUser) return;
    setPwdError('');
    const pwdErr = validatePassword(newPwd, passwordPolicy);
    if (pwdErr) {
      setPwdError(pwdErr);
      return;
    }

    const ok = await confirm({
      title: '重置密码',
      content: `确定要重置用户「${pwdUser.username}」的登录密码吗？重置后，该用户需使用新密码登录。`,
      confirmText: '确认重置',
      danger: true,
    });
    if (!ok) return;

    setPwdSubmitting(true);
    try {
      await api.users.resetPassword(pwdUser.id, newPwd);
      setPwdUser(null);
      setNewPwd('');
      setToast('已重置密码');
    } catch (err) {
      setPwdError((err as Error).message);
    } finally {
      setPwdSubmitting(false);
    }
  };

  const handleToggleStatus = async (target: User) => {
    const isDisabling = target.status === 'active';
    if (isDisabling && target.id === currentUser?.id) return;

    if (isDisabling) {
      const ok = await confirm({
        title: '停用账号',
        content: `停用后，用户「${target.username}」将退出所有设备的登录状态，且无法再次登录。确定要停用吗？`,
        confirmText: '确认停用',
        danger: true,
      });
      if (!ok) return;
    }

    setError('');
    try {
      await api.users.update(target.id, { status: isDisabling ? 'disabled' : 'active' });
      setToast(isDisabling ? '已停用账号' : '已启用账号');
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleUnlockUser = async (target: User) => {
    setError('');
    try {
      await api.users.unlock(target.id);
      setToast('已解除锁定');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleResetMFA = async (target: User) => {
    if (target.id === currentUser?.id) return;
    const ok = await confirm({
      title: '重置两步验证',
      content: '将清除该用户绑定的身份验证器，并让其所有设备退出登录。用户下次登录后可重新开启两步验证。',
      confirmText: '确认重置',
      danger: true,
    });
    if (!ok) return;

    setError('');
    try {
      await api.users.resetMFA(target.id);
      setToast('已重置两步验证');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDeleteUser = async (target: User) => {
    if (target.id === currentUser?.id) return;
    const ok = await confirm({
      title: '删除账号',
      content: `将从所有域中移除账号「${target.username}」，此操作不可撤销。确定要删除吗？`,
      confirmText: '确认删除',
      danger: true,
    });
    if (!ok) return;

    setError('');
    try {
      await api.users.delete(target.id);
      setToast('已删除账号');
      await loadUsers();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<User>[] = (() => {
    const baseCols: GridColDef<User>[] = [
      { field: 'id', headerName: 'ID', width: 70 },
      { field: 'username', headerName: '用户名', width: 140 },
      { field: 'display_name', headerName: '显示名称', width: 140 },
      { field: 'email', headerName: '邮箱', width: 200, valueFormatter: (v) => (v ? String(v) : '-') },
      { field: 'phone', headerName: '手机号', width: 140, valueFormatter: (v) => (v ? String(v) : '-') },
      {
        field: 'roles',
        headerName: '域角色',
        flex: 1,
        minWidth: 220,
        sortable: false,
        renderCell: (params) => {
          const entries = Object.entries(params.row.roles || {});
          if (entries.length === 0) {
            return (
              <Typography variant="caption" color="text.secondary">
                无角色
              </Typography>
            );
          }
          return (
            <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" sx={{ py: 0.5 }}>
              {entries.map(([dom, rCodes]) =>
                rCodes.map((rc) => (
                  <Chip key={`${dom}-${rc}`} size="small" label={`${dom}：${rc}`} variant="outlined" />
                )),
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
            label={params.value === 'active' ? '正常' : '已停用'}
          />
        ),
      },
      {
        field: 'last_login_at',
        headerName: '最近登录',
        width: 165,
        valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '从未登录'),
      },
    ];

    if (canWriteUsers) {
      baseCols.push({
        field: 'actions',
        type: 'actions',
        headerName: '操作',
        width: 185,
        getActions: (params) => {
          const isSelf = params.row.id === currentUser?.id;
          const items = [
            <GridActionsCellItem
              key="edit"
              icon={<EditIcon />}
              label="编辑用户"
              onClick={() => openEditUserDialog(params.row)}
              showInMenu={false}
            />,
          ];

          if (canAssignRoles) {
            items.push(
              <GridActionsCellItem
                key="roles"
                icon={<RoleIcon />}
                label="分配域角色"
                onClick={() => void openRoleDialog(params.row)}
                showInMenu={false}
              />,
            );
          }

          items.push(
            <GridActionsCellItem
              key="pwd"
              icon={<KeyIcon />}
              label="重置密码"
              onClick={() => openResetPwdDialog(params.row)}
              showInMenu={false}
            />,
            <GridActionsCellItem
              key="unlock"
              icon={<UnlockIcon fontSize="small" />}
              label="解除锁定"
              onClick={() => void handleUnlockUser(params.row)}
              showInMenu
            />,
          );

          if (!isSelf) {
            items.push(
              <GridActionsCellItem
                key="reset-mfa"
                icon={<ResetMfaIcon fontSize="small" />}
                label="重置两步验证"
                onClick={() => void handleResetMFA(params.row)}
                showInMenu
              />,
            );
          }

          if (!(isSelf && params.row.status === 'active')) {
            items.push(
              <GridActionsCellItem
                key="toggle"
                label={params.row.status === 'active' ? '停用账号' : '启用账号'}
                onClick={() => void handleToggleStatus(params.row)}
                showInMenu
              />,
            );
          }

          if (!isSelf) {
            items.push(
              <GridActionsCellItem
                key="delete"
                icon={<DeleteIcon fontSize="small" color="error" />}
                label="删除账号"
                onClick={() => void handleDeleteUser(params.row)}
                showInMenu
              />,
            );
          }

          return items;
        },
      });
    }

    return baseCols;
  })();

  const isEditingSelf = editUser?.id === currentUser?.id;

  return (
    <Box>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        justifyContent="space-between"
        alignItems={{ sm: 'center' }}
        mb={2.5}
        spacing={2}
      >
        <Box>
          <Typography variant="h5">用户</Typography>
          <Typography variant="body2" color="text.secondary">
            共 {total} 位用户，支持按域分配角色。
          </Typography>
        </Box>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
          <TextField
            size="small"
            placeholder="搜索用户名、邮箱或显示名称"
            value={keyword}
            onChange={(e) => handleKeywordChange(e.target.value)}
            sx={{ minWidth: 220 }}
          />
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>状态</InputLabel>
            <Select
              label="状态"
              value={statusFilter}
              onChange={(e) => handleStatusFilterChange(e.target.value)}
            >
              <MenuItem value="">全部</MenuItem>
              <MenuItem value="active">正常</MenuItem>
              <MenuItem value="disabled">已停用</MenuItem>
            </Select>
          </FormControl>
          {canWriteUsers && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => void openCreateDialog()}>
              新建用户
            </Button>
          )}
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
          paginationMode="server"
          rowCount={total}
          paginationModel={paginationModel}
          onPaginationModelChange={setPaginationModel}
          pageSizeOptions={[10, 20, 50]}
          slots={{ toolbar: GridToolbar }}
        />
      </Box>

      {/* 新建用户弹窗 */}
      <Dialog
        open={createOpen}
        onClose={() => {
          if (!createSubmitting) setCreateOpen(false);
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>新建用户</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {createError && (
              <Alert severity="error" onClose={() => setCreateError('')}>
                {createError}
              </Alert>
            )}
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
              inputProps={{ maxLength: 64 }}
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            />
            <TextField
              label="初始密码"
              size="small"
              type="password"
              required
              helperText={pwdHelperText}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
            <TextField label="所属域" size="small" value={currentDomain} disabled />
            <FormControl size="small" fullWidth required>
              <InputLabel>初始角色</InputLabel>
              <Select
                label="初始角色"
                value={form.role_code}
                disabled={createRolesLoading || createRoles.length === 0}
                onChange={(e) => setForm({ ...form, role_code: e.target.value })}
              >
                {createRoles.map((r) => (
                  <MenuItem key={r.code} value={r.code}>
                    {r.name}（{r.code}）
                  </MenuItem>
                ))}
              </Select>
              {!createRolesLoading && createRoles.length === 0 && (
                <FormHelperText>当前域下暂无可用角色，请先在角色管理中创建。</FormHelperText>
              )}
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={createSubmitting}>
            取消
          </Button>
          <Button
            variant="contained"
            onClick={() => void handleCreateUser()}
            disabled={createSubmitting || createRolesLoading || createRoles.length === 0}
          >
            {createSubmitting ? '创建中…' : '创建'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 编辑用户弹窗 */}
      <Dialog
        open={Boolean(editUser)}
        onClose={() => {
          if (!editSubmitting) setEditUser(null);
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>编辑用户：{editUser?.username}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {editError && (
              <Alert severity="error" onClose={() => setEditError('')}>
                {editError}
              </Alert>
            )}
            <TextField label="用户名" size="small" value={editUser?.username || ''} disabled />
            <TextField
              label="显示名称"
              size="small"
              inputProps={{ maxLength: 64 }}
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
            <FormControl size="small" fullWidth disabled={isEditingSelf}>
              <InputLabel>账号状态</InputLabel>
              <Select
                label="账号状态"
                value={editForm.status}
                onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
              >
                <MenuItem value="active">正常</MenuItem>
                {!isEditingSelf && <MenuItem value="disabled">已停用</MenuItem>}
              </Select>
              {isEditingSelf && <FormHelperText>不能停用当前登录的账号。</FormHelperText>}
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditUser(null)} disabled={editSubmitting}>
            取消
          </Button>
          <Button variant="contained" onClick={() => void handleSaveEditUser()} disabled={editSubmitting}>
            {editSubmitting ? '保存中…' : '保存'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 分配域角色弹窗 */}
      <Dialog
        open={Boolean(roleDialogUser)}
        onClose={() => {
          if (!roleSubmitting) setRoleDialogUser(null);
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>分配域角色：{roleDialogUser?.username}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {roleError && (
              <Alert severity="error" onClose={() => setRoleError('')}>
                {roleError}
              </Alert>
            )}
            <FormControl size="small" fullWidth>
              <InputLabel>选择目标域</InputLabel>
              <Select
                value={roleDomain}
                label="选择目标域"
                onChange={(e) => void handleRoleDomainChange(e.target.value)}
              >
                {domains.map((d) => (
                  <MenuItem key={d.code} value={d.code}>
                    {d.name}（{d.code}）
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Typography variant="subtitle2">选择要授予的角色：</Typography>
            {domainRoles.length === 0 ? (
              <Alert severity="info">该域下暂无角色，可前往角色管理页面创建。</Alert>
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
                    label={`${r.name}（${r.code}）`}
                  />
                ))}
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRoleDialogUser(null)} disabled={roleSubmitting}>
            取消
          </Button>
          <Button variant="contained" onClick={() => void handleSaveRoles()} disabled={roleSubmitting}>
            {roleSubmitting ? '保存中…' : '保存'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* 重置密码弹窗 */}
      <Dialog
        open={Boolean(pwdUser)}
        onClose={() => {
          if (!pwdSubmitting) setPwdUser(null);
        }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>重置密码：{pwdUser?.username}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            {pwdError && (
              <Alert severity="error" onClose={() => setPwdError('')}>
                {pwdError}
              </Alert>
            )}
            <TextField
              label="新密码"
              type="password"
              size="small"
              fullWidth
              required
              helperText={pwdHelperText}
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPwdUser(null)} disabled={pwdSubmitting}>
            取消
          </Button>
          <Button variant="contained" onClick={() => void handleResetPassword()} disabled={pwdSubmitting}>
            {pwdSubmitting ? '重置中…' : '确认重置'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={Boolean(toast)}
        autoHideDuration={3000}
        onClose={() => setToast('')}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" variant="filled" onClose={() => setToast('')}>
          {toast}
        </Alert>
      </Snackbar>
    </Box>
  );
};
