import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormHelperText,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { Add as AddIcon, Block as RevokeIcon, MoreTime as JitIcon } from '@mui/icons-material';
import { DataGrid, GridActionsCellItem, GridColDef, GridToolbar } from '@mui/x-data-grid';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { useConfirm } from '../components/ConfirmDialog';
import { AnimatedRefreshIcon } from '../components/PageTransition';
import { useAuth } from '../context/AuthContext';
import { Role, TempRoleGrant, User } from '../types/api';

const MAX_TTL_MINUTES = 30 * 24 * 60; // 30 天（与后端限制一致）
const MIN_REASON_LENGTH = 4;

const STATUS_MAP: Record<string, { label: string; color: 'success' | 'warning' | 'default' | 'error' }> = {
  active: { label: '生效中', color: 'success' },
  pending: { label: '待生效', color: 'warning' },
  expired: { label: '已到期回收', color: 'default' },
  revoked: { label: '已撤销', color: 'error' },
};

interface FieldErrors {
  userId?: string;
  roleCode?: string;
  startsAt?: string;
  ttlMinutes?: string;
  reason?: string;
}

export const JitGrantsPage: React.FC = () => {
  const { currentDomain, hasCap } = useAuth();
  const confirm = useConfirm();
  const canWrite = hasCap('jit:write');
  const [grants, setGrants] = useState<TempRoleGrant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [dialogError, setDialogError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [userId, setUserId] = useState<number>(0);
  const [roleCode, setRoleCode] = useState('');
  const [ttlInput, setTtlInput] = useState('120');
  const [startsAtLocal, setStartsAtLocal] = useState('');
  const [reason, setReason] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [gList, uRes, rList] = await Promise.all([
        api.jit.list({ domain: currentDomain }),
        api.users.list({ page: 1, page_size: 100 }).catch(() => ({ items: [] })),
        api.roles.list(currentDomain).catch(() => []),
      ]);
      setGrants(gList || []);
      setUsers(uRes?.items || []);
      setRoles(rList || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [currentDomain]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const openCreateDialog = () => {
    setDialogError('');
    setFieldErrors({});
    setUserId(0);
    setRoleCode('');
    setTtlInput('120');
    setStartsAtLocal('');
    setReason('');
    setOpen(true);
  };

  const handleCloseDialog = () => {
    if (submitting) return;
    setOpen(false);
  };

  const validateForm = (): { valid: boolean; ttlNum: number; startsAtIso?: string } => {
    const nextErrors: FieldErrors = {};

    if (!userId) {
      nextErrors.userId = '请选择目标用户';
    }
    if (!roleCode) {
      nextErrors.roleCode = '请选择临时角色';
    }

    const trimmedTtl = ttlInput.trim();
    const ttlNum = Number(trimmedTtl);
    if (!trimmedTtl || !Number.isInteger(ttlNum) || ttlNum < 1 || ttlNum > MAX_TTL_MINUTES) {
      nextErrors.ttlMinutes = `请输入 1 至 ${MAX_TTL_MINUTES} 之间的正整数（最长 30 天）`;
    }

    let startsAtIso: string | undefined;
    if (startsAtLocal) {
      const parsedStart = dayjs(startsAtLocal);
      const now = dayjs();
      if (!parsedStart.isValid()) {
        nextErrors.startsAt = '生效时间格式无效';
      } else if (parsedStart.isAfter(now.add(30, 'day'))) {
        nextErrors.startsAt = '预约生效时间不得晚于 30 天后';
      } else if (!nextErrors.ttlMinutes && !parsedStart.add(ttlNum, 'minute').isAfter(now)) {
        nextErrors.startsAt = '到期时间必须晚于当前时间';
      } else {
        startsAtIso = parsedStart.toDate().toISOString();
      }
    }

    const trimmedReason = reason.trim();
    if (!trimmedReason) {
      nextErrors.reason = '请填写授权原因';
    } else if (trimmedReason.length < MIN_REASON_LENGTH) {
      nextErrors.reason = `授权原因至少需要 ${MIN_REASON_LENGTH} 个字符`;
    }

    setFieldErrors(nextErrors);
    return { valid: Object.keys(nextErrors).length === 0, ttlNum, startsAtIso };
  };

  const handleCreate = async () => {
    setDialogError('');
    const { valid, ttlNum, startsAtIso } = validateForm();
    if (!valid) return;

    setSubmitting(true);
    try {
      const payload: {
        user_id: number;
        domain_code: string;
        role_code: string;
        reason: string;
        ttl_minutes: number;
        starts_at?: string;
      } = {
        user_id: userId,
        domain_code: currentDomain,
        role_code: roleCode,
        reason: reason.trim(),
        ttl_minutes: ttlNum,
      };
      if (startsAtIso) {
        payload.starts_at = startsAtIso;
      }
      await api.jit.create(payload);
      setOpen(false);
      setSuccess('已创建临时授权，到期后将由系统自动回收。');
      await loadData();
    } catch (err) {
      setDialogError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (row: TempRoleGrant) => {
    const ok = await confirm({
      title: '撤销临时授权',
      content: `确认提前撤销用户「${row.username || `#${row.user_id}`}」的临时角色「${row.role_code}」？撤销后该临时角色将立即失效。`,
      confirmText: '确认撤销',
      danger: true,
    });
    if (!ok) return;

    setError('');
    setSuccess('');
    try {
      await api.jit.revoke(row.id);
      setSuccess('已提前撤销该临时授权。');
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: GridColDef<TempRoleGrant>[] = [
    { field: 'username', headerName: '用户', width: 130, valueGetter: (_, r) => r.username || `#${r.user_id}` },
    { field: 'domain_code', headerName: '业务域', width: 110 },
    { field: 'role_code', headerName: '临时角色', width: 130 },
    {
      field: 'status',
      headerName: '状态',
      width: 120,
      renderCell: (p) => {
        const meta = STATUS_MAP[p.value as string] || { label: String(p.value || '—'), color: 'default' as const };
        return <Chip size="small" color={meta.color} label={meta.label} />;
      },
    },
    {
      field: 'reason',
      headerName: '授权原因',
      flex: 1,
      minWidth: 180,
      valueGetter: (_, r) => r.reason || '—',
    },
    {
      field: 'starts_at',
      headerName: '生效时间',
      width: 160,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '—'),
    },
    {
      field: 'expires_at',
      headerName: '到期自动回收',
      width: 160,
      valueFormatter: (v) => (v ? dayjs(v as string).format('YYYY-MM-DD HH:mm') : '—'),
    },
    ...(canWrite
      ? [
          {
            field: 'actions',
            type: 'actions',
            headerName: '撤销',
            width: 75,
            getActions: (p: { row: TempRoleGrant }) =>
              p.row.status === 'active' || p.row.status === 'pending'
                ? [
                    <GridActionsCellItem
                      key="rev"
                      icon={<RevokeIcon color="error" />}
                      label="提前撤销"
                      onClick={() => void handleRevoke(p.row)}
                    />,
                  ]
                : [],
          } as GridColDef<TempRoleGrant>,
        ]
      : []),
  ];

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} spacing={2} mb={2.5}>
        <Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <JitIcon color="primary" />
            <Typography variant="h5">临时授权（JIT）</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary" mt={0.4}>
            为应急运维或临时协作授予限时角色，支持预约生效，到期后由系统自动回收。
          </Typography>
        </Box>
        <Stack direction="row" spacing={1.5}>
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
          {canWrite && (
            <Button variant="contained" startIcon={<AddIcon />} onClick={openCreateDialog}>
              新增临时授权
            </Button>
          )}
        </Stack>
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
          {success}
        </Alert>
      )}

      <Box sx={{ height: 520 }}>
        <DataGrid
          rows={grants}
          columns={columns}
          loading={loading}
          disableRowSelectionOnClick
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
        />
      </Box>

      {canWrite && (
        <Dialog open={open} onClose={handleCloseDialog} maxWidth="xs" fullWidth>
          <DialogTitle>新增临时授权（域：{currentDomain}）</DialogTitle>
          <DialogContent>
            <Stack spacing={2} mt={1}>
              {dialogError && (
                <Alert severity="error" onClose={() => setDialogError('')}>
                  {dialogError}
                </Alert>
              )}

              <FormControl size="small" fullWidth required error={Boolean(fieldErrors.userId)}>
                <InputLabel>目标用户</InputLabel>
                <Select
                  label="目标用户"
                  value={userId || ''}
                  onChange={(e) => {
                    setUserId(Number(e.target.value));
                    if (fieldErrors.userId) setFieldErrors((prev) => ({ ...prev, userId: undefined }));
                  }}
                >
                  {users.map((u) => (
                    <MenuItem key={u.id} value={u.id}>
                      {u.username}（{u.display_name || u.email || '未命名'}）
                    </MenuItem>
                  ))}
                </Select>
                {fieldErrors.userId && <FormHelperText>{fieldErrors.userId}</FormHelperText>}
              </FormControl>

              <FormControl size="small" fullWidth required error={Boolean(fieldErrors.roleCode)}>
                <InputLabel>临时角色</InputLabel>
                <Select
                  label="临时角色"
                  value={roleCode}
                  onChange={(e) => {
                    setRoleCode(e.target.value);
                    if (fieldErrors.roleCode) setFieldErrors((prev) => ({ ...prev, roleCode: undefined }));
                  }}
                >
                  {roles.map((r) => (
                    <MenuItem key={r.id} value={r.code}>
                      {r.name}（{r.code}）
                    </MenuItem>
                  ))}
                </Select>
                {fieldErrors.roleCode && <FormHelperText>{fieldErrors.roleCode}</FormHelperText>}
              </FormControl>

              <TextField
                label="预约生效时间（留空则立即生效）"
                type="datetime-local"
                size="small"
                fullWidth
                InputLabelProps={{ shrink: true }}
                value={startsAtLocal}
                error={Boolean(fieldErrors.startsAt)}
                helperText={fieldErrors.startsAt || '使用本地时间，最晚可预约 30 天内生效'}
                onChange={(e) => {
                  setStartsAtLocal(e.target.value);
                  if (fieldErrors.startsAt) setFieldErrors((prev) => ({ ...prev, startsAt: undefined }));
                }}
              />

              <TextField
                label="有效时长（分钟）"
                type="number"
                size="small"
                fullWidth
                required
                inputProps={{ min: 1, max: MAX_TTL_MINUTES, step: 1 }}
                value={ttlInput}
                error={Boolean(fieldErrors.ttlMinutes)}
                helperText={fieldErrors.ttlMinutes || `请输入 1 至 ${MAX_TTL_MINUTES} 之间的正整数（最长 30 天）`}
                onChange={(e) => {
                  setTtlInput(e.target.value);
                  if (fieldErrors.ttlMinutes) setFieldErrors((prev) => ({ ...prev, ttlMinutes: undefined }));
                }}
              />

              <TextField
                label="授权原因（将写入审计日志）"
                size="small"
                fullWidth
                required
                multiline
                minRows={2}
                value={reason}
                error={Boolean(fieldErrors.reason)}
                helperText={fieldErrors.reason || `请简要说明授权背景，至少 ${MIN_REASON_LENGTH} 个字符`}
                onChange={(e) => {
                  setReason(e.target.value);
                  if (fieldErrors.reason) setFieldErrors((prev) => ({ ...prev, reason: undefined }));
                }}
              />
            </Stack>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={handleCloseDialog} disabled={submitting}>
              取消
            </Button>
            <Button variant="contained" onClick={() => void handleCreate()} disabled={submitting}>
              {submitting ? '提交中…' : '确认授权'}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};
