import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Grid2 as Grid,
  Stack,
  Typography,
} from '@mui/material';
import {
  Apps as AppsIcon,
  Domain as DomainIcon,
  History as AuditIcon,
  People as PeopleIcon,
  Security as RoleIcon,
  Verified as VersionIcon,
} from '@mui/icons-material';
import { BarChart } from '@mui/x-charts/BarChart';
import { api } from '../api/client';
import { VersionStatus } from '../types/api';

interface DashboardData {
  counts: {
    users: number;
    domains: number;
    roles: number;
    permissions: number;
    oauth_clients: number;
    active_providers: number;
    audit_logs: number;
  };
  version: VersionStatus;
}

interface DailyBucket {
  date: string;
  auth_count: number;
  rbac_count: number;
  fail_count: number;
}

export const DashboardPage: React.FC = () => {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [dailyStats, setDailyStats] = useState<DailyBucket[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api.system.dashboard(), api.audit.stats()])
      .then(([dashRes, statsRes]) => {
        setDashboard(dashRes);
        setDailyStats(statsRes?.daily_7d || []);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  const statCards = [
    { label: '平台用户数', value: dashboard?.counts.users ?? '-', icon: <PeopleIcon color="primary" /> },
    { label: '业务域 / 租户', value: dashboard?.counts.domains ?? '-', icon: <DomainIcon color="secondary" /> },
    { label: 'RBAC 角色', value: dashboard?.counts.roles ?? '-', icon: <RoleIcon color="success" /> },
    { label: 'OAuth 接入应用', value: dashboard?.counts.oauth_clients ?? '-', icon: <AppsIcon color="warning" /> },
    { label: '审计事件总数', value: dashboard?.counts.audit_logs ?? '-', icon: <AuditIcon color="info" /> },
  ];

  return (
    <Box>
      <Typography variant="h5" mb={0.5}>
        安全仪表盘
      </Typography>
      <Typography variant="body2" color="text.secondary" mb={3}>
        OpenRealm 私有身份中心运行态势、多域 RBAC 与审计趋势概览
      </Typography>

      {error && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={2} mb={3}>
        {statCards.map((item) => (
          <Grid key={item.label} size={{ xs: 12, sm: 6, md: 2.4 }}>
            <Card>
              <CardContent>
                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      {item.label}
                    </Typography>
                    <Typography variant="h4" mt={0.5}>
                      {item.value}
                    </Typography>
                  </Box>
                  <Box sx={{ p: 1, borderRadius: 2, bgcolor: 'action.hover' }}>{item.icon}</Box>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" mb={1}>
                近 7 日认证与 RBAC 审计事件分布
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={2}>
                包含账密/OAuth 认证事件、角色/权限变更事件与失败告警
              </Typography>
              {dailyStats.length > 0 ? (
                <BarChart
                  height={290}
                  xAxis={[{ scaleType: 'band', data: dailyStats.map((d) => d.date.slice(5)) }]}
                  series={[
                    { data: dailyStats.map((d) => d.auth_count), label: '认证与 OAuth', color: '#1E40AF' },
                    { data: dailyStats.map((d) => d.rbac_count), label: 'RBAC 权限变更', color: '#10B981' },
                    { data: dailyStats.map((d) => d.fail_count), label: '失败/拦截事件', color: '#EF4444' },
                  ]}
                />
              ) : (
                <Box sx={{ py: 8, textAlign: 'center', color: 'text.secondary' }}>暂无统计数据</Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, lg: 4 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Stack direction="row" spacing={1} alignItems="center" mb={2}>
                <VersionIcon color="primary" />
                <Typography variant="h6">系统与数据库版本</Typography>
              </Stack>

              <Stack spacing={1.8}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">
                    应用版本
                  </Typography>
                  <Chip size="small" label={`v${dashboard?.version?.app_version || '0.1.0'}`} color="primary" />
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">
                    Schema 版本
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    v{dashboard?.version?.current_schema_version ?? '-'} / 期望 v
                    {dashboard?.version?.expected_schema_version ?? '-'}
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">
                    一致性状态
                  </Typography>
                  <Chip
                    size="small"
                    color={dashboard?.version?.up_to_date ? 'success' : 'warning'}
                    label={dashboard?.version?.up_to_date ? '版本同步正常' : '需要检查'}
                  />
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">
                    已启用联合登录源
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {dashboard?.counts.active_providers ?? 0} 个
                  </Typography>
                </Box>
                <Alert severity={dashboard?.version?.up_to_date ? 'info' : 'warning'} sx={{ mt: 1 }}>
                  {dashboard?.version?.message || '版本信息加载中...'}
                </Alert>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};
