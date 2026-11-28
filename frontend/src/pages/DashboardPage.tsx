import React, { useEffect, useState } from 'react';
import {
  Alert,
  alpha,
  Box,
  Card,
  CardContent,
  Chip,
  Grid2 as Grid,
  Stack,
  Typography,
  useTheme,
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
import { PieChart } from '@mui/x-charts/PieChart';
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
  const theme = useTheme();
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
    {
      label: '用户',
      value: dashboard?.counts.users ?? '-',
      sub: '已注册账号',
      color: theme.palette.primary.main,
      icon: <PeopleIcon />,
    },
    {
      label: '业务域',
      value: dashboard?.counts.domains ?? '-',
      sub: '独立权限空间',
      color: theme.palette.secondary.main,
      icon: <DomainIcon />,
    },
    {
      label: '角色',
      value: dashboard?.counts.roles ?? '-',
      sub: `${dashboard?.counts.permissions ?? 0} 项权限`,
      color: theme.palette.success.main,
      icon: <RoleIcon />,
    },
    {
      label: '接入应用',
      value: dashboard?.counts.oauth_clients ?? '-',
      sub: `${dashboard?.counts.active_providers ?? 0} 个第三方登录`,
      color: theme.palette.warning.main,
      icon: <AppsIcon />,
    },
    {
      label: '审计日志',
      value: dashboard?.counts.audit_logs ?? '-',
      sub: '累计记录数',
      color: theme.palette.info.main,
      icon: <AuditIcon />,
    },
  ];

  const pieData = [
    { id: 0, value: dashboard?.counts.users || 0, label: '用户', color: theme.palette.primary.main },
    { id: 1, value: dashboard?.counts.roles || 0, label: '角色', color: theme.palette.success.main },
    { id: 2, value: dashboard?.counts.permissions || 0, label: '权限点', color: theme.palette.secondary.main },
    { id: 3, value: dashboard?.counts.oauth_clients || 0, label: 'OAuth 应用', color: theme.palette.warning.main },
  ].filter((d) => d.value > 0);

  return (
    <Box>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'center' }} mb={3} spacing={1}>
        <Box>
          <Typography variant="h5">概览</Typography>
          <Typography variant="body2" color="text.secondary" mt={0.3}>
            账号、权限与登录活动统计
          </Typography>
        </Box>
        {dashboard?.version && (
          <Chip
            icon={<VersionIcon />}
            color={dashboard.version.up_to_date ? 'success' : 'warning'}
            variant="outlined"
            label={`v${dashboard.version.app_version} · 数据版本 v${dashboard.version.current_schema_version}`}
          />
        )}
      </Stack>

      {error && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* 核心指标概览 */}
      <Grid container spacing={2} mb={3}>
        {statCards.map((item) => (
          <Grid key={item.label} size={{ xs: 12, sm: 6, md: 2.4 }}>
            <Card
              sx={{
                '&:hover': {
                  borderColor: alpha(item.color, 0.45),
                  boxShadow: `0 6px 20px ${alpha(item.color, 0.12)}`,
                },
              }}
            >
              <CardContent sx={{ p: 2.2 }}>
                <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                  <Box>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      {item.label}
                    </Typography>
                    <Typography variant="h4" mt={0.6} mb={0.4}>
                      {item.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.sub}
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      width: 42,
                      height: 42,
                      borderRadius: 2.5,
                      bgcolor: alpha(item.color, 0.12),
                      color: item.color,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {item.icon}
                  </Box>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6">近 7 天活动统计</Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={2}>
                登录认证、权限变更及失败拦截趋势
              </Typography>
              {dailyStats.length > 0 ? (
                <BarChart
                  height={300}
                  borderRadius={6}
                  xAxis={[{ scaleType: 'band', data: dailyStats.map((d) => d.date.slice(5)) }]}
                  series={[
                    { data: dailyStats.map((d) => d.auth_count), label: '认证与 OAuth', color: theme.palette.primary.main },
                    { data: dailyStats.map((d) => d.rbac_count), label: 'RBAC 权限变更', color: theme.palette.success.main },
                    { data: dailyStats.map((d) => d.fail_count), label: '失败/拦截事件', color: theme.palette.error.main },
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
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6">资源分布</Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={1.5}>
                用户、角色、权限与应用数量占比
              </Typography>
              {pieData.length > 0 ? (
                <PieChart
                  height={210}
                  series={[
                    {
                      data: pieData,
                      innerRadius: 48,
                      outerRadius: 78,
                      paddingAngle: 3,
                      cornerRadius: 6,
                    },
                  ]}
                />
              ) : (
                <Box sx={{ py: 5, textAlign: 'center', color: 'text.secondary' }}>暂无资源数据</Box>
              )}

              <Alert
                severity={dashboard?.version?.up_to_date ? 'success' : 'warning'}
                variant="outlined"
                sx={{ mt: 2, borderRadius: 2.5 }}
              >
                {dashboard?.version?.message || '正在检查系统版本状态...'}
              </Alert>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};
