import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  alpha,
  Box,
  Card,
  CardContent,
  Chip,
  Grid2 as Grid,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Stack,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Apps as AppsIcon,
  ChevronRight as ChevronRightIcon,
  Domain as DomainIcon,
  History as AuditIcon,
  People as PeopleIcon,
  Security as RoleIcon,
  Settings as SettingsIcon,
  Verified as VersionIcon,
  VpnKey as PermissionIcon,
} from '@mui/icons-material';
import { BarChart } from '@mui/x-charts/BarChart';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { VersionStatus } from '../types/api';

interface PlatformDashboardData {
  scope: 'platform';
  counts: {
    users: number;
    domains: number;
    roles: number;
    permissions: number;
    oauth_clients: number;
    active_providers: number;
    audit_logs: number;
  };
  version?: VersionStatus;
}

interface DomainDashboardData {
  scope: 'domain';
  domain: string;
  counts: {
    users: number;
    roles: number;
    permissions: number;
    oauth_clients: number;
    audit_logs: number;
  };
}

type DashboardData = PlatformDashboardData | DomainDashboardData;

interface DailyBucket {
  date: string;
  auth_count: number;
  rbac_count: number;
  fail_count: number;
}

interface StatCardItem {
  label: string;
  value: number | string;
  sub: string;
  color: string;
  icon: React.ReactNode;
}

export const DashboardPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { currentDomain, adminTier, hasCap } = useAuth();

  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [dailyStats, setDailyStats] = useState<DailyBucket[]>([]);
  const [error, setError] = useState('');
  const [statsError, setStatsError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setError('');
    setStatsError('');

    const canReadAudit = hasCap('audit_logs:read');
    const tasks: [Promise<DashboardData>, Promise<{ daily_7d?: DailyBucket[] } | null>] = [
      api.system.dashboard(),
      canReadAudit ? api.audit.stats() : Promise.resolve(null),
    ];

    Promise.allSettled(tasks).then(([dashResult, statsResult]) => {
      if (cancelled) return;
      if (dashResult.status === 'fulfilled') {
        setDashboard(dashResult.value);
      } else {
        setDashboard(null);
        setError((dashResult.reason as Error)?.message || '加载概览数据失败，请稍后重试。');
      }

      if (statsResult.status === 'fulfilled') {
        setDailyStats(statsResult.value?.daily_7d || []);
      } else {
        setDailyStats([]);
        setStatsError((statsResult.reason as Error)?.message || '加载活动趋势失败。');
      }
    });

    return () => {
      cancelled = true;
    };
  }, [currentDomain, hasCap]);

  const isPlatformScope = dashboard?.scope === 'platform';

  const statCards: StatCardItem[] = useMemo(() => {
    if (!dashboard) return [];

    if (dashboard.scope === 'domain') {
      return [
        {
          label: '用户',
          value: dashboard.counts.users,
          sub: '当前域成员',
          color: theme.palette.primary.main,
          icon: <PeopleIcon />,
        },
        {
          label: '角色',
          value: dashboard.counts.roles,
          sub: '当前域角色',
          color: theme.palette.success.main,
          icon: <RoleIcon />,
        },
        {
          label: '权限点',
          value: dashboard.counts.permissions,
          sub: '已定义权限',
          color: theme.palette.secondary.main,
          icon: <PermissionIcon />,
        },
        {
          label: 'OAuth 应用',
          value: dashboard.counts.oauth_clients,
          sub: '当前域接入应用',
          color: theme.palette.warning.main,
          icon: <AppsIcon />,
        },
        {
          label: '审计日志',
          value: dashboard.counts.audit_logs,
          sub: '当前域累计记录',
          color: theme.palette.info.main,
          icon: <AuditIcon />,
        },
      ];
    }

    return [
      {
        label: '用户',
        value: dashboard.counts.users,
        sub: '平台已注册账号',
        color: theme.palette.primary.main,
        icon: <PeopleIcon />,
      },
      {
        label: '域',
        value: dashboard.counts.domains,
        sub: '独立权限空间',
        color: theme.palette.secondary.main,
        icon: <DomainIcon />,
      },
      {
        label: '角色',
        value: dashboard.counts.roles,
        sub: `${dashboard.counts.permissions} 项权限点`,
        color: theme.palette.success.main,
        icon: <RoleIcon />,
      },
      {
        label: 'OAuth 应用',
        value: dashboard.counts.oauth_clients,
        sub: `${dashboard.counts.active_providers} 个已启用第三方登录`,
        color: theme.palette.warning.main,
        icon: <AppsIcon />,
      },
      {
        label: '审计日志',
        value: dashboard.counts.audit_logs,
        sub: '全平台累计记录',
        color: theme.palette.info.main,
        icon: <AuditIcon />,
      },
    ];
  }, [dashboard, theme.palette]);

  const quickLinks = useMemo(() => {
    const links: { label: string; desc: string; path: string; icon: React.ReactNode }[] = [];
    if (hasCap('users:read')) {
      links.push({
        label: '用户管理',
        desc: '管理账号、状态与域角色',
        path: '/users',
        icon: <PeopleIcon fontSize="small" />,
      });
    }
    if (hasCap('roles:read')) {
      links.push({
        label: '角色管理',
        desc: '维护域内角色及权限配置',
        path: '/roles',
        icon: <RoleIcon fontSize="small" />,
      });
    }
    if (hasCap('permissions:read')) {
      links.push({
        label: '权限点管理',
        desc: '查看与维护资源访问策略',
        path: '/permissions',
        icon: <PermissionIcon fontSize="small" />,
      });
    }
    links.push({
      label: 'OAuth 应用',
      desc: '管理接入应用的凭据与回调地址',
      path: '/oauth-apps',
      icon: <AppsIcon fontSize="small" />,
    });
    if (hasCap('audit_logs:read')) {
      links.push({
        label: '审计日志',
        desc: '检索登录与权限变更记录',
        path: '/audit-logs',
        icon: <AuditIcon fontSize="small" />,
      });
    }
    if (adminTier === 'platform_admin') {
      links.push(
        {
          label: '域管理',
          desc: '创建与管理平台域空间',
          path: '/domains',
          icon: <DomainIcon fontSize="small" />,
        },
        {
          label: '系统设置',
          desc: '配置站点、安全策略与通知服务',
          path: '/system-settings',
          icon: <SettingsIcon fontSize="small" />,
        },
      );
    }
    return links;
  }, [adminTier, hasCap]);

  const subtitle =
    dashboard?.scope === 'domain'
      ? `以下为「${dashboard.domain || currentDomain}」域的统计。`
      : '账号、权限与登录活动统计。';

  return (
    <Box>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        justifyContent="space-between"
        alignItems={{ sm: 'center' }}
        mb={3}
        spacing={1}
      >
        <Box>
          <Typography variant="h5">概览</Typography>
          <Typography variant="body2" color="text.secondary" mt={0.3}>
            {subtitle}
          </Typography>
        </Box>
        {isPlatformScope && dashboard.version && (
          <Chip
            icon={<VersionIcon />}
            color={dashboard.version.up_to_date ? 'success' : 'warning'}
            variant="outlined"
            label={`v${dashboard.version.app_version} · 数据版本 v${dashboard.version.current_schema_version}`}
          />
        )}
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* 核心指标概览 */}
      {statCards.length > 0 && (
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
      )}

      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6">近 7 天活动统计</Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={2}>
                登录认证、权限变更及失败事件趋势
              </Typography>
              {statsError ? (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  {statsError}
                </Alert>
              ) : dailyStats.length > 0 ? (
                <BarChart
                  height={300}
                  borderRadius={6}
                  xAxis={[{ scaleType: 'band', data: dailyStats.map((d) => d.date.slice(5)) }]}
                  series={[
                    { data: dailyStats.map((d) => d.auth_count), label: '认证与 OAuth', color: theme.palette.primary.main },
                    { data: dailyStats.map((d) => d.rbac_count), label: '权限变更', color: theme.palette.success.main },
                    { data: dailyStats.map((d) => d.fail_count), label: '失败事件', color: theme.palette.error.main },
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
              <Typography variant="h6">快捷入口</Typography>
              <Typography variant="caption" color="text.secondary" display="block" mb={1.5}>
                常用管理功能快速跳转
              </Typography>
              <List disablePadding>
                {quickLinks.map((link) => (
                  <ListItemButton
                    key={link.path}
                    onClick={() => navigate(link.path)}
                    sx={{ borderRadius: 2, px: 1.2, py: 0.9, mb: 0.5 }}
                  >
                    <ListItemIcon sx={{ minWidth: 34, color: 'primary.main' }}>{link.icon}</ListItemIcon>
                    <ListItemText
                      primary={link.label}
                      secondary={link.desc}
                      primaryTypographyProps={{ variant: 'body2', fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: 'caption' }}
                    />
                    <ChevronRightIcon fontSize="small" color="action" />
                  </ListItemButton>
                ))}
              </List>

              {isPlatformScope && dashboard.version && (
                <Alert
                  severity={dashboard.version.up_to_date ? 'success' : 'warning'}
                  variant="outlined"
                  sx={{ mt: 2, borderRadius: 2.5 }}
                >
                  {dashboard.version.message || '系统版本状态正常。'}
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};
