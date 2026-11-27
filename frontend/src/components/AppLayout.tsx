import React, { useMemo, useState } from 'react';
import {
  alpha,
  AppBar,
  Autocomplete,
  Avatar,
  Box,
  Chip,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Select,
  Stack,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Apps as AppsIcon,
  Brightness4 as DarkIcon,
  Brightness7 as LightIcon,
  Dashboard as DashboardIcon,
  Domain as DomainIcon,
  Gavel as PolicyIcon,
  History as AuditIcon,
  Hub as ProviderIcon,
  Logout as LogoutIcon,
  Menu as MenuIcon,
  Palette as PaletteIcon,
  People as PeopleIcon,
  Search as SearchIcon,
  Security as RoleIcon,
  Settings as SettingsIcon,
  VerifiedUser as ShieldIcon,
  SystemUpdateAlt as VersionIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';
import { PageTransition } from './PageTransition';
import { ThemeDrawer } from './ThemeDrawer';

const DRAWER_WIDTH = 244;

interface NavItem {
  label: string;
  path: string;
  keywords: string;
  icon: React.ReactNode;
  // 平台级入口（全局设置、全局身份源）只对超级管理员展示；
  // 域管理员点了也只会拿到 403，隐藏只是体验，鉴权仍在服务端。
  platformOnly?: boolean;
}

const navSections: { title: string; items: NavItem[] }[] = [
  {
    title: '总览',
    items: [{ label: '概览', path: '/', keywords: 'dashboard overview 首页 统计 图表', icon: <DashboardIcon fontSize="small" /> }],
  },
  {
    title: '访问控制',
    items: [
      { label: '用户', path: '/users', keywords: 'users 账号 密码 角色', icon: <PeopleIcon fontSize="small" /> },
      { label: '角色', path: '/roles', keywords: 'roles rbac 角色管理', icon: <RoleIcon fontSize="small" /> },
      { label: '权限', path: '/permissions', keywords: 'permissions policy tree 权限 策略', icon: <PolicyIcon fontSize="small" /> },
      { label: '业务域', path: '/domains', keywords: 'domains tenant 多租户 工作空间', icon: <DomainIcon fontSize="small" /> },
    ],
  },
  {
    title: '应用与登录',
    items: [
      { label: '应用管理', path: '/oauth-apps', keywords: 'oauth client oidc sso 应用', icon: <AppsIcon fontSize="small" /> },
      { label: '第三方登录', path: '/identity-providers', keywords: 'idp sso github google feishu wecom 联合登录', icon: <ProviderIcon fontSize="small" />, platformOnly: true },
    ],
  },
  {
    title: '系统',
    items: [
      { label: '审计日志', path: '/audit-logs', keywords: 'audit logs 登录记录 变更记录', icon: <AuditIcon fontSize="small" /> },
      { label: '系统设置', path: '/system-settings', keywords: 'settings config jwt ratelimit cors 设置', icon: <SettingsIcon fontSize="small" />, platformOnly: true },
      { label: '版本信息', path: '/system-version', keywords: 'version migration 数据库 版本', icon: <VersionIcon fontSize="small" /> },
    ],
  },
];

export const AppLayout: React.FC = () => {
  const theme = useTheme();
  const toggleColorMode = useThemeStore((s) => s.toggleColorMode);
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const motionScale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchFocused, setSearchFocused] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [themeDrawerOpen, setThemeDrawerOpen] = useState(false);
  const { user, roles, domains, currentDomain, switchDomain, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const isSuperAdmin = useMemo(() => (roles['openiam'] || []).includes('super_admin'), [roles]);
  const visibleSections = useMemo(
    () =>
      navSections
        .map((sec) => ({ ...sec, items: sec.items.filter((i) => !i.platformOnly || isSuperAdmin) }))
        .filter((sec) => sec.items.length > 0),
    [isSuperAdmin],
  );
  const allNavItems = useMemo(() => visibleSections.flatMap((s) => s.items), [visibleSections]);
  const radius = Number(theme.shape.borderRadius);

  const handleLogout = async () => {
    setAnchorEl(null);
    await logout();
    navigate('/login');
  };

  const drawerContent = (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        bgcolor: 'background.default',
      }}
    >
      {/* 品牌标识区 */}
      <Box sx={{ px: 2.5, py: 2, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: `${Math.max(4, radius)}px`,
            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.28)}`,
          }}
        >
          <ShieldIcon fontSize="small" />
        </Box>
        <Box>
          <Typography variant="subtitle1" fontWeight={700} lineHeight={1.2}>
            OpenIAM
          </Typography>
          <Typography variant="caption" color="text.secondary">
            身份与访问管理
          </Typography>
        </Box>
      </Box>

      {/* 导航菜单 */}
      <Box sx={{ flex: 1, overflowY: 'auto', px: 1.5, py: 1 }}>
        {visibleSections.map((sec) => (
          <Box key={sec.title} sx={{ mb: 2 }}>
            <Typography
              variant="overline"
              color="text.secondary"
              sx={{ px: 1.5, fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.06em' }}
            >
              {sec.title}
            </Typography>
            <List disablePadding sx={{ mt: 0.5 }}>
              {sec.items.map((item) => {
                const selected = location.pathname === item.path;
                return (
                  <ListItemButton
                    key={item.path}
                    selected={selected}
                    onClick={() => {
                      navigate(item.path);
                      setMobileOpen(false);
                    }}
                    sx={{
                      borderRadius: `${radius}px`,
                      mb: 0.4,
                      py: 0.9,
                      px: 1.5,
                      color: selected ? 'primary.main' : 'text.primary',
                      '& .MuiListItemIcon-root': {
                        minWidth: 34,
                        color: selected ? 'primary.main' : 'text.secondary',
                      },
                      '&.Mui-selected': {
                        bgcolor: alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.16 : 0.1),
                        '&:hover': {
                          bgcolor: alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.22 : 0.14),
                        },
                      },
                      '&:hover': {
                        bgcolor: alpha(theme.palette.text.primary, 0.04),
                      },
                    }}
                  >
                    <ListItemIcon>{item.icon}</ListItemIcon>
                    <ListItemText
                      primary={item.label}
                      primaryTypographyProps={{
                        fontSize: '0.875rem',
                        fontWeight: selected ? 600 : 500,
                      }}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          </Box>
        ))}
      </Box>

      {/* 底部域状态 */}
      <Box sx={{ p: 2 }}>
        <Box
          sx={{
            p: 1.4,
            borderRadius: `${radius + 2}px`,
            bgcolor: 'background.paper',
            border: 1,
            borderColor: 'divider',
          }}
        >
          <Typography variant="caption" color="text.secondary" display="block">
            当前业务域
          </Typography>
          <Stack direction="row" alignItems="center" justifyContent="space-between" mt={0.4}>
            <Typography variant="body2" fontWeight={700} color="primary.main">
              {currentDomain}
            </Typography>
            <Chip size="small" label="已连接" color="success" variant="outlined" sx={{ height: 20, fontSize: '0.68rem' }} />
          </Stack>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* 顶部导航栏 */}
      <AppBar
        position="fixed"
        elevation={0}
        color="inherit"
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { md: `${DRAWER_WIDTH}px` },
          bgcolor: alpha(theme.palette.background.default, 0.82),
          backdropFilter: 'blur(14px)',
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Toolbar sx={{ gap: 1.5, minHeight: '60px !important' }}>
          <IconButton edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ display: { md: 'none' } }}>
            <MenuIcon />
          </IconButton>

          {/* 全局快捷搜索（聚焦平滑展开动画） */}
          <motion.div
            animate={{ width: searchFocused ? 310 : 220 }}
            transition={
              motionScale === 0
                ? { duration: 0 }
                : { type: 'spring', stiffness: 360 / motionScale, damping: 30 }
            }
            style={{ maxWidth: '48vw' }}
          >
            <Autocomplete
              size="small"
              options={allNavItems}
              getOptionLabel={(o) => o.label}
              filterOptions={(options, state) => {
                const q = state.inputValue.trim().toLowerCase();
                if (!q) return options;
                return options.filter(
                  (o) => o.label.toLowerCase().includes(q) || o.keywords.toLowerCase().includes(q),
                );
              }}
              onChange={(_, val) => {
                if (val) navigate(val.path);
              }}
              fullWidth
              renderInput={(params) => (
                <TextField
                  {...params}
                  placeholder="搜索页面..."
                  onFocus={() => setSearchFocused(true)}
                  onBlur={() => setSearchFocused(false)}
                  InputProps={{
                    ...params.InputProps,
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon fontSize="small" color={searchFocused ? 'primary' : 'action'} />
                      </InputAdornment>
                    ),
                  }}
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      bgcolor: 'background.paper',
                      height: 36,
                      boxShadow: searchFocused ? `0 0 0 3px ${alpha(theme.palette.primary.main, 0.14)}` : 'none',
                    },
                  }}
                />
              )}
            />
          </motion.div>

          {/* 业务域选择器 */}
          <FormControl size="small" sx={{ minWidth: { xs: 110, sm: 170 } }}>
            <Select
              value={currentDomain}
              onChange={(e) => switchDomain(e.target.value)}
              sx={{
                fontSize: '0.84rem',
                height: 36,
                bgcolor: 'background.paper',
              }}
            >
              {domains.length === 0 ? (
                <MenuItem value="openiam">openiam · 核心域</MenuItem>
              ) : (
                domains.map((d) => (
                  <MenuItem key={d.code} value={d.code}>
                    {d.code} · {d.name}
                  </MenuItem>
                ))
              )}
            </Select>
          </FormControl>

          <Box sx={{ flexGrow: 1 }} />

          {/* 外观与主题抽屉触发器 */}
          <Tooltip title="外观与主题设置">
            <IconButton onClick={() => setThemeDrawerOpen(true)} size="small">
              <PaletteIcon fontSize="small" color="primary" />
            </IconButton>
          </Tooltip>

          <Tooltip title={theme.palette.mode === 'light' ? '切换深色模式' : '切换浅色模式'}>
            <IconButton onClick={() => toggleColorMode(theme.palette.mode)} size="small">
              {theme.palette.mode === 'light' ? <DarkIcon fontSize="small" /> : <LightIcon fontSize="small" />}
            </IconButton>
          </Tooltip>

          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} sx={{ p: 0.5 }}>
            <Avatar
              sx={{
                width: 32,
                height: 32,
                bgcolor: 'primary.main',
                fontSize: '0.85rem',
                fontWeight: 700,
              }}
            >
              {(user?.display_name || user?.username || 'A').slice(0, 1).toUpperCase()}
            </Avatar>
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
            PaperProps={{ sx: { minWidth: 200, border: 1, borderColor: 'divider' } }}
          >
            <Box sx={{ px: 2, py: 1.2 }}>
              <Typography variant="subtitle2">{user?.display_name || user?.username}</Typography>
              <Typography variant="caption" color="text.secondary">
                {user?.email}
              </Typography>
            </Box>
            <Divider />
            <MenuItem onClick={handleLogout}>
              <ListItemIcon>
                <LogoutIcon fontSize="small" />
              </ListItemIcon>
              退出登录
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* 响应式侧边栏 */}
      <Box component="nav" sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box', border: 'none' },
          }}
        >
          {drawerContent}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': {
              width: DRAWER_WIDTH,
              boxSizing: 'border-box',
              borderRight: 1,
              borderColor: 'divider',
            },
          }}
          open
        >
          {drawerContent}
        </Drawer>
      </Box>

      {/* 主内容区域（带路由过渡动画） */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3 },
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          mt: '60px',
          maxWidth: '100%',
        }}
      >
        <AnimatePresence mode="wait">
          <PageTransition key={location.pathname}>
            <Outlet />
          </PageTransition>
        </AnimatePresence>
      </Box>

      <ThemeDrawer open={themeDrawerOpen} onClose={() => setThemeDrawerOpen(false)} />
    </Box>
  );
};
