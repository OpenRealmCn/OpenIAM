import React, { useMemo, useState } from 'react';
import {
  Alert,
  AlertTitle,
  alpha,
  AppBar,
  Autocomplete,
  Avatar,
  Box,
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
  Home as PortalIcon,
  Hub as ProviderIcon,
  Logout as LogoutIcon,
  ManageAccounts as ProfileIcon,
  Menu as MenuIcon,
  Palette as PaletteIcon,
  People as PeopleIcon,
  Search as SearchIcon,
  Security as RoleIcon,
  Settings as SettingsIcon,
  SystemUpdateAlt as VersionIcon,
  VerifiedUser as ShieldIcon,
} from '@mui/icons-material';
import { AnimatePresence, motion } from 'framer-motion';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';
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

const adminNavSections: { title: string; items: NavItem[] }[] = [
  {
    title: '总览',
    items: [
      { label: '管理概览', path: '/', keywords: 'dashboard overview 首页 统计 图表', icon: <DashboardIcon fontSize="small" /> },
      { label: '个人工作台', path: '/portal', keywords: 'portal 工作台 个人 首页', icon: <PortalIcon fontSize="small" /> },
    ],
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
    title: '系统与账号',
    items: [
      { label: '审计日志', path: '/audit-logs', keywords: 'audit logs 登录记录 变更记录', icon: <AuditIcon fontSize="small" /> },
      { label: '系统设置', path: '/system-settings', keywords: 'settings config smtp site 公告 图标 设置', icon: <SettingsIcon fontSize="small" />, platformOnly: true },
      { label: '版本信息', path: '/system-version', keywords: 'version migration 数据库 版本', icon: <VersionIcon fontSize="small" /> },
      { label: '个人中心', path: '/profile', keywords: 'profile passkey 密码 通行密钥 资料 绑定', icon: <ProfileIcon fontSize="small" /> },
    ],
  },
];

const userNavSections: { title: string; items: NavItem[] }[] = [
  {
    title: '个人空间',
    items: [
      { label: '工作台', path: '/', keywords: 'portal 首页 概览 工作台', icon: <PortalIcon fontSize="small" /> },
      { label: '我的应用', path: '/oauth-apps', keywords: 'oauth client 应用 授权码', icon: <AppsIcon fontSize="small" /> },
      { label: '个人中心', path: '/profile', keywords: 'profile passkey 密码 通行密钥 资料 第三方账号', icon: <ProfileIcon fontSize="small" /> },
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
  const [logoError, setLogoError] = useState(false);
  const [announcementDismissed, setAnnouncementDismissed] = useState(false);

  const { user, roles, isAdmin, domains, currentDomain, switchDomain, logout } = useAuth();
  const { siteInfo } = useSite();
  const location = useLocation();
  const navigate = useNavigate();

  const isSuperAdmin = useMemo(() => (roles['openiam'] || []).includes('super_admin'), [roles]);
  const navSections = useMemo(() => {
    const base = isAdmin ? adminNavSections : userNavSections;
    return base
      .map((sec) => ({ ...sec, items: sec.items.filter((i) => !i.platformOnly || isSuperAdmin) }))
      .filter((sec) => sec.items.length > 0);
  }, [isAdmin, isSuperAdmin]);
  const allNavItems = useMemo(() => navSections.flatMap((s) => s.items), [navSections]);
  const radius = Number(theme.shape.borderRadius);

  const handleLogout = async () => {
    setAnchorEl(null);
    setMobileOpen(false);
    await logout();
    navigate('/login');
  };

  const handleGoProfile = () => {
    setAnchorEl(null);
    setMobileOpen(false);
    navigate('/profile');
  };

  const initialChar = (user?.display_name || user?.username || 'U').slice(0, 1).toUpperCase();
  const showDomainSelector = isAdmin || domains.length > 1;

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
      <Box
        sx={{ px: 2.5, py: 2, display: 'flex', alignItems: 'center', gap: 1.5, cursor: 'pointer' }}
        onClick={() => {
          navigate('/');
          setMobileOpen(false);
        }}
      >
        {siteInfo.logo_url && !logoError ? (
          <Box
            component="img"
            src={siteInfo.logo_url}
            alt={siteInfo.name}
            onError={() => setLogoError(true)}
            sx={{
              width: 36,
              height: 36,
              borderRadius: `${Math.max(4, radius)}px`,
              objectFit: 'contain',
              flexShrink: 0,
            }}
          />
        ) : (
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
              flexShrink: 0,
              boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.28)}`,
            }}
          >
            <ShieldIcon fontSize="small" />
          </Box>
        )}
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle1" fontWeight={700} lineHeight={1.2} noWrap>
            {siteInfo.name || 'OpenIAM'}
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap display="block">
            {isAdmin ? '管理控制台' : '用户工作台'}
          </Typography>
        </Box>
      </Box>

      {/* 导航菜单 */}
      <Box sx={{ flex: 1, overflowY: 'auto', px: 1.5, py: 1 }}>
        {navSections.map((sec) => (
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

      {/* 底部极简状态与用户操作栏 */}
      <Divider />
      <Box sx={{ px: 1.25, py: 1 }}>
        {isAdmin && (
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            sx={{ px: 1, pb: 0.75 }}
          >
            <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
              <Box
                sx={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  bgcolor: 'success.main',
                  flexShrink: 0,
                }}
              />
              <Typography variant="caption" color="text.secondary" noWrap>
                域 · <Box component="span" sx={{ color: 'text.primary', fontWeight: 600 }}>{currentDomain}</Box>
              </Typography>
            </Stack>
          </Stack>
        )}

        <Stack direction="row" spacing={0.5} alignItems="center">
          <Tooltip title="进入个人中心">
            <Box
              onClick={handleGoProfile}
              sx={{
                flex: 1,
                minWidth: 0,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
                px: 1,
                py: 0.75,
                borderRadius: `${radius}px`,
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
                '&:hover': {
                  bgcolor: alpha(theme.palette.text.primary, 0.05),
                },
              }}
            >
              <Avatar
                src={user?.avatar_url || undefined}
                sx={{ width: 28, height: 28, bgcolor: 'primary.main', fontSize: '0.78rem', fontWeight: 700, flexShrink: 0 }}
              >
                {initialChar}
              </Avatar>
              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography variant="body2" fontWeight={600} lineHeight={1.25} noWrap>
                  {user?.display_name || user?.username}
                </Typography>
                <Typography variant="caption" color="text.secondary" lineHeight={1.2} noWrap display="block">
                  {user?.email}
                </Typography>
              </Box>
            </Box>
          </Tooltip>

          <Tooltip title="退出登录">
            <IconButton
              size="small"
              onClick={handleLogout}
              aria-label="退出登录"
              sx={{
                color: 'text.secondary',
                flexShrink: 0,
                '&:hover': {
                  color: 'error.main',
                  bgcolor: alpha(theme.palette.error.main, 0.08),
                },
              }}
            >
              <LogoutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
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
        <Toolbar sx={{ gap: { xs: 0.75, sm: 1.5 }, minHeight: '60px !important', px: { xs: 1.5, sm: 2.5 } }}>
          <IconButton
            edge="start"
            onClick={() => setMobileOpen(!mobileOpen)}
            sx={{ display: { md: 'none' }, flexShrink: 0 }}
            aria-label="打开导航菜单"
          >
            <MenuIcon />
          </IconButton>

          {/* 移动端顶部站点名称 */}
          <Typography
            variant="subtitle1"
            fontWeight={700}
            noWrap
            sx={{ display: { xs: 'block', sm: 'none' }, minWidth: 0, flexShrink: 1 }}
          >
            {siteInfo.name || 'OpenIAM'}
          </Typography>

          {/* 全局快捷搜索（桌面端与平板显示，避免移动端挤压右侧头像与退出菜单） */}
          <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
            <motion.div
              animate={{ width: searchFocused ? 300 : 210 }}
              transition={
                motionScale === 0
                  ? { duration: 0 }
                  : { type: 'spring', stiffness: 360 / motionScale, damping: 30 }
              }
              style={{ maxWidth: '38vw' }}
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
          </Box>

          {/* 业务域选择器（移动端自适应缩小） */}
          {showDomainSelector && (
            <FormControl size="small" sx={{ minWidth: { xs: 96, sm: 160 }, maxWidth: { xs: 132, sm: 220 } }}>
              <Select
                value={currentDomain}
                onChange={(e) => switchDomain(e.target.value)}
                sx={{
                  fontSize: '0.82rem',
                  height: 34,
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
          )}

          <Box sx={{ flexGrow: 1 }} />

          {/* 右侧固定操作区：主题 + 深浅色 + 用户头像菜单 */}
          <Stack direction="row" spacing={{ xs: 0.25, sm: 0.75 }} alignItems="center" sx={{ flexShrink: 0 }}>
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

            <IconButton
              onClick={(e) => setAnchorEl(e.currentTarget)}
              sx={{ p: 0.5 }}
              aria-label="账号菜单"
            >
              <Avatar
                src={user?.avatar_url || undefined}
                sx={{
                  width: 32,
                  height: 32,
                  bgcolor: 'primary.main',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                }}
              >
                {initialChar}
              </Avatar>
            </IconButton>
          </Stack>

          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
            PaperProps={{ sx: { minWidth: 210, border: 1, borderColor: 'divider' } }}
          >
            <Box sx={{ px: 2, py: 1.2 }}>
              <Typography variant="subtitle2" noWrap>
                {user?.display_name || user?.username}
              </Typography>
              <Typography variant="caption" color="text.secondary" noWrap display="block">
                {user?.email}
              </Typography>
            </Box>
            <Divider />
            <MenuItem onClick={handleGoProfile}>
              <ListItemIcon>
                <ProfileIcon fontSize="small" />
              </ListItemIcon>
              个人中心
            </MenuItem>
            <MenuItem onClick={handleLogout} sx={{ color: 'error.main' }}>
              <ListItemIcon sx={{ color: 'inherit' }}>
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

      {/* 主内容区域（带全局公告与路由过渡动画） */}
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
        {siteInfo.announcement_enabled && siteInfo.announcement_content && !announcementDismissed && (
          <Alert
            severity={siteInfo.announcement_type || 'info'}
            onClose={() => setAnnouncementDismissed(true)}
            sx={{ mb: 2.5 }}
          >
            {siteInfo.announcement_title && <AlertTitle>{siteInfo.announcement_title}</AlertTitle>}
            {siteInfo.announcement_content}
          </Alert>
        )}

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
