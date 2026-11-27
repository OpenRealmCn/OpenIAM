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
  Popover,
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
  Check as CheckIcon,
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
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { THEME_PRESETS, ThemePresetKey } from '../theme/theme';

const DRAWER_WIDTH = 248;

interface NavItem {
  label: string;
  path: string;
  keywords: string;
  icon: React.ReactNode;
}

const navSections: { title: string; items: NavItem[] }[] = [
  {
    title: '概览',
    items: [{ label: '安全仪表盘', path: '/', keywords: 'dashboard overview 统计 图表', icon: <DashboardIcon fontSize="small" /> }],
  },
  {
    title: '身份与访问控制',
    items: [
      { label: '用户管理', path: '/users', keywords: 'users 账号 密码 角色', icon: <PeopleIcon fontSize="small" /> },
      { label: '域 / 租户管理', path: '/domains', keywords: 'domains tenant 多租户 业务域', icon: <DomainIcon fontSize="small" /> },
      { label: '角色管理', path: '/roles', keywords: 'roles rbac 权限分配', icon: <RoleIcon fontSize="small" /> },
      { label: '权限与 Casbin 策略', path: '/permissions', keywords: 'permissions casbin policy tree 权限树', icon: <PolicyIcon fontSize="small" /> },
    ],
  },
  {
    title: 'OAuth 联合与开放能力',
    items: [
      { label: 'OAuth 应用接入', path: '/oauth-apps', keywords: 'oauth client oidc sso 应用', icon: <AppsIcon fontSize="small" /> },
      { label: '联合登录插件', path: '/identity-providers', keywords: 'idp github google feishu wecom 插件', icon: <ProviderIcon fontSize="small" /> },
    ],
  },
  {
    title: '审计与系统运维',
    items: [
      { label: '安全审计日志', path: '/audit-logs', keywords: 'audit logs 快照 记录', icon: <AuditIcon fontSize="small" /> },
      { label: '系统设置', path: '/system-settings', keywords: 'settings config jwt ratelimit cors 配置', icon: <SettingsIcon fontSize="small" /> },
      { label: '版本与数据库升级', path: '/system-version', keywords: 'version migration schema 升级', icon: <VersionIcon fontSize="small" /> },
    ],
  },
];

interface AppLayoutProps {
  mode: 'light' | 'dark';
  preset: ThemePresetKey;
  onToggleMode: () => void;
  onChangePreset: (preset: ThemePresetKey) => void;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ mode, preset, onToggleMode, onChangePreset }) => {
  const theme = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [paletteAnchor, setPaletteAnchor] = useState<null | HTMLElement>(null);
  const { user, domains, currentDomain, switchDomain, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const allNavItems = useMemo(() => navSections.flatMap((s) => s.items), []);

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
      {/* 品牌区（Cloudreve v4 轻盈无割裂侧栏头部） */}
      <Box sx={{ px: 2.5, py: 2, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box
          sx={{
            width: 38,
            height: 38,
            borderRadius: 2.5,
            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.3)}`,
          }}
        >
          <ShieldIcon fontSize="small" />
        </Box>
        <Box>
          <Typography variant="subtitle1" fontWeight={700} lineHeight={1.2}>
            OpenIAM
          </Typography>
          <Typography variant="caption" color="text.secondary">
            OpenRealm 身份控制中心
          </Typography>
        </Box>
      </Box>

      {/* 导航菜单（柔和胶囊选中态） */}
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
                      borderRadius: 2.5,
                      mb: 0.4,
                      py: 0.95,
                      px: 1.5,
                      transition: 'all 0.16s ease',
                      color: selected ? 'primary.main' : 'text.primary',
                      '& .MuiListItemIcon-root': {
                        minWidth: 34,
                        color: selected ? 'primary.main' : 'text.secondary',
                      },
                      '&.Mui-selected': {
                        bgcolor: alpha(theme.palette.primary.main, mode === 'dark' ? 0.16 : 0.1),
                        '&:hover': {
                          bgcolor: alpha(theme.palette.primary.main, mode === 'dark' ? 0.22 : 0.14),
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

      {/* 底部状态胶囊 */}
      <Box sx={{ p: 2 }}>
        <Box
          sx={{
            p: 1.5,
            borderRadius: 3,
            bgcolor: 'background.paper',
            border: 1,
            borderColor: 'divider',
          }}
        >
          <Typography variant="caption" color="text.secondary" display="block">
            当前业务域上下文
          </Typography>
          <Stack direction="row" alignItems="center" justifyContent="space-between" mt={0.5}>
            <Typography variant="body2" fontWeight={700} color="primary.main">
              {currentDomain}
            </Typography>
            <Chip size="small" label="MUI X" color="primary" variant="outlined" sx={{ height: 20, fontSize: '0.68rem' }} />
          </Stack>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* Cloudreve v4 风格毛玻璃顶栏 */}
      <AppBar
        position="fixed"
        elevation={0}
        color="inherit"
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { md: `${DRAWER_WIDTH}px` },
          bgcolor: alpha(theme.palette.background.default, 0.8),
          backdropFilter: 'blur(14px)',
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Toolbar sx={{ gap: 1.5, minHeight: '62px !important' }}>
          <IconButton edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ display: { md: 'none' } }}>
            <MenuIcon />
          </IconButton>

          {/* 全局快捷搜索框（类 Cloudreve v4 顶部圆角搜索条） */}
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
            sx={{ width: { xs: 170, sm: 260, lg: 320 } }}
            renderInput={(params) => (
              <TextField
                {...params}
                placeholder="快捷搜索功能模块..."
                InputProps={{
                  ...params.InputProps,
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon fontSize="small" color="action" />
                    </InputAdornment>
                  ),
                }}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 999,
                    bgcolor: 'background.paper',
                    height: 38,
                  },
                }}
              />
            )}
          />

          {/* 业务域选择器 */}
          <FormControl size="small" sx={{ minWidth: { xs: 110, sm: 175 } }}>
            <Select
              value={currentDomain}
              onChange={(e) => switchDomain(e.target.value)}
              sx={{
                fontSize: '0.84rem',
                height: 38,
                borderRadius: 999,
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

          {/* Cloudreve 风格主题色调色板 */}
          <Tooltip title="切换主题色">
            <IconButton onClick={(e) => setPaletteAnchor(e.currentTarget)} size="small">
              <PaletteIcon fontSize="small" color="primary" />
            </IconButton>
          </Tooltip>
          <Popover
            open={Boolean(paletteAnchor)}
            anchorEl={paletteAnchor}
            onClose={() => setPaletteAnchor(null)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            transformOrigin={{ vertical: 'top', horizontal: 'right' }}
            PaperProps={{ sx: { p: 2, borderRadius: 3, border: 1, borderColor: 'divider' } }}
          >
            <Typography variant="caption" color="text.secondary" fontWeight={700} display="block" mb={1.2}>
              主题预设配色
            </Typography>
            <Stack direction="row" spacing={1}>
              {THEME_PRESETS.map((p) => {
                const active = preset === p.key;
                const swatch = mode === 'dark' ? p.darkMain : p.lightMain;
                return (
                  <Tooltip key={p.key} title={p.label}>
                    <IconButton
                      size="small"
                      onClick={() => {
                        onChangePreset(p.key);
                        setPaletteAnchor(null);
                      }}
                      sx={{
                        width: 30,
                        height: 30,
                        bgcolor: swatch,
                        color: '#fff',
                        '&:hover': { bgcolor: swatch, opacity: 0.9 },
                      }}
                    >
                      {active && <CheckIcon sx={{ fontSize: 16 }} />}
                    </IconButton>
                  </Tooltip>
                );
              })}
            </Stack>
          </Popover>

          <Tooltip title={mode === 'light' ? '切换深色模式' : '切换浅色模式'}>
            <IconButton onClick={onToggleMode} size="small">
              {mode === 'light' ? <DarkIcon fontSize="small" /> : <LightIcon fontSize="small" />}
            </IconButton>
          </Tooltip>

          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} sx={{ p: 0.5 }}>
            <Avatar
              sx={{
                width: 34,
                height: 34,
                bgcolor: 'primary.main',
                fontSize: '0.875rem',
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
            PaperProps={{ sx: { minWidth: 200, borderRadius: 3, border: 1, borderColor: 'divider' } }}
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

      {/* 主内容区域 */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3 },
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          mt: '62px',
          maxWidth: '100%',
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
};
