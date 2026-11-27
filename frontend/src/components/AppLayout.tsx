import React, { useState } from 'react';
import {
  AppBar,
  Avatar,
  Box,
  Chip,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Select,
  Toolbar,
  Tooltip,
  Typography,
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
  People as PeopleIcon,
  Security as RoleIcon,
  VerifiedUser as ShieldIcon,
  SystemUpdateAlt as VersionIcon,
} from '@mui/icons-material';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const DRAWER_WIDTH = 252;

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const navSections: { title: string; items: NavItem[] }[] = [
  {
    title: '概览',
    items: [{ label: '安全仪表盘', path: '/', icon: <DashboardIcon fontSize="small" /> }],
  },
  {
    title: '身份与访问控制',
    items: [
      { label: '用户管理', path: '/users', icon: <PeopleIcon fontSize="small" /> },
      { label: '域 / 租户管理', path: '/domains', icon: <DomainIcon fontSize="small" /> },
      { label: '角色管理', path: '/roles', icon: <RoleIcon fontSize="small" /> },
      { label: '权限与 Casbin 策略', path: '/permissions', icon: <PolicyIcon fontSize="small" /> },
    ],
  },
  {
    title: 'OAuth 联合与开放能力',
    items: [
      { label: 'OAuth 应用接入', path: '/oauth-apps', icon: <AppsIcon fontSize="small" /> },
      { label: '联合登录插件', path: '/identity-providers', icon: <ProviderIcon fontSize="small" /> },
    ],
  },
  {
    title: '审计与系统运维',
    items: [
      { label: '安全审计日志', path: '/audit-logs', icon: <AuditIcon fontSize="small" /> },
      { label: '版本与数据库升级', path: '/system-version', icon: <VersionIcon fontSize="small" /> },
    ],
  },
];

interface AppLayoutProps {
  mode: 'light' | 'dark';
  onToggleMode: () => void;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ mode, onToggleMode }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { user, domains, currentDomain, switchDomain, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    setAnchorEl(null);
    await logout();
    navigate('/login');
  };

  const drawerContent = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Box sx={{ px: 2.5, py: 2.2, display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: 2,
            bgcolor: 'primary.main',
            color: 'primary.contrastText',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
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
      <Divider />

      <Box sx={{ flex: 1, overflowY: 'auto', px: 1.5, py: 1.5 }}>
        {navSections.map((sec) => (
          <Box key={sec.title} sx={{ mb: 2 }}>
            <Typography
              variant="overline"
              color="text.secondary"
              sx={{ px: 1.5, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em' }}
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
                      borderRadius: 2,
                      mb: 0.4,
                      py: 0.9,
                      '&.Mui-selected': {
                        bgcolor: 'primary.main',
                        color: 'primary.contrastText',
                        '& .MuiListItemIcon-root': { color: 'primary.contrastText' },
                        '&:hover': { bgcolor: 'primary.dark' },
                      },
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 34 }}>{item.icon}</ListItemIcon>
                    <ListItemText
                      primary={item.label}
                      primaryTypographyProps={{ fontSize: '0.875rem', fontWeight: selected ? 600 : 500 }}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          </Box>
        ))}
      </Box>

      <Divider />
      <Box sx={{ p: 2 }}>
        <Chip size="small" color="primary" variant="outlined" label={`当前域: ${currentDomain}`} sx={{ width: '100%' }} />
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      <AppBar
        position="fixed"
        elevation={0}
        color="inherit"
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { md: `${DRAWER_WIDTH}px` },
          borderBottom: 1,
          borderColor: 'divider',
          bgcolor: 'background.paper',
        }}
      >
        <Toolbar sx={{ gap: 2 }}>
          <IconButton edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ display: { md: 'none' } }}>
            <MenuIcon />
          </IconButton>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" color="text.secondary" sx={{ display: { xs: 'none', sm: 'block' } }}>
              操作域上下文:
            </Typography>
            <FormControl size="small" sx={{ minWidth: 180 }}>
              <Select
                value={currentDomain}
                onChange={(e) => switchDomain(e.target.value)}
                sx={{ fontSize: '0.875rem', height: 36 }}
              >
                {domains.length === 0 ? (
                  <MenuItem value="openiam">openiam (核心域)</MenuItem>
                ) : (
                  domains.map((d) => (
                    <MenuItem key={d.code} value={d.code}>
                      {d.code} · {d.name}
                    </MenuItem>
                  ))
                )}
              </Select>
            </FormControl>
          </Box>

          <Box sx={{ flexGrow: 1 }} />

          <Tooltip title={mode === 'light' ? '切换深色模式' : '切换浅色模式'}>
            <IconButton onClick={onToggleMode} size="small">
              {mode === 'light' ? <DarkIcon fontSize="small" /> : <LightIcon fontSize="small" />}
            </IconButton>
          </Tooltip>

          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} sx={{ p: 0.5 }}>
            <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main', fontSize: '0.875rem' }}>
              {(user?.display_name || user?.username || 'A').slice(0, 1).toUpperCase()}
            </Avatar>
          </IconButton>
          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
            <Box sx={{ px: 2, py: 1 }}>
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

      <Box component="nav" sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
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

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3 },
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          mt: '64px',
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
};
