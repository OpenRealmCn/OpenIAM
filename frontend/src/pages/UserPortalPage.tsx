import React, { useEffect, useState } from 'react';
import {
  alpha,
  Avatar,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Grid2 as Grid,
  Stack,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Apps as AppsIcon,
  ArrowForward as ArrowIcon,
  Dashboard as AdminIcon,
  Fingerprint as PasskeyIcon,
  Link as LinkIcon,
  Lock as PasswordIcon,
  ManageAccounts as ProfileIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useSite } from '../context/SiteContext';

export const UserPortalPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { user, isAdmin, hasPassword, passkeyCount, identities } = useAuth();
  const { siteInfo } = useSite();
  const [myAppsCount, setMyAppsCount] = useState<number>(0);

  useEffect(() => {
    api.myOAuthClients
      .list()
      .then((list) => setMyAppsCount(Array.isArray(list) ? list.length : 0))
      .catch(() => setMyAppsCount(0));
  }, []);

  const securityCards = [
    {
      title: '登录密码',
      value: hasPassword ? '已设置' : '未设置',
      chipColor: hasPassword ? ('success' as const) : ('warning' as const),
      icon: <PasswordIcon />,
      color: theme.palette.primary.main,
      action: () => navigate('/profile?tab=security'),
    },
    {
      title: '通行密钥',
      value: `${passkeyCount} 个`,
      chipColor: passkeyCount > 0 ? ('success' as const) : ('default' as const),
      icon: <PasskeyIcon />,
      color: theme.palette.secondary.main,
      action: () => navigate('/profile?tab=security'),
    },
    {
      title: '第三方账号',
      value: `${identities.length} 个已绑定`,
      chipColor: identities.length > 0 ? ('info' as const) : ('default' as const),
      icon: <LinkIcon />,
      color: theme.palette.info.main,
      action: () => navigate('/profile?tab=oauth'),
    },
    {
      title: '我的应用',
      value: `${myAppsCount} 个`,
      chipColor: 'primary' as const,
      icon: <AppsIcon />,
      color: theme.palette.success.main,
      action: () => navigate('/oauth-apps'),
    },
  ];

  const initialChar = (user?.display_name || user?.username || 'U').slice(0, 1).toUpperCase();

  return (
    <Box>
      {/* 欢迎横幅 */}
      <Card
        sx={{
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.12)} 0%, ${alpha(theme.palette.secondary.main, 0.08)} 100%)`,
        }}
      >
        <CardContent sx={{ p: { xs: 2.5, sm: 3.5 } }}>
          <Stack
            direction={{ xs: 'column', sm: 'row' }}
            spacing={2}
            alignItems={{ xs: 'flex-start', sm: 'center' }}
            justifyContent="space-between"
          >
            <Stack direction="row" spacing={2} alignItems="center">
              <Avatar
                src={user?.avatar_url || undefined}
                sx={{
                  width: 58,
                  height: 58,
                  bgcolor: 'primary.main',
                  fontSize: '1.35rem',
                  fontWeight: 700,
                }}
              >
                {initialChar}
              </Avatar>
              <Box>
                <Typography variant="h5" fontWeight={700}>
                  你好，{user?.display_name || user?.username}
                </Typography>
                <Typography variant="body2" color="text.secondary" mt={0.4}>
                  欢迎使用 {siteInfo.name} 个人工作台，在这里管理您的账号安全、通行密钥与个人应用
                </Typography>
              </Box>
            </Stack>

            <Stack direction="row" spacing={1.2}>
              {isAdmin && (
                <Button
                  variant="outlined"
                  startIcon={<AdminIcon />}
                  onClick={() => navigate('/')}
                >
                  管理概览
                </Button>
              )}
              <Button
                variant="contained"
                startIcon={<ProfileIcon />}
                onClick={() => navigate('/profile')}
              >
                管理个人资料
              </Button>
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      {/* 安全与资源状态卡片 */}
      <Grid container spacing={2.5} mb={3}>
        {securityCards.map((item) => (
          <Grid key={item.title} size={{ xs: 12, sm: 6, md: 3 }}>
            <Card sx={{ height: '100%' }}>
              <CardActionArea onClick={item.action} sx={{ height: '100%' }}>
                <CardContent>
                  <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1.5}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 2,
                        bgcolor: alpha(item.color, 0.12),
                        color: item.color,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      {item.icon}
                    </Box>
                    <Chip size="small" color={item.chipColor} label={item.value} />
                  </Stack>
                  <Typography variant="subtitle2" fontWeight={600}>
                    {item.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    点击前往管理 →
                  </Typography>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* 快捷入口 */}
      <Grid container spacing={2.5}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Stack direction="row" spacing={1.5} alignItems="center" mb={1.5}>
                <ProfileIcon color="primary" />
                <Typography variant="h6" fontWeight={600}>
                  个人中心与账号安全
                </Typography>
              </Stack>
              <Typography variant="body2" color="text.secondary" mb={2.5}>
                修改显示名称与头像、更新登录密码、绑定设备通行密钥（Passkey）以及关联第三方 OAuth 账号。
              </Typography>
              <Stack direction="row" spacing={1.2} flexWrap="wrap" useFlexGap>
                <Button variant="contained" size="small" endIcon={<ArrowIcon />} onClick={() => navigate('/profile')}>
                  进入个人中心
                </Button>
                <Button variant="outlined" size="small" onClick={() => navigate('/profile?tab=security')}>
                  绑定通行密钥
                </Button>
                <Button variant="outlined" size="small" onClick={() => navigate('/profile?tab=oauth')}>
                  第三方账号
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Stack direction="row" spacing={1.5} alignItems="center" mb={1.5}>
                <AppsIcon color="primary" />
                <Typography variant="h6" fontWeight={600}>
                  我的 OAuth 应用
                </Typography>
              </Stack>
              <Typography variant="body2" color="text.secondary" mb={2.5}>
                创建并管理属于您自己的 OAuth2 / OIDC 应用，轮换应用密钥或生成一次性授权码用于应用授权接入。
              </Typography>
              <Button variant="contained" size="small" endIcon={<ArrowIcon />} onClick={() => navigate('/oauth-apps')}>
                管理我的应用
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};
