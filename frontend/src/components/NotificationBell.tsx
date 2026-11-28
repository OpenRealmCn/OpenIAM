import React, { useCallback, useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Popover,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  DoneAll as DoneAllIcon,
  GppMaybe as SecurityIcon,
  NotificationsNone as BellIcon,
} from '@mui/icons-material';
import dayjs from 'dayjs';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { NotificationItem } from '../types/api';

const CATEGORY_LABEL: Record<string, string> = {
  system_message: '系统消息',
  announcement: '系统公告',
  system_notice: '系统通知',
};

export const NotificationBell: React.FC = () => {
  const navigate = useNavigate();
  const { unreadNotifications, refreshUnreadCount, isAdmin } = useAuth();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [tab, setTab] = useState<string>('all');
  const [items, setItems] = useState<NotificationItem[]>([]);

  const loadList = useCallback(async () => {
    try {
      const list = await api.notifications.list(tab === 'all' ? undefined : { category: tab });
      setItems(Array.isArray(list) ? list.slice(0, 12) : []);
    } catch {
      setItems([]);
    }
  }, [tab]);

  useEffect(() => {
    if (anchorEl) {
      void loadList();
    }
  }, [anchorEl, loadList]);

  const handleMarkRead = async (item: NotificationItem) => {
    if (!item.is_read) {
      try {
        await api.notifications.markRead(item.id);
        await Promise.all([loadList(), refreshUnreadCount?.()]);
      } catch {
        // 忽略偶发请求失败，保留当前列表
      }
    }
  };

  const handleReadAll = async () => {
    try {
      await api.notifications.markAllRead();
      await Promise.all([loadList(), refreshUnreadCount?.()]);
    } catch {
      // 忽略偶发请求失败
    }
  };

  return (
    <>
      <Tooltip title="通知中心">
        <IconButton size="small" onClick={(e) => setAnchorEl(e.currentTarget)}>
          <Badge badgeContent={unreadNotifications} color="error" max={99}>
            <BellIcon fontSize="small" />
          </Badge>
        </IconButton>
      </Tooltip>

      <Popover
        open={Boolean(anchorEl)}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        PaperProps={{ sx: { width: { xs: 320, sm: 380 }, maxHeight: 480 } }}
      >
        <Box sx={{ px: 2, py: 1.2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="subtitle2" fontWeight={700}>
            通知中心
          </Typography>
          <Button size="small" startIcon={<DoneAllIcon fontSize="small" />} onClick={() => void handleReadAll()}>
            全部标为已读
          </Button>
        </Box>

        <Tabs
          value={tab}
          onChange={(_, v) => setTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ px: 1, borderBottom: 1, borderColor: 'divider', minHeight: 36 }}
        >
          <Tab value="all" label="全部" sx={{ minHeight: 36, py: 0.5 }} />
          <Tab value="system_message" label="系统消息" sx={{ minHeight: 36, py: 0.5 }} />
          <Tab value="announcement" label="系统公告" sx={{ minHeight: 36, py: 0.5 }} />
          {isAdmin && <Tab value="system_notice" label="系统通知" sx={{ minHeight: 36, py: 0.5 }} />}
        </Tabs>

        <List disablePadding sx={{ maxHeight: 320, overflowY: 'auto' }}>
          {items.length === 0 ? (
            <Box sx={{ py: 4, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                暂无通知
              </Typography>
            </Box>
          ) : (
            items.map((item, idx) => {
              const isSecurity = item.level === 'security';
              return (
                <React.Fragment key={item.id}>
                  {idx > 0 && <Divider />}
                  <ListItemButton
                    onClick={() => void handleMarkRead(item)}
                    sx={{ opacity: item.is_read ? 0.68 : 1, alignItems: 'flex-start', py: 1.2 }}
                  >
                    <ListItemText
                      primary={
                        <Stack direction="row" spacing={1} alignItems="center" mb={0.3}>
                          {isSecurity ? (
                            <Chip
                              size="small"
                              icon={<SecurityIcon sx={{ fontSize: 13 }} />}
                              label="安全提醒"
                              color="error"
                              sx={{ height: 20, fontSize: '0.68rem' }}
                            />
                          ) : (
                            <Chip
                              size="small"
                              label={CATEGORY_LABEL[item.category] || item.category}
                              color={item.level === 'error' ? 'error' : item.level === 'warning' ? 'warning' : 'default'}
                              sx={{ height: 20, fontSize: '0.68rem' }}
                            />
                          )}
                          <Typography variant="body2" fontWeight={item.is_read ? 500 : 700} noWrap sx={{ flex: 1 }}>
                            {item.title}
                          </Typography>
                        </Stack>
                      }
                      secondary={
                        <>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            display="block"
                            sx={{ mb: 0.3, whiteSpace: 'pre-line' }}
                          >
                            {item.content}
                          </Typography>
                          <Typography variant="caption" color="text.disabled">
                            {dayjs(item.created_at).format('MM-DD HH:mm')}
                          </Typography>
                        </>
                      }
                    />
                  </ListItemButton>
                </React.Fragment>
              );
            })
          )}
        </List>

        <Divider />
        <Box sx={{ p: 1, textAlign: 'center' }}>
          <Button
            size="small"
            fullWidth
            onClick={() => {
              setAnchorEl(null);
              navigate('/notifications');
            }}
          >
            {isAdmin ? '进入通知中心' : '查看全部通知'}
          </Button>
        </Box>
      </Popover>
    </>
  );
};
