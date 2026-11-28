import React from 'react';
import { Alert, Box, Button, Typography } from '@mui/material';
import { LockOutlined as FenceIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { AdminTier } from '../types/api';

interface CapabilityGuardProps {
  cap?: string;
  tiers?: AdminTier[];
  children: React.ReactNode;
}

// 管理员分级与操作围栏：按平台超管、域管理员、安全审计员等真实权限控制路由与功能模块访问
export const CapabilityGuard: React.FC<CapabilityGuardProps> = ({ cap, tiers, children }) => {
  const { adminTier, hasCap } = useAuth();
  const navigate = useNavigate();

  const tierAllowed = !tiers || tiers.includes(adminTier);
  const capAllowed = !cap || hasCap(cap);

  if (!tierAllowed || !capAllowed) {
    return (
      <Box sx={{ py: 8, textAlign: 'center', maxWidth: 460, mx: 'auto' }}>
        <FenceIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1.5 }} />
        <Typography variant="h6" fontWeight={700} mb={1}>
          没有访问权限
        </Typography>
        <Alert severity="info" sx={{ textAlign: 'left', mb: 2.5 }}>
          你当前的身份是「{adminTier === 'domain_admin' ? '域管理员' : adminTier === 'auditor' ? '审计员' : '普通用户'}」，无权访问此页面。如需访问，请联系管理员分配权限。
        </Alert>
        <Button variant="contained" onClick={() => navigate('/')}>
          返回首页
        </Button>
      </Box>
    );
  }

  return <>{children}</>;
};
