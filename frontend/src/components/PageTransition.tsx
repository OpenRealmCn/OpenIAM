import React from 'react';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import { motion } from 'framer-motion';
import { MOTION_SPEED_SCALE, useThemeStore } from '../store/themeStore';

interface PageTransitionProps {
  children: React.ReactNode;
}

export const PageTransition: React.FC<PageTransitionProps> = ({ children }) => {
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  if (scale === 0) {
    return <>{children}</>;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.2 * scale, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
};

interface AnimatedRefreshIconProps {
  spinning?: boolean;
  spinCount?: number;
}

export const AnimatedRefreshIcon: React.FC<AnimatedRefreshIconProps> = ({ spinning = false, spinCount = 0 }) => {
  const motionSpeed = useThemeStore((s) => s.motionSpeed);
  const scale = MOTION_SPEED_SCALE[motionSpeed] ?? 1;

  if (scale === 0) {
    return <RefreshIcon fontSize="small" />;
  }

  return (
    <motion.span
      style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
      animate={spinning ? { rotate: 360 } : { rotate: spinCount * 360 }}
      transition={
        spinning
          ? { repeat: Infinity, duration: 0.85 * scale, ease: 'linear' }
          : { duration: 0.45 * scale, ease: [0.22, 1, 0.36, 1] }
      }
    >
      <RefreshIcon fontSize="small" />
    </motion.span>
  );
};
