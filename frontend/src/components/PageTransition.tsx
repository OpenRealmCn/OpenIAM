import React from 'react';
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
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22 * scale, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
};
