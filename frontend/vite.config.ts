import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_BACKEND_URL || 'http://localhost:8080';

  return {
    plugins: [react()],
    build: {
      rollupOptions: {
        output: {
          // 页面按路由懒加载。React 与 MUI 仍会进首屏，单独成块后入口不再超过 500 KB。
          // 表格、图表、日期选择器随具体页面加载，不放进这个公共块。
          manualChunks(id) {
            const path = id.split('\\').join('/');
            if (!path.includes('node_modules')) return;
            if (path.includes('@mui/x-')) return;
            if (
              path.includes('node_modules/react/') ||
              path.includes('node_modules/react-dom/') ||
              path.includes('node_modules/react-router') ||
              path.includes('node_modules/scheduler/')
            ) {
              return 'react';
            }
            if (path.includes('framer-motion')) return 'motion';
            if (
              path.includes('@mui/material') ||
              path.includes('@mui/system') ||
              path.includes('@mui/utils') ||
              path.includes('@emotion/')
            ) {
              return 'mui';
            }
          },
        },
      },
    },
    server: {
      port: Number(env.VITE_DEV_PORT || 5173),
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
        },
        '/oauth2': {
          target: backendTarget,
          changeOrigin: true,
          bypass(req) {
            if (req.url?.startsWith('/oauth2/consent')) {
              return '/index.html';
            }
          },
        },
        '/.well-known': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
