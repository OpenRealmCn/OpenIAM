import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_BACKEND_URL || 'http://localhost:8080';

  return {
    plugins: [react()],
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
        },
        '/.well-known': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
