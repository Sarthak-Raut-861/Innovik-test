import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The backend origin the dev server proxies to. In Docker Compose this is the
// `backend` service; for local development it defaults to localhost:8000.
// The browser only ever talks to relative URLs — never directly to the backend.
const BACKEND = process.env.VITE_PROXY_TARGET || 'http://localhost:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: Number(process.env.PORT || 5173),
    strictPort: false,
    // Allow any host so the app can be served behind a preview/tunnel proxy.
    allowedHosts: true as unknown as string[],
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true, ws: true },
      '/v1': { target: BACKEND, changeOrigin: true },
      '/docs': { target: BACKEND, changeOrigin: true },
      '/openapi.json': { target: BACKEND, changeOrigin: true },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: Number(process.env.PORT || 4173),
    allowedHosts: true as unknown as string[],
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true, ws: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
