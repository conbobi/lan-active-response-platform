import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // 👇 THÊM DÒNG NÀY VÀO ĐÂY 👇
    allowedHosts: ['edr.alwayready.id.vn', 'localhost'],

    proxy: {
      '/api': {
        target: 'http://localhost:8005',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'ws://localhost:8005',
        ws: true,
      },
    },
  },
})