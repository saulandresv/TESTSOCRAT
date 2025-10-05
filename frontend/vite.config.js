import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 3000,
    hmr: {
      port: 3000
    },
    proxy: {
      '/api/v1': {
        target: 'http://backend:8000/api/v1',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/v1/, '')
      },
      '/api/certs': {
        target: 'http://backend:8000/api/certs',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/certs/, '')
      }
    }
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: undefined
      }
    }
  }
})