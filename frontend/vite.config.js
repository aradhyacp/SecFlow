import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    open: true,
    proxy: {
      '/api/web-analyzer': {
        target: 'http://localhost:5001',
        changeOrigin: true,
      },
      '/api/steg-analyzer': {
        target: 'http://localhost:5002',
        changeOrigin: true,
      },
      '/api/Recon-Analyzer': {
        target: 'http://localhost:5003',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/Recon-Analyzer/, '/api/Recon-Analyzer')
      },
      '/api/malware-analyzer': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      }
    }
  }
})
