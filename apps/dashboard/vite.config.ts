import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const actisMode = process.env.VITE_ACTIS_MODE || env.VITE_ACTIS_MODE || (mode === 'demo' ? 'demo' : '')
  const apiUrl = process.env.VITE_ACTIS_API_URL || env.VITE_ACTIS_API_URL || 'http://127.0.0.1:8000'
  const orgId = process.env.VITE_ACTIS_ORGANIZATION_ID || env.VITE_ACTIS_ORGANIZATION_ID || 'org-acme-devices'

  return {
    plugins: [react()],
    define: {
      'import.meta.env.VITE_ACTIS_MODE': JSON.stringify(actisMode),
      'import.meta.env.VITE_ACTIS_API_URL': JSON.stringify(apiUrl),
      'import.meta.env.VITE_ACTIS_ORGANIZATION_ID': JSON.stringify(orgId),
    },
    server: {
      port: 4173,
      proxy: {
        '/v1': {
          target: apiUrl,
          changeOrigin: true,
        },
      },
    },
    preview: {
      port: 4173,
    },
  }
})
