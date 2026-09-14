import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: mode === 'demo' ? {
    'import.meta.env.VITE_ACTIS_MODE': JSON.stringify('demo'),
  } : undefined,
  server: {
    port: 4173,
  },
  preview: {
    port: 4173,
  },
}))
