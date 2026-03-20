import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  define: {
    'import.meta.env.VITE_API_URL': JSON.stringify(import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000')
  },
  server: {
    host: '0.0.0.0',    // Force IPv4 - fixes ERR_CONNECTION_REFUSED on Windows
    port: 5173,
    strictPort: true,   // Fail if port in use instead of silently switching
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
  }
})
