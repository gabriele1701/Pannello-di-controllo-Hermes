import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In sviluppo il frontend gira su :5173 e le chiamate /api vengono inoltrate
// a uvicorn su :8000. In produzione non c'e' proxy: FastAPI serve il build
// dalla stessa origine, quindi /api e' una chiamata relativa e CORS non
// entra mai in gioco.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
