import { fileURLToPath, URL } from 'node:url'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

// Hôte de développement mobile fourni par `tauri android dev`.
const host = process.env.TAURI_DEV_HOST

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  // Tauri attend un port fixe et affiche lui-même les erreurs Rust.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: 'ws', host, port: 1421 } : undefined,
    watch: { ignored: ['**/src-tauri/**'] },
    // Les tests comparent tokens.css à la maquette, hors de la racine.
    fs: process.env.VITEST ? { allow: ['.', '../../aidd_docs/design/vigie-design'] } : undefined,
  },
  build: {
    target: 'es2021',
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.spec.ts'],
    css: true,
  },
})
