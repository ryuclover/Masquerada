import react from '@vitejs/plugin-react'
import { defineConfig } from 'electron-vite'

export default defineConfig({
  main: {},
  renderer: {
    plugins: [react()]
  }
})

