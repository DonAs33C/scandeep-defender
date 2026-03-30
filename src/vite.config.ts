import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist"   // dentro la cartella src, dist sarà src/dist
  },
  plugins: [react()]
});
