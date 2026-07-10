import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';

// The Chromium manifest is the single source of truth. Both targets build from
// it so @crxjs discovers the same entry points; Firefox-specific manifest
// differences are applied afterwards by scripts/postbuild-firefox.mjs. The build
// mode only selects the output directory:
//   vite build                 → dist/chrome  (default; also used by Edge)
//   vite build --mode firefox  → dist/firefox
// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    crx({ manifest }),
  ],
  build: {
    sourcemap: true,
    outDir: mode === 'firefox' ? 'dist/firefox' : 'dist/chrome',
  },
}));
