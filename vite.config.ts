import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    crx({ manifest }),
  ],
  build: {
    rollupOptions: {
      input: {
        // crxjs handles popup/background from the manifest; panel.html must be
        // added explicitly because it is only referenced as a string in devtools.ts
        'devtools-panel': 'src/devtools/panel.html',
      },
    },
    sourcemap: true,
  },
});
