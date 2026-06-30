/**
 * Generates minimal 1×1 transparent PNG placeholder icon files.
 * Run once with: node scripts/generate-icons.mjs
 *
 * Replace the files in public/icons/ with real artwork before publishing.
 */
import { writeFileSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const iconsDir = join(__dirname, '..', 'public', 'icons');

mkdirSync(iconsDir, { recursive: true });

// Minimal valid 1×1 transparent PNG (RGBA, no interlacing)
const PLACEHOLDER_1X1_PNG =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

const sizes = [16, 32, 48, 128];

for (const size of sizes) {
  const buf = Buffer.from(PLACEHOLDER_1X1_PNG, 'base64');
  // File names must match the icons referenced in manifest.json (`<size>px.png`).
  const dest = join(iconsDir, `${size}px.png`);
  writeFileSync(dest, buf);
  console.log(`✓ public/icons/${size}px.png — placeholder created`);
}

console.log('\nReplace these files with real artwork before publishing.');
