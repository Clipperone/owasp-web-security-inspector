/**
 * Packages the built extensions into store-ready zips under artifacts/.
 *
 *   dist/chrome  → owasp-web-security-inspector-<version>-chrome.zip
 *   dist/chrome  → owasp-web-security-inspector-<version>-edge.zip   (same Chromium build)
 *   dist/firefox → owasp-web-security-inspector-<version>-firefox.zip
 *
 * Run after `npm run build:all`. The version is read from package.json and must
 * match manifest.json (the single source of truth enforced by release.mjs).
 */
import AdmZip from 'adm-zip';
import { readFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function readJson(relativePath) {
  return JSON.parse(readFileSync(join(root, relativePath), 'utf8'));
}

const pkg = readJson('package.json');
const manifest = readJson('manifest.json');

if (pkg.version !== manifest.version) {
  throw new Error(`Version mismatch: package.json is ${pkg.version} but manifest.json is ${manifest.version}.`);
}

const version = pkg.version;
const artifactsDir = join(root, 'artifacts');
mkdirSync(artifactsDir, { recursive: true });

const targets = [
  { name: 'chrome', dir: 'dist/chrome' },
  { name: 'edge', dir: 'dist/chrome' }, // Edge is Chromium — same artifact, separate store upload
  { name: 'firefox', dir: 'dist/firefox' },
];

for (const target of targets) {
  const sourceDir = join(root, target.dir);
  if (!existsSync(sourceDir)) {
    throw new Error(`Missing build output "${target.dir}". Run "npm run build:all" first.`);
  }
  const outPath = join(artifactsDir, `owasp-web-security-inspector-${version}-${target.name}.zip`);
  if (existsSync(outPath)) rmSync(outPath);

  const zip = new AdmZip();
  // addLocalFolder places files at the zip root (manifest.json at top level),
  // which is what both the Chrome Web Store and AMO expect.
  zip.addLocalFolder(sourceDir);
  zip.writeZip(outPath);
  console.log(`Wrote ${outPath}`);
}

console.log(`Packaged version ${version} for ${targets.map(t => t.name).join(', ')}.`);
