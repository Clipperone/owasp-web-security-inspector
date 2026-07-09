/**
 * Firefox post-build manifest transform.
 *
 * The build produces a Chromium manifest in dist/firefox (via `vite build
 * --mode firefox`). This script rewrites that manifest into a Firefox MV3 one:
 *   - drop `minimum_chrome_version` (Chrome-only)
 *   - `side_panel` → `sidebar_action` (Firefox renders the same page in its sidebar)
 *   - drop the `sidePanel` permission (no such API in Firefox)
 *   - `background.service_worker` → `background.scripts` (Firefox MV3 event page)
 *   - add `browser_specific_settings.gecko` (id + strict_min_version) — required by AMO
 *   - strip Chrome-only `use_dynamic_url` from web_accessible_resources
 *
 * The transform is a pure function so it can be unit-tested; the file I/O only
 * runs when the script is invoked directly.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

/**
 * Immutable Firefox add-on identifier. Must NEVER change once published to AMO.
 * Update this to your own domain-style id or GUID before the first submission.
 */
export const GECKO_ID = 'owasp-web-security-inspector@clipperone.dev';

/**
 * Minimum Firefox version. 115 is the first release with `chrome.storage.session`,
 * which the background worker relies on, so no storage shim is needed.
 */
export const GECKO_MIN_VERSION = '115.0';

/** Pure transform: Chromium manifest object → Firefox manifest object. */
export function transformManifest(manifest) {
  const out = structuredClone(manifest);
  const name = out.name || 'OWASP Web Security Inspector';

  // Chrome-only gate.
  delete out.minimum_chrome_version;

  // Side panel → sidebar.
  if (out.side_panel && out.side_panel.default_path) {
    out.sidebar_action = {
      default_panel: out.side_panel.default_path,
      default_title: name,
      ...(out.icons ? { default_icon: out.icons } : {}),
    };
  }
  delete out.side_panel;

  // Drop the Chromium-only sidePanel permission.
  if (Array.isArray(out.permissions)) {
    out.permissions = out.permissions.filter(p => p !== 'sidePanel');
  }

  // Service worker → event-page background scripts.
  if (out.background && out.background.service_worker) {
    const worker = out.background.service_worker;
    out.background = {
      scripts: [worker],
      ...(out.background.type ? { type: out.background.type } : {}),
    };
  }

  // Firefox add-on identity (required by AMO).
  out.browser_specific_settings = {
    gecko: { id: GECKO_ID, strict_min_version: GECKO_MIN_VERSION },
  };

  // `use_dynamic_url` is a Chromium-only key that the AMO linter rejects.
  if (Array.isArray(out.web_accessible_resources)) {
    out.web_accessible_resources = out.web_accessible_resources.map(entry => {
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        const clone = { ...entry };
        delete clone.use_dynamic_url;
        return clone;
      }
      return entry;
    });
  }

  return out;
}

async function main() {
  const manifestPath = new URL('../dist/firefox/manifest.json', import.meta.url);
  const source = JSON.parse(await readFile(manifestPath, 'utf8'));
  const transformed = transformManifest(source);
  await writeFile(manifestPath, JSON.stringify(transformed, null, 2) + '\n', 'utf8');
  console.log('Rewrote dist/firefox/manifest.json for Firefox (gecko id:', GECKO_ID + ').');
}

// Only run the file I/O when invoked directly (not when imported by tests).
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch(err => {
    console.error('postbuild-firefox failed:', err);
    process.exit(1);
  });
}
