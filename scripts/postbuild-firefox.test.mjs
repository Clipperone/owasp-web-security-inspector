import { describe, expect, test } from 'vitest';
import { transformManifest, GECKO_ID, GECKO_MIN_VERSION } from './postbuild-firefox.mjs';

/** A manifest shaped like the one @crxjs emits for this project. */
function builtChromiumManifest() {
  return {
    manifest_version: 3,
    name: 'OWASP Web Security Inspector',
    version: '0.5.0',
    minimum_chrome_version: '114',
    permissions: ['storage', 'cookies', 'activeTab', 'webRequest', 'sidePanel'],
    host_permissions: ['<all_urls>'],
    side_panel: { default_path: 'src/sidepanel/index.html' },
    background: { service_worker: 'service-worker-loader.js', type: 'module' },
    icons: { 16: 'icons/16px.png', 128: 'icons/128px.png' },
    web_accessible_resources: [
      { matches: ['<all_urls>'], resources: ['assets/x.js'], use_dynamic_url: true },
    ],
  };
}

describe('transformManifest (Firefox)', () => {
  const out = transformManifest(builtChromiumManifest());

  test('drops the Chrome-only minimum_chrome_version', () => {
    expect(out.minimum_chrome_version).toBeUndefined();
  });

  test('converts side_panel to sidebar_action pointing at the same page', () => {
    expect(out.side_panel).toBeUndefined();
    expect(out.sidebar_action.default_panel).toBe('src/sidepanel/index.html');
    expect(out.sidebar_action.default_title).toBe('OWASP Web Security Inspector');
    expect(out.sidebar_action.default_icon).toEqual({ 16: 'icons/16px.png', 128: 'icons/128px.png' });
  });

  test('removes the sidePanel permission but keeps the rest', () => {
    expect(out.permissions).toEqual(['storage', 'cookies', 'activeTab', 'webRequest']);
  });

  test('rewrites the background service worker as an event-page script', () => {
    expect(out.background.service_worker).toBeUndefined();
    expect(out.background.scripts).toEqual(['service-worker-loader.js']);
    expect(out.background.type).toBe('module');
  });

  test('adds the gecko settings (stable id + strict_min_version)', () => {
    expect(out.browser_specific_settings.gecko.id).toBe(GECKO_ID);
    expect(out.browser_specific_settings.gecko.strict_min_version).toBe(GECKO_MIN_VERSION);
  });

  test('strips use_dynamic_url from web_accessible_resources', () => {
    expect(out.web_accessible_resources[0].use_dynamic_url).toBeUndefined();
    expect(out.web_accessible_resources[0].resources).toEqual(['assets/x.js']);
  });

  test('does not mutate the input manifest', () => {
    const input = builtChromiumManifest();
    transformManifest(input);
    expect(input.side_panel).toBeDefined();
    expect(input.permissions).toContain('sidePanel');
  });
});
