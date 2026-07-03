/**
 * @file content/index.ts
 * @description Content script — injected into every page at document_idle.
 *
 * Responsibilities:
 *   1. Scan `localStorage` and `sessionStorage` for potential auth tokens.
 *   2. Filter entries by key name heuristics and value shape heuristics.
 *   3. Send the structured results to the background service worker via
 *      `chrome.runtime.sendMessage`, which caches them per tab for the popup.
 *
 * Security / performance constraints:
 *   - Runs in Chrome's ISOLATED world — has DOM access but cannot reach
 *     page-defined JS variables directly.
 *   - All storage access is wrapped in try/catch: cross-origin iframes throw
 *     a `SecurityError` when `localStorage` is accessed.
 *   - The scan is scheduled via `requestIdleCallback` so it never executes
 *     during the page's critical rendering path.
 *   - Values longer than MAX_VALUE_LENGTH are truncated before transmission
 *     to avoid flooding the message bus with large blobs.
 *   - No value is ever written — this script is strictly read-only.
 */

import type {
  ExtensionMessage,
  ExtensionResponse,
  ObservedPageResource,
  PageResourceObservation,
  StorageEntry,
  StorageScanResult,
  TransportDomObservation,
  TransportObservedForm,
  TokenHint,
  WebStorageArea,
} from '../types';
import { isJwt } from '../utils/jwtUtils';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Key-name substrings (case-insensitive) that suggest an entry holds an
 * authentication token. Checked with `String.includes()` — no regex overhead.
 */
const AUTH_KEY_PATTERNS: string[] = [
  'token',
  'auth',
  'jwt',
  'bearer',
  'access',
  'refresh',
  'id_token',
  'session',
  'credential',
  'apikey',
  'api_key',
];

/**
 * JWT compact serializations always start with `ey` because the header is a
 * Base64Url-encoded JSON object `{...}` — 0x7B encodes to `ey` in Base64Url.
 * This is a fast pre-filter before running the more expensive `isJwt()`.
 */
const JWT_VALUE_PREFIX = 'ey';

/**
 * Maximum character length of a stored value that will be forwarded intact.
 * Values exceeding this are truncated to avoid flooding the message channel.
 * 4096 chars is generous enough to hold even large JWT payloads.
 */
const MAX_VALUE_LENGTH = 4096;

const SENSITIVE_FIELD_PATTERNS: string[] = [
  'user',
  'username',
  'email',
  'login',
  'password',
  'pass',
  'token',
  'access',
  'refresh',
  'reset',
  'session',
  'bearer',
  'secret',
  'api',
  'key',
  'otp',
  'code',
];

const MAX_OBSERVED_HTTP_LINKS = 20;
const MAX_OBSERVED_FORMS = 12;
const MAX_OBSERVED_SCRIPTS = 40;
const MAX_OBSERVED_STYLESHEETS = 40;

/** One or more space-separated `sha(256|384|512)-<base64>` hashes. Format only. */
const SRI_INTEGRITY_RE = /^(sha(256|384|512)-[A-Za-z0-9+/=]+\s*)+$/;

// ─────────────────────────────────────────────────────────────────────────────
// Core scanning logic
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Reads all entries from a single `Storage` object and returns those that
 * match at least one token heuristic.
 *
 * @param storage - The `localStorage` or `sessionStorage` object to scan.
 * @param area    - Label used to tag each returned entry.
 */
function scanStorageArea(storage: Storage, area: WebStorageArea): StorageEntry[] {
  const entries: StorageEntry[] = [];

  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i);
    if (key === null) continue;

    const rawValue = storage.getItem(key);
    if (rawValue === null || rawValue.length === 0) continue;

    // Truncate oversized values — do this before any pattern matching so
    // we always work on a bounded string.
    const value = rawValue.length > MAX_VALUE_LENGTH
      ? rawValue.slice(0, MAX_VALUE_LENGTH)
      : rawValue;

    const hints = collectHints(key, value);
    if (hints.length === 0) continue;

    entries.push({
      area,
      key,
      value,
      hints,
      // Full JWT structural validation — more expensive, only run on candidates
      isJwt: isJwt(value),
    });
  }

  return entries;
}

/**
 * Returns the set of `TokenHint` reasons that apply to a key/value pair.
 * Returns an empty array when no heuristic matches (entry should be skipped).
 *
 * Heuristics applied in order of ascending cost:
 *   1. `key-name`  — O(n) substring search over AUTH_KEY_PATTERNS
 *   2. `ey-prefix` — O(1) prefix check on the value string
 *   3. `jwt-value` — O(n) regex check via `isJwt()` (only when ey-prefix hit)
 */
function collectHints(key: string, value: string): TokenHint[] {
  const hints: TokenHint[] = [];

  // Heuristic 1: key name contains an auth-related keyword
  const lowerKey = key.toLowerCase();
  if (AUTH_KEY_PATTERNS.some((pattern) => lowerKey.includes(pattern))) {
    hints.push('key-name');
  }

  // Heuristic 2: value starts with 'ey' — cheap JWT prefix check
  if (value.startsWith(JWT_VALUE_PREFIX)) {
    hints.push('ey-prefix');

    // Heuristic 3: value passes full JWT structural validation
    if (isJwt(value)) {
      hints.push('jwt-value');
    }
  }

  return hints;
}

/**
 * Scans both `localStorage` and `sessionStorage`.
 *
 * Each storage area access is independently wrapped in try/catch because:
 *   - Cross-origin iframes throw `SecurityError` on any storage access.
 *   - Some browsers restrict storage in private/incognito contexts.
 *   - One area failing must not abort the scan of the other.
 *
 * @returns A `StorageScanResult` ready to be sent to the background worker.
 */
function performScan(): StorageScanResult {
  const entries: StorageEntry[] = [];

  // Scan localStorage
  try {
    entries.push(...scanStorageArea(window.localStorage, 'localStorage'));
  } catch {
    // SecurityError or similar — silently skip this area
  }

  // Scan sessionStorage
  try {
    entries.push(...scanStorageArea(window.sessionStorage, 'sessionStorage'));
  } catch {
    // SecurityError or similar — silently skip this area
  }

  return {
    origin:    window.location.origin,
    scannedAt: new Date().toISOString(),
    entries,
  };
}

function isSensitiveFieldName(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0) return false;
  return SENSITIVE_FIELD_PATTERNS.some(pattern => normalized.includes(pattern));
}

function resolveUrl(candidate: string | null): string {
  if (!candidate || candidate.trim().length === 0) {
    return window.location.href;
  }

  try {
    return new URL(candidate, window.location.href).href;
  } catch {
    return candidate;
  }
}

function scanForms(): TransportObservedForm[] {
  const forms = Array.from(document.querySelectorAll('form'));

  return forms.slice(0, MAX_OBSERVED_FORMS).map((form): TransportObservedForm => {
    const action = resolveUrl(form.getAttribute('action'));
    const method = (form.getAttribute('method') || 'get').toUpperCase();
    const passwordFields = Array.from(form.querySelectorAll('input[type="password"]'));
    const fieldNames = Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
      .map(element => element.getAttribute('name') || '')
      .filter(Boolean);
    const sensitiveFieldNames = Array.from(new Set(fieldNames.filter(isSensitiveFieldName))).slice(0, 8);

    return {
      action,
      method,
      hasPasswordField: passwordFields.length > 0,
      passwordFieldCount: passwordFields.length,
      sensitiveFieldNames,
    };
  });
}

function scanAbsoluteHttpLinks(): string[] {
  const links = Array.from(document.querySelectorAll('a[href^="http://"]'));
  return Array.from(new Set(
    links
      .map(link => link.getAttribute('href') || '')
      .filter(Boolean),
  )).slice(0, MAX_OBSERVED_HTTP_LINKS);
}

function performTransportObservation(): TransportDomObservation {
  const forms = scanForms();

  return {
    pageUrl: window.location.href,
    scannedAt: new Date().toISOString(),
    absoluteHttpLinks: scanAbsoluteHttpLinks(),
    forms,
    passwordFieldCount: forms.reduce((sum, form) => sum + form.passwordFieldCount, 0),
  };
}

function observeResource(element: Element, kind: ObservedPageResource['kind'], urlAttr: string): ObservedPageResource | null {
  const rawUrl = element.getAttribute(urlAttr);
  if (!rawUrl || rawUrl.trim().length === 0) return null;

  const url = resolveUrl(rawUrl);
  let crossOrigin = false;
  try {
    crossOrigin = new URL(url).origin !== window.location.origin;
  } catch {
    crossOrigin = false;
  }

  const integrity = element.getAttribute('integrity')?.trim() ?? '';
  const hasIntegrity = integrity.length > 0;
  const crossOriginAttr = element.getAttribute('crossorigin');

  return {
    url,
    kind,
    crossOrigin,
    crossOriginAttr: crossOriginAttr ?? undefined,
    hasIntegrity,
    integrityValid: hasIntegrity ? SRI_INTEGRITY_RE.test(integrity) : undefined,
  };
}

/**
 * Scans the current document for `<script src>` and `<link rel=stylesheet>`
 * subresources so the assessment can check Subresource Integrity coverage.
 * Only same-document, at-scan-time DOM is visible; dynamically injected or
 * late-loaded resources may be missed until a re-scan.
 */
function performPageResourceObservation(): PageResourceObservation {
  const scriptElements = Array.from(document.querySelectorAll('script[src]'));
  const linkElements = Array.from(document.querySelectorAll('link[rel~="stylesheet"][href]'));

  const scripts = scriptElements
    .slice(0, MAX_OBSERVED_SCRIPTS)
    .map(element => observeResource(element, 'script', 'src'))
    .filter((resource): resource is ObservedPageResource => resource !== null);
  const stylesheets = linkElements
    .slice(0, MAX_OBSERVED_STYLESHEETS)
    .map(element => observeResource(element, 'stylesheet', 'href'))
    .filter((resource): resource is ObservedPageResource => resource !== null);

  return {
    pageUrl: window.location.href,
    scannedAt: new Date().toISOString(),
    scripts,
    stylesheets,
    truncated: scriptElements.length > MAX_OBSERVED_SCRIPTS || linkElements.length > MAX_OBSERVED_STYLESHEETS,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point — schedule scan during browser idle time
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executes the scan and forwards results to the background worker.
 *
 * Wrapped in a top-level try/catch so any unexpected error is silently
 * swallowed — the content script must never interfere with the host page.
 *
 * `chrome.runtime.sendMessage` is fire-and-forget here (no await / callback)
 * because the content script does not need the background's acknowledgement.
 * The background caches the result; the popup requests it on demand.
 */
async function runScan(): Promise<StorageScanResult | null> {
  try {
    const result = performScan();

    await chrome.runtime.sendMessage({
      type:    'STORAGE_SCAN_RESULT',
      payload: result,
    });

    return result;
  } catch {
    // Silent — content script must never crash or throw to the page
    return null;
  }
}

async function runTransportScan(): Promise<TransportDomObservation | null> {
  try {
    const result = performTransportObservation();

    await chrome.runtime.sendMessage({
      type: 'TRANSPORT_SCAN_RESULT',
      payload: result,
    });

    return result;
  } catch {
    return null;
  }
}

async function runPageResourceScan(): Promise<PageResourceObservation | null> {
  try {
    const result = performPageResourceObservation();

    await chrome.runtime.sendMessage({
      type: 'PAGE_RESOURCE_SCAN_RESULT',
      payload: result,
    });

    return result;
  } catch {
    return null;
  }
}

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    _sender,
    sendResponse: (response: ExtensionResponse<{ entries: number }>) => void,
  ) => {
    switch (message.type) {
      case 'RUN_STORAGE_SCAN':
        void (async () => {
          const result = await runScan();
          if (result) {
            sendResponse({ success: true, data: { entries: result.entries.length } });
            return;
          }
          sendResponse({ success: false, error: 'Storage scan failed.' });
        })();
        return true;

      case 'RUN_TRANSPORT_SCAN':
        void (async () => {
          const result = await runTransportScan();
          if (result) {
            sendResponse({ success: true, data: { entries: result.forms.length + result.absoluteHttpLinks.length } });
            return;
          }
          sendResponse({ success: false, error: 'Transport scan failed.' });
        })();
        return true;

      case 'RUN_PAGE_RESOURCE_SCAN':
        void (async () => {
          const result = await runPageResourceScan();
          if (result) {
            sendResponse({ success: true, data: { entries: result.scripts.length + result.stylesheets.length } });
            return;
          }
          sendResponse({ success: false, error: 'Page resource scan failed.' });
        })();
        return true;

      default:
        return false;
    }
  },
);

/**
 * Schedule the scan during a browser idle period so it never competes with
 * the page's own scripts. Falls back to `setTimeout` in environments that
 * do not expose `requestIdleCallback` (e.g. some WebExtension polyfills).
 */
if (typeof requestIdleCallback === 'function') {
  requestIdleCallback(() => {
    void runScan();
    void runTransportScan();
    void runPageResourceScan();
  }, { timeout: 3000 });
} else {
  setTimeout(() => {
    void runScan();
    void runTransportScan();
    void runPageResourceScan();
  }, 200);
}
