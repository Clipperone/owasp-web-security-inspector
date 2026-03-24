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
  StorageEntry,
  StorageScanResult,
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

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    _sender,
    sendResponse: (response: ExtensionResponse<{ entries: number }>) => void,
  ) => {
    if (message.type !== 'RUN_STORAGE_SCAN') {
      return false;
    }

    void (async () => {
      const result = await runScan();
      if (result) {
        sendResponse({
          success: true,
          data: { entries: result.entries.length },
        });
        return;
      }

      sendResponse({ success: false, error: 'Storage scan failed.' });
    })();

    return true;
  },
);

/**
 * Schedule the scan during a browser idle period so it never competes with
 * the page's own scripts. Falls back to `setTimeout` in environments that
 * do not expose `requestIdleCallback` (e.g. some WebExtension polyfills).
 */
if (typeof requestIdleCallback === 'function') {
  requestIdleCallback(() => { void runScan(); }, { timeout: 3000 });
} else {
  setTimeout(() => { void runScan(); }, 200);
}
