/**
 * @file background/service-worker.ts
 * @description Background service worker — Manifest V3.
 *
 * The background never modifies requests, responses, or headers. It exposes only
 * reads and scan triggers; the sole cookie write path is user-initiated in the
 * Cookies tab, which calls chrome.cookies directly (not through this worker).
 * This worker only:
 *
 *  1. Lifecycle (onInstalled)
 *     – Seed storage with defaults on first install.
 *     – On update, remove the legacy `headerRules` key written by pre-0.5.0
 *       builds that supported request/response header rewriting.
 *
 *  2. Passive observation
 *     – Cache document/XHR response headers per tab (webRequest, non-blocking).
 *     – Record observed WebSocket handshakes per tab.
 *     – Cache content-script scan results (storage / transport / page resources).
 *
 *  3. Message router (panel ↔ background)
 *     – GET_COOKIES         – read-only bridge to chrome.cookies.getAll
 *     – GET_STORAGE_TOKENS / GET_TRANSPORT_OBSERVATIONS / GET_PAGE_RESOURCES
 *     – RUN_* scan triggers relayed to the active tab's content script
 *     – GET_TAB_HEADERS / GET_TAB_WEBSOCKETS / GET_ACTIVE_TAB_INFO
 *
 *  All errors are caught silently — the service worker must never crash.
 */

import type {
  ActiveTabInfo,
  CachedRequest,
  CookieData,
  ExtensionMessage,
  ExtensionResponse,
  ObservedWebSocket,
  PageResourceObservation,
  StorageScanResult,
  TransportDomObservation,
} from '../types';
import { DEFAULT_SETTINGS, LEGACY_STORAGE_KEYS, STORAGE_KEYS } from '../types';

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(({ reason }) => {
  // Wrap in void + silent catch — onInstalled must never propagate errors
  void (async () => {
    try {
      if (reason === 'install') {
        // First-time install: seed storage with factory defaults
        await chrome.storage.local.set({
          [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS,
        });
      } else if (reason === 'update') {
        // Upgraders from a pre-0.5.0 build may still have persisted header
        // rules. The declarativeNetRequest permission is gone, so any dynamic
        // rules stopped applying the moment the permission was dropped; we only
        // need to purge the now-orphaned storage key. (No DNR API call is
        // possible here — chrome.declarativeNetRequest is undefined without the
        // permission and would throw.)
        await chrome.storage.local.remove(LEGACY_STORAGE_KEYS.HEADER_RULES);
      }
    } catch {
      // Silent — service worker must not crash on install
    }
  })();
});

// Open the panel when the user clicks the toolbar icon.
//   - Chromium (Chrome/Edge): the sidePanel API opens the side panel on click.
//   - Firefox: there is no sidePanel API; the manifest's sidebar_action renders
//     the same page, and clicking the toolbar action toggles it via
//     browser.sidebarAction.toggle() (a user gesture, so it is allowed).
// Both paths are wrapped so a missing API never crashes the service worker.
if (chrome.sidePanel?.setPanelBehavior) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {
    // Silent — the side panel is a progressive enhancement of the toolbar action.
  });
} else if (typeof browser !== 'undefined' && browser?.sidebarAction) {
  chrome.action.onClicked.addListener(() => {
    void browser?.sidebarAction?.toggle();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Response header cache  (webRequest → chrome.storage.session per tab)
// ─────────────────────────────────────────────────────────────────────────────

const TAB_HEADERS_MAX = 10;

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return; // -1 = no associated tab (e.g. prefetch)
    void (async () => {
      try {
        const key    = `tabHeaders:${details.tabId}`;
        const stored = await chrome.storage.session.get(key);
        const prev   = (stored[key] as CachedRequest[] | undefined) ?? [];

        const entry: CachedRequest = {
          url:             details.url,
          method:          details.method,
          resourceType:    details.type,
          statusCode:      details.statusCode,
          timestamp:       Date.now(),
          responseHeaders: details.responseHeaders?.map(h => ({
            name:  h.name,
            value: h.value ?? '',
          })) ?? [],
        };

        const latestDocument = details.type === 'main_frame'
          ? entry
          : prev.find(request => request.resourceType === 'main_frame');

        const recentRequests = [
          ...(details.type === 'main_frame' ? [] : [entry]),
          ...prev.filter(request => request.resourceType !== 'main_frame'),
        ].slice(0, latestDocument ? TAB_HEADERS_MAX - 1 : TAB_HEADERS_MAX);

        const updated = latestDocument
          ? [latestDocument, ...recentRequests]
          : recentRequests;
        await chrome.storage.session.set({ [key]: updated });
      } catch { /* silent */ }
    })();

    return undefined;
  },
  { urls: ['<all_urls>'], types: ['main_frame', 'sub_frame', 'xmlhttprequest'] },
  ['responseHeaders'],
);

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket observation  (webRequest.onBeforeRequest per tab)
// ─────────────────────────────────────────────────────────────────────────────
//
// onHeadersReceived does not reliably fire for WebSocket handshakes, so the
// observable signal is onBeforeRequest with type 'websocket'. Only the handshake
// URL is visible (no frames/payloads); connections opened before this listener
// was registered are missed until a reload.

const TAB_WEBSOCKETS_MAX = 20;

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== 'websocket') return;
    void (async () => {
      try {
        const key = `tabWebSockets:${details.tabId}`;
        const stored = await chrome.storage.session.get(key);
        const prev = (stored[key] as ObservedWebSocket[] | undefined) ?? [];
        const entry: ObservedWebSocket = {
          url: details.url,
          secure: details.url.startsWith('wss://'),
          timestamp: Date.now(),
        };
        const updated = [entry, ...prev.filter(ws => ws.url !== entry.url)].slice(0, TAB_WEBSOCKETS_MAX);
        await chrome.storage.session.set({ [key]: updated });
      } catch { /* silent */ }
    })();

    return undefined;
  },
  { urls: ['<all_urls>'], types: ['websocket'] },
);

// ─────────────────────────────────────────────────────────────────────────────
// Message router
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    sender,
    sendResponse: (response: ExtensionResponse) => void,
  ) => {
    // Return `true` to keep the message channel open for async responses
    handleMessage(message, sender)
      .then(sendResponse)
      .catch((err: unknown) => {
        // Silent catch — never let an unhandled rejection crash the worker
        const error = err instanceof Error ? err.message : String(err);
        sendResponse({ success: false, error });
      });

    return true;
  },
);

/**
 * Dispatches an incoming message to the appropriate handler.
 * Every branch must return an `ExtensionResponse` — never throw.
 */
async function handleMessage(
  message: ExtensionMessage,
  sender: chrome.runtime.MessageSender,
): Promise<ExtensionResponse> {
  try {
    switch (message.type) {

      // ── Cookie bridge (read) ────────────────────────────────────────────
      // The panel reads cookies through the background. There is no cookie
      // *write* bridge: the Cookies tab performs user-initiated edits by calling
      // chrome.cookies.set/remove directly, so no mutating message type exists.

      case 'GET_COOKIES': {
        const url     = message.payload as string;
        const cookies = await chrome.cookies.getAll({ url });
        return { success: true, data: cookies };
      }

      // ── Storage token inspection ─────────────────────────────────────────────
      // Content script pushes results after scanning localStorage /
      // sessionStorage. We cache per tab using chrome.storage.session
      // (cleared automatically when the browser session ends).

      case 'STORAGE_SCAN_RESULT': {
        const result = message.payload as StorageScanResult;
        const tabId = sender.tab?.id ?? await getFallbackTabId();
        const cacheKey = `storageScan:${tabId}`;
        // chrome.storage.session is ephemeral — no user data persists to disk
        await chrome.storage.session.set({ [cacheKey]: result });
        return { success: true, data: null };
      }

      case 'TRANSPORT_SCAN_RESULT': {
        const result = message.payload as TransportDomObservation;
        const tabId = sender.tab?.id ?? await getFallbackTabId();
        const cacheKey = `transportScan:${tabId}`;
        await chrome.storage.session.set({ [cacheKey]: result });
        return { success: true, data: null };
      }

      case 'PAGE_RESOURCE_SCAN_RESULT': {
        const result = message.payload as PageResourceObservation;
        const tabId = sender.tab?.id ?? await getFallbackTabId();
        const cacheKey = `pageResources:${tabId}`;
        await chrome.storage.session.set({ [cacheKey]: result });
        return { success: true, data: null };
      }

      case 'GET_STORAGE_TOKENS': {
        const [tab]    = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId    = tab?.id ?? -1;
        const cacheKey = `storageScan:${tabId}`;
        const stored   = await chrome.storage.session.get(cacheKey);
        const result   = (stored[cacheKey] as StorageScanResult | undefined) ?? null;
        return { success: true, data: result };
      }

      case 'GET_TRANSPORT_OBSERVATIONS': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = tab?.id ?? -1;
        const cacheKey = `transportScan:${tabId}`;
        const stored = await chrome.storage.session.get(cacheKey);
        const result = (stored[cacheKey] as TransportDomObservation | undefined) ?? null;
        return { success: true, data: result };
      }

      case 'GET_PAGE_RESOURCES': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId = tab?.id ?? -1;
        const cacheKey = `pageResources:${tabId}`;
        const stored = await chrome.storage.session.get(cacheKey);
        const result = (stored[cacheKey] as PageResourceObservation | undefined) ?? null;
        return { success: true, data: result };
      }

      case 'RUN_STORAGE_SCAN': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id === undefined) {
          return { success: false, error: 'No active tab available for storage scan.' };
        }

        try {
          const response = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_STORAGE_SCAN' });
          return response as ExtensionResponse;
        } catch {
          return {
            success: false,
            error: 'Storage scan is not available on this tab.',
          };
        }
      }

      case 'RUN_TRANSPORT_SCAN': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id === undefined) {
          return { success: false, error: 'No active tab available for transport scan.' };
        }

        try {
          const response = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_TRANSPORT_SCAN' });
          return response as ExtensionResponse;
        } catch {
          return {
            success: false,
            error: 'Transport scan is not available on this tab.',
          };
        }
      }

      case 'RUN_PAGE_RESOURCE_SCAN': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id === undefined) {
          return { success: false, error: 'No active tab available for page resource scan.' };
        }

        try {
          const response = await chrome.tabs.sendMessage(tab.id, { type: 'RUN_PAGE_RESOURCE_SCAN' });
          return response as ExtensionResponse;
        } catch {
          return {
            success: false,
            error: 'Page resource scan is not available on this tab.',
          };
        }
      }
      // ── Active tab info ─────────────────────────────────────────────────

      case 'GET_ACTIVE_TAB_INFO': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) {
          return { success: false, error: 'No active tab URL available.' };
        }
        const url    = new URL(tab.url);
        const info: ActiveTabInfo = {
          tabId:  tab.id ?? -1,
          url:    tab.url,
          origin: url.origin,
          title:  tab.title,
        };
        return { success: true, data: info };
      }

      // ── Live response header cache ────────────────────────────────────────

      case 'GET_TAB_HEADERS': {
        const id     = message.payload as number;
        const key    = `tabHeaders:${id}`;
        const stored = await chrome.storage.session.get(key);
        const data   = (stored[key] as CachedRequest[] | undefined) ?? [];
        return { success: true, data };
      }

      case 'GET_TAB_WEBSOCKETS': {
        const id     = message.payload as number;
        const key    = `tabWebSockets:${id}`;
        const stored = await chrome.storage.session.get(key);
        const data   = (stored[key] as ObservedWebSocket[] | undefined) ?? [];
        return { success: true, data };
      }

      // ── Fallthrough ─────────────────────────────────────────────────────

      default: {
        const exhaustive: never = message.type;
        return { success: false, error: `Unknown message type: ${String(exhaustive)}` };
      }
    }
  } catch (err) {
    // Catch-all — surface the error message without crashing the worker
    const error = err instanceof Error ? err.message : String(err);
    return { success: false, error };
  }
}

// Required to satisfy isolatedModules when there are no top-level exports
export type { CookieData };

async function getFallbackTabId(): Promise<number> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.id ?? -1;
  } catch {
    return -1;
  }
}
