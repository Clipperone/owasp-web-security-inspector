/**
 * @file background/index.ts
 * @description Background service worker — Manifest V3.
 *
 * Responsibilities:
 *
 *  1. Lifecycle (onInstalled)
 *     – Seed storage with defaults on first install.
 *     – Clear all dynamic DNR rules on every install/update so stale rules
 *       from a previous version never linger.
 *
 *  2. DNR rule synchronisation
 *     – `updateNetworkRules(rules)` converts our `HeaderRule[]` to the DNR
 *       wire format and calls `chrome.declarativeNetRequest.updateDynamicRules`.
 *     – Only rules with `enabled: true` are pushed to the DNR engine.
 *
 *  3. Message router (popup ↔ background)
 *     – GET_HEADER_RULES    – return all persisted rules from storage
 *     – ADD_HEADER_RULE     – save new rule to storage + sync DNR
 *     – UPDATE_HEADER_RULE  – update existing rule in storage + sync DNR
 *     – DELETE_HEADER_RULE  – remove rule from storage + sync DNR
 *     – TOGGLE_HEADER_RULE  – flip enabled flag in storage + sync DNR
 *     – GET_COOKIES         – bridge to chrome.cookies API
 *     – SET_COOKIE          – bridge to chrome.cookies API
 *     – DELETE_COOKIE       – bridge to chrome.cookies API
 *     – GET_ACTIVE_TAB_INFO – return active tab URL / origin
 *
 *  All errors are caught silently — the service worker must never crash.
 */

import type {
  ActiveTabInfo,
  CookieData,
  ExtensionMessage,
  ExtensionResponse,
  HeaderModification,
  HeaderRule,
  StorageScanResult,
} from '../types';
import { DEFAULT_SETTINGS, STORAGE_KEYS } from '../types';
import {
  deleteRule,
  getRules,
  saveRule,
  toggleRule,
} from '../utils/storageUtils';

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(({ reason }) => {
  // Wrap in void + silent catch — onInstalled must never propagate errors
  void (async () => {
    try {
      // Always flush dynamic DNR rules on install/update so stale rules
      // from a previous extension version cannot persist across upgrades.
      await clearAllDynamicRules();

      if (reason === 'install') {
        // First-time install: seed storage with factory defaults
        await chrome.storage.local.set({
          [STORAGE_KEYS.HEADER_RULES]:     [],
          [STORAGE_KEYS.COOKIE_OVERRIDES]: {},
          [STORAGE_KEYS.SETTINGS]:         DEFAULT_SETTINGS,
        });
      } else if (reason === 'update') {
        // On update: restore only the rules that were enabled before the update
        const stored = await getRules();
        await updateNetworkRules(stored);
      }
    } catch {
      // Silent — service worker must not crash on install
    }
  })();
});

// ─────────────────────────────────────────────────────────────────────────────
// DNR helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Removes **all** dynamic DNR rules currently registered by this extension.
 * Used on install/update to ensure a clean slate.
 */
async function clearAllDynamicRules(): Promise<void> {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  if (existing.length === 0) return;

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
  });
}

/**
 * Converts a `HeaderModification` (our app model) to the object shape
 * expected by `chrome.declarativeNetRequest.ModifyHeaderInfo`.
 *
 * The DNR API accepts:
 *   - `operation: "append" | "set" | "remove"`
 *   - `header: string`           (lowercase recommended)
 *   - `value?: string`           (required for append/set, absent for remove)
 */
function toModifyHeaderInfo(
  mod: HeaderModification,
): chrome.declarativeNetRequest.ModifyHeaderInfo {
  const base = {
    header:    mod.header.toLowerCase(), // HTTP headers are case-insensitive
    operation: mod.operation as chrome.declarativeNetRequest.HeaderOperation,
  };

  // `value` must be present for append/set and absent for remove
  if (mod.operation !== 'remove' && mod.value !== undefined) {
    return { ...base, value: mod.value };
  }

  return base;
}

/**
 * Converts a single `HeaderRule` to a `chrome.declarativeNetRequest.Rule`.
 *
 * Rule structure:
 * ```
 * {
 *   id:       number                  (must be a positive integer ≥ 1)
 *   priority: number                  (lower = higher priority in DNR)
 *   condition: { urlFilter, ... }
 *   action: {
 *     type: "modifyHeaders",
 *     requestHeaders?,               (outgoing request header modifications)
 *     responseHeaders?,              (incoming response header modifications)
 *   }
 * }
 * ```
 */
function toDNRRule(rule: HeaderRule): chrome.declarativeNetRequest.Rule {
  const action: chrome.declarativeNetRequest.RuleAction = {
    type: chrome.declarativeNetRequest.RuleActionType.MODIFY_HEADERS,
  };

  if (rule.requestHeaders && rule.requestHeaders.length > 0) {
    action.requestHeaders = rule.requestHeaders.map(toModifyHeaderInfo);
  }

  if (rule.responseHeaders && rule.responseHeaders.length > 0) {
    action.responseHeaders = rule.responseHeaders.map(toModifyHeaderInfo);
  }

  return {
    id:       rule.id,
    priority: rule.priority,
    condition: {
      // urlFilter supports wildcards: e.g. "*://*.example.com/*"
      urlFilter:       rule.urlFilter,
      // Apply to all resource types unless scoped further in a future version
      resourceTypes:  ['main_frame', 'sub_frame', 'xmlhttprequest', 'other'] as
                       chrome.declarativeNetRequest.ResourceType[],
    },
    action,
  };
}

/**
 * Synchronises the DNR engine with the current application rule set.
 *
 * Strategy:
 *  1. Fetch all currently registered dynamic rules from Chrome.
 *  2. From the provided `rules` array, select only those where `enabled: true`.
 *  3. Remove every existing dynamic rule (full replace — simpler and safer
 *     than a diff-based update for the typical rule set sizes here).
 *  4. Add the enabled rules in their DNR wire format.
 *
 * @param rules - The full list of `HeaderRule` objects from storage.
 *                Disabled rules are filtered out before pushing to DNR.
 */
export async function updateNetworkRules(rules: HeaderRule[]): Promise<void> {
  // IDs of all currently registered dynamic rules to remove
  const existing    = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);

  // Only push enabled rules to the DNR engine
  const addRules = rules
    .filter((r) => r.enabled)
    .map(toDNRRule);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Message router
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionMessage,
    _sender,
    sendResponse: (response: ExtensionResponse) => void,
  ) => {
    // Return `true` to keep the message channel open for async responses
    handleMessage(message)
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
): Promise<ExtensionResponse> {
  try {
    switch (message.type) {

      // ── Header rule CRUD ────────────────────────────────────────────────

      case 'GET_HEADER_RULES': {
        const rules = await getRules();
        return { success: true, data: rules };
      }

      case 'ADD_HEADER_RULE':
      case 'UPDATE_HEADER_RULE': {
        const rule = message.payload as HeaderRule;
        await saveRule(rule);
        const all = await getRules();
        await updateNetworkRules(all);
        return { success: true, data: rule };
      }

      case 'DELETE_HEADER_RULE': {
        const id = message.payload as number;
        await deleteRule(id);
        const all = await getRules();
        await updateNetworkRules(all);
        return { success: true, data: id };
      }

      case 'TOGGLE_HEADER_RULE': {
        const id      = message.payload as number;
        const updated = await toggleRule(id);
        const all     = await getRules();
        await updateNetworkRules(all);
        return { success: true, data: updated };
      }

      // ── Cookie bridge ───────────────────────────────────────────────────
      // The popup cannot call chrome.cookies directly because it needs a URL
      // context; the background asks Chrome on its behalf.

      case 'GET_COOKIES': {
        const url     = message.payload as string;
        const cookies = await chrome.cookies.getAll({ url });
        return { success: true, data: cookies };
      }

      case 'SET_COOKIE': {
        const details = message.payload as chrome.cookies.SetDetails;
        const cookie  = await chrome.cookies.set(details);
        return { success: true, data: cookie };
      }

      case 'DELETE_COOKIE': {
        const details = message.payload as chrome.cookies.Details;
        await chrome.cookies.remove(details);
        return { success: true, data: null };
      }
      // ── Storage token inspection ─────────────────────────────────────────────
      // Content script pushes results after scanning localStorage /
      // sessionStorage. We cache per tab using chrome.storage.session
      // (cleared automatically when the browser session ends).

      case 'STORAGE_SCAN_RESULT': {
        const result  = message.payload as StorageScanResult;
        const [tab]   = await chrome.tabs.query({ active: true, currentWindow: true });
        const tabId   = tab?.id ?? -1;
        const cacheKey = `storageScan:${tabId}`;
        // chrome.storage.session is ephemeral — no user data persists to disk
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
