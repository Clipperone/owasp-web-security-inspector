/**
 * @file storageUtils.ts  (re-exported as storageManager)
 * @description Strongly-typed wrapper around chrome.storage.local.
 *
 * All reads and writes to extension storage go through this module.
 * Components and the background service worker never call chrome.storage
 * directly, which provides:
 *   - A single source of truth for storage keys
 *   - Full TypeScript type safety at every call site
 *   - Easy unit-testability: mock chrome.storage once, here
 *   - A single migration point if keys or schemas change in the future
 */

import type { ExtensionSettings, HeaderRule } from '../types';
import { DEFAULT_SETTINGS, STORAGE_KEYS } from '../types';

// ─────────────────────────────────────────────────────────────────────────────
// Low-level typed primitives
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Reads a single value from chrome.storage.local.
 * Returns `undefined` when the key does not exist yet.
 *
 * @param key - The storage key to read.
 */
async function getItem<T>(key: string): Promise<T | undefined> {
  const result = await chrome.storage.local.get(key);
  // chrome.storage.get returns {} for missing keys, never throws
  return result[key] as T | undefined;
}

/**
 * Writes a single value to chrome.storage.local.
 *
 * @param key   - The storage key to write.
 * @param value - The value to persist. Must be JSON-serializable.
 */
async function setItem<T>(key: string, value: T): Promise<void> {
  await chrome.storage.local.set({ [key]: value });
}

/**
 * Removes a single key from chrome.storage.local.
 * Is a no-op if the key does not exist.
 *
 * @param key - The storage key to delete.
 */
async function removeItem(key: string): Promise<void> {
  await chrome.storage.local.remove(key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Header Rule operations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns all persisted header rules sorted by `priority` descending.
 * Returns an empty array when no rules have been saved yet.
 *
 * Sorting ensures the UI list and the declarativeNetRequest API always
 * operate on the same deterministic order.
 */
export async function getRules(): Promise<HeaderRule[]> {
  const stored = await getItem<HeaderRule[]>(STORAGE_KEYS.HEADER_RULES);
  if (!Array.isArray(stored)) return [];
  // Return a new sorted array — never mutate the stored reference
  return [...stored].sort((a, b) => b.priority - a.priority);
}

/**
 * Reassigns rule priorities from top to bottom so the first rule in the array
 * has the highest DNR priority and the last rule has the lowest one.
 */
export function normalizeRulePriorities(rules: HeaderRule[]): HeaderRule[] {
  return rules.map((rule, index) => ({
    ...rule,
    priority: rules.length - index,
  }));
}

/**
 * Persists the complete ordered rule list exactly as provided.
 * Callers are responsible for any priority normalization before writing.
 */
export async function setRules(rules: HeaderRule[]): Promise<void> {
  await setItem(STORAGE_KEYS.HEADER_RULES, rules);
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings operations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the persisted extension settings merged with `DEFAULT_SETTINGS`.
 *
 * The merge strategy (`{ ...DEFAULT_SETTINGS, ...stored }`) ensures that any
 * setting fields added in future versions of the extension are automatically
 * populated with their default values, even for users who have older persisted
 * data — i.e., it is forward-compatible.
 */
export async function getSettings(): Promise<ExtensionSettings> {
  const stored = await getItem<Partial<ExtensionSettings>>(STORAGE_KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

/**
 * Merges a partial settings patch into the currently persisted settings and
 * persists the result. Only the keys present in `patch` are overwritten.
 *
 * @param patch - A partial `ExtensionSettings` object with the fields to change.
 * @returns The full settings object after the update.
 *
 * @example
 * await updateSettings({ theme: 'dark' });
 */
export async function updateSettings(
  patch: Partial<ExtensionSettings>,
): Promise<ExtensionSettings> {
  const current = await getSettings();
  const next    = { ...current, ...patch };
  await setItem(STORAGE_KEYS.SETTINGS, next);
  return next;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage maintenance
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Clears all extension data and re-seeds storage with factory defaults.
 * Intended to back a "Reset to defaults" action in the settings panel.
 *
 * This does NOT clear rules managed by `declarativeNetRequest` — the
 * background service worker must call `chrome.declarativeNetRequest
 * .updateDynamicRules` separately to remove active DNR rules.
 */
export async function resetStorage(): Promise<void> {
  await removeItem(STORAGE_KEYS.HEADER_RULES);
  await setItem(STORAGE_KEYS.SETTINGS, DEFAULT_SETTINGS);
}
