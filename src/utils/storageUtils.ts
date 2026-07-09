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

import type { ExtensionSettings } from '../types';
import { DEFAULT_SETTINGS, LEGACY_STORAGE_KEYS, STORAGE_KEYS } from '../types';

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
 * Clears extension data and re-seeds storage with factory defaults.
 * Intended to back a "Reset to defaults" action in the settings panel.
 *
 * Also removes the legacy `headerRules` key left behind by pre-0.5.0 builds
 * that supported request/response header rewriting (now removed).
 */
export async function resetStorage(): Promise<void> {
  await removeItem(LEGACY_STORAGE_KEYS.HEADER_RULES);
  await setItem(STORAGE_KEYS.SETTINGS, DEFAULT_SETTINGS);
}
