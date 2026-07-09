/**
 * Minimal ambient declarations for the Firefox-only `browser.*` surface this
 * extension touches. `@types/chrome` does not cover `sidebarAction`, and we use
 * the natively promise-flavoured `chrome.*`/`browser.*` namespaces directly
 * rather than pulling in webextension-polyfill.
 *
 * `browser` is declared optional so `typeof browser !== 'undefined'` guards
 * type-check on Chromium, where the global does not exist.
 */
interface WebExtSidebarAction {
  toggle(): Promise<void>;
  open(): Promise<void>;
  close(): Promise<void>;
}

interface WebExtBrowser {
  sidebarAction?: WebExtSidebarAction;
}

declare const browser: WebExtBrowser | undefined;
