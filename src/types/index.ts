// ─────────────────────────────────────────────────────────────────────────────
// JWT / Token types
// ─────────────────────────────────────────────────────────────────────────────

/** Standard JOSE header fields present in a JWT. */
export interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

/** Standard registered JWT payload claims (RFC 7519). */
export interface JWTPayload {
  iss?: string;               // Issuer
  sub?: string;               // Subject
  aud?: string | string[];    // Audience
  exp?: number;               // Expiration time (Unix timestamp)
  nbf?: number;               // Not before (Unix timestamp)
  iat?: number;               // Issued at (Unix timestamp)
  jti?: string;               // JWT ID
  [key: string]: unknown;     // Additional custom claims
}

/** Full decoded representation of a JWT token. */
export interface TokenData {
  /** The raw, encoded token string. */
  raw: string;
  header: JWTHeader;
  payload: JWTPayload;
  /** The base64url-encoded signature segment (not verified client-side). */
  signature: string;
  /** True when `exp` is in the past. */
  isExpired: boolean;
  /** Resolved Date from the `exp` claim, if present. */
  expiresAt?: Date;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie types
// ─────────────────────────────────────────────────────────────────────────────

export type SameSitePolicy = 'strict' | 'lax' | 'none' | 'unspecified';

/** Mirrors the shape of `chrome.cookies.Cookie` with typed sameSite. */
export interface CookieData {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSitePolicy;
  /** Unix timestamp (seconds). Absent for session cookies. */
  expirationDate?: number;
  hostOnly: boolean;
  /** True if the cookie expires at the end of the browser session. */
  session: boolean;
  storeId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Header Rule types  (declarativeNetRequest)
// ─────────────────────────────────────────────────────────────────────────────

export type HeaderOperation = 'append' | 'set' | 'remove';

/** A single header modification action. */
export interface HeaderModification {
  /** Header name, case-insensitive per HTTP spec. */
  header: string;
  operation: HeaderOperation;
  /** Required for 'append' and 'set'; omitted for 'remove'. */
  value?: string;
}

/** A complete declarativeNetRequest-style rule persisted by the extension. */
export interface HeaderRule {
  /** Unique numeric rule ID (required by the DNR API). */
  id: number;
  /** Lower number = higher priority when rules conflict. */
  priority: number;
  /** Display name set by the user. */
  name: string;
  /** Whether this rule is currently active. */
  enabled: boolean;
  /** URL filter pattern (supports wildcards, e.g. `*://*.example.com/*`). */
  urlFilter: string;
  /** Modifications applied to outgoing request headers. */
  requestHeaders?: HeaderModification[];
  /** Modifications applied to incoming response headers. */
  responseHeaders?: HeaderModification[];
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 last-updated timestamp. */
  updatedAt: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage inspection types  (content script → background → popup)
// ─────────────────────────────────────────────────────────────────────────────

/** The web storage area the entry was found in. */
export type WebStorageArea = 'localStorage' | 'sessionStorage';

/** Reason an entry was flagged as a potential authentication token. */
export type TokenHint =
  | 'jwt-value'       // value matches the 3-segment Base64Url JWT pattern
  | 'key-name'        // key name contains an auth-related keyword
  | 'ey-prefix';      // value starts with 'ey' (Base64Url-encoded '{')

/** A single web storage entry that may contain an authentication token. */
export interface StorageEntry {
  /** The storage area where the entry was found. */
  area: WebStorageArea;
  /** The storage key. */
  key: string;
  /** The raw string value stored under the key. */
  value: string;
  /** One or more reasons this entry was flagged. */
  hints: TokenHint[];
  /** True when the value passes the full JWT structural validation. */
  isJwt: boolean;
}

/** Full result of a web storage scan sent from the content script. */
export interface StorageScanResult {
  /** The origin of the scanned page (e.g. "https://example.com"). */
  origin: string;
  /** ISO 8601 timestamp of when the scan completed. */
  scannedAt: string;
  /** All flagged entries, ordered by area then key. */
  entries: StorageEntry[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Messaging types  (popup ↔ background ↔ content)
// ─────────────────────────────────────────────────────────────────────────────

export type MessageType =
  // Cookie operations
  | 'GET_COOKIES'
  | 'SET_COOKIE'
  | 'DELETE_COOKIE'
  // Header rule operations
  | 'GET_HEADER_RULES'
  | 'ADD_HEADER_RULE'
  | 'UPDATE_HEADER_RULE'
  | 'DELETE_HEADER_RULE'
  | 'TOGGLE_HEADER_RULE'
  // Storage token inspection (content → background, popup → background)
  | 'STORAGE_SCAN_RESULT'   // content script pushes scan results
  | 'GET_STORAGE_TOKENS'    // popup requests cached results for active tab
  // Tab info
  | 'GET_ACTIVE_TAB_INFO';

export interface ExtensionMessage<T = unknown> {
  type: MessageType;
  payload?: T;
}

export interface ExtensionResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage types
// ─────────────────────────────────────────────────────────────────────────────

export const STORAGE_KEYS = {
  HEADER_RULES:     'headerRules',
  COOKIE_OVERRIDES: 'cookieOverrides',
  SETTINGS:         'settings',
  // Keyed by tab ID string at runtime; not a fixed key like the others
  // but declared here so the shape is documented alongside the rest.
  // e.g. chrome.storage.session.set({ [`storageScan:${tabId}`]: result })
} as const;

export type StorageKey = (typeof STORAGE_KEYS)[keyof typeof STORAGE_KEYS];

// ─────────────────────────────────────────────────────────────────────────────
// Settings types
// ─────────────────────────────────────────────────────────────────────────────

export interface ExtensionSettings {
  theme: 'light' | 'dark' | 'system';
  /** Automatically attempt JWT decode when a cookie value looks like a token. */
  autoDecodeTokens: boolean;
  /** Show Chrome notification on rule enable/disable. */
  showNotifications: boolean;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  theme:              'system',
  autoDecodeTokens:   true,
  showNotifications:  false,
};

// ─────────────────────────────────────────────────────────────────────────────
// Active tab info  (returned by GET_ACTIVE_TAB_INFO)
// ─────────────────────────────────────────────────────────────────────────────

export interface ActiveTabInfo {
  tabId: number;
  url: string;
  origin: string;
  title?: string;
}
