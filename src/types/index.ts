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
  /** Higher number = higher priority when rules conflict. */
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
  /**
   * When set, the DNR rule is restricted to this domain only
   * (maps to `requestDomains` in the RuleCondition).
   * When absent or undefined the rule applies to all URLs matched by `urlFilter`.
   */
  domainScope?: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 last-updated timestamp. */
  updatedAt: string;
}

/** Input required from the UI to create a new persisted header rule. */
export interface HeaderRuleDraft {
  /** Display name set by the user. */
  name: string;
  /** URL filter pattern (supports wildcards, e.g. `*://*.example.com/*`). */
  urlFilter: string;
  /** Modifications applied to outgoing request headers. */
  requestHeaders?: HeaderModification[];
  /** Modifications applied to incoming response headers. */
  responseHeaders?: HeaderModification[];
  /** Optional domain restriction mapped to DNR requestDomains. */
  domainScope?: string;
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

export interface TransportObservedForm {
  action: string;
  method: string;
  hasPasswordField: boolean;
  passwordFieldCount: number;
  sensitiveFieldNames: string[];
}

export interface TransportDomObservation {
  pageUrl: string;
  scannedAt: string;
  absoluteHttpLinks: string[];
  forms: TransportObservedForm[];
  passwordFieldCount: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Live response header cache types  (webRequest → background → popup)
// ─────────────────────────────────────────────────────────────────────────────

/** A single HTTP response captured by the background webRequest listener. */
export interface CachedRequest {
  url:             string;
  method:          string;
  resourceType:    string;
  statusCode:      number;
  /** Date.now() at the moment of capture. */
  timestamp:       number;
  responseHeaders: { name: string; value: string }[];
}

export type HeaderAssessmentStatus = 'pass' | 'fail' | 'warn' | 'not-applicable';

export type HeaderAssessmentKind = 'required' | 'deprecated' | 'advisory';

export interface HeaderAssessmentCheck {
  id: string;
  headerName: string;
  kind: HeaderAssessmentKind;
  status: HeaderAssessmentStatus;
  summary: string;
  expected: string;
  observedValues: string[];
  evidence: string;
  remediation: string;
  source: 'validator' | 'project';
}

export interface HeaderAssessmentReport {
  activeUrl: string;
  primaryRequest: CachedRequest | null;
  capturedRequestCount: number;
  logoutRequestCount: number;
  observedHeaderNames: string[];
  checks: HeaderAssessmentCheck[];
  summary: Record<HeaderAssessmentStatus, number>;
}

export type TransportTlsStatus = 'pass' | 'fail' | 'warn' | 'inconclusive';

export type TransportTlsTheme =
  | 'https-adoption'
  | 'sensitive-flows'
  | 'hsts'
  | 'downgrade-signals';

export type TransportTlsConfidence = 'high' | 'medium' | 'low';

export type TransportTlsCoverage = 'broad' | 'partial' | 'limited';

export type TransportTlsEvidenceKind = 'request' | 'header' | 'dom' | 'storage';

export interface TransportTlsEvidenceReference {
  kind: TransportTlsEvidenceKind;
  label: string;
  detail: string;
}

export interface TransportTlsCheck {
  id: string;
  theme: TransportTlsTheme;
  title: string;
  status: TransportTlsStatus;
  confidence: TransportTlsConfidence;
  coverage: TransportTlsCoverage;
  summary: string;
  observedFacts: string[];
  assessment: string;
  guidance: string[];
  evidenceRefs: TransportTlsEvidenceReference[];
}

export interface TransportTlsReport {
  activeUrl: string;
  primaryHost: string;
  capturedRequestCount: number;
  observedHttpRequestCount: number;
  observedHttpsRequestCount: number;
  domObservation: TransportDomObservation | null;
  checks: TransportTlsCheck[];
  summary: Record<TransportTlsStatus, number>;
  overallStatus: TransportTlsStatus;
  overview: string;
  coverage: TransportTlsCoverage;
  confidence: TransportTlsConfidence;
}

// ─────────────────────────────────────────────────────────────────────────────
// Assessment types  (aggregated OWASP-oriented findings in the popup)
// ─────────────────────────────────────────────────────────────────────────────

export type AssessmentSeverity = 'high' | 'medium' | 'low' | 'info';

export type AssessmentCategory = 'cookies' | 'tokens' | 'headers' | 'storage' | 'transport';

export type CookieAssessmentCategory = 'session/auth' | 'csrf' | 'preference' | 'analytics/other';

export interface AssessmentFinding {
  /** Stable ID used for React keys and future export/diff support. */
  id: string;
  category: AssessmentCategory;
  severity: AssessmentSeverity;
  title: string;
  summary: string;
  whyItMatters?: string;
  evidence: string;
  remediation: string;
}

export interface CookieAssessmentSummary {
  counts: Record<CookieAssessmentCategory, number>;
  criticalCookies: string[];
}

export interface SetCookieAssessmentSummary {
  observedCount: number;
  sensitiveObservedCount: number;
  relevantRequestCount: number;
  observedNames: string[];
  persistedSensitiveNames: string[];
}

export type TokenAssessmentOrigin = 'cookie' | 'localStorage' | 'sessionStorage' | 'manual';

export interface TokenAssessmentSummary {
  observedCount: number;
  jwtCount: number;
  opaqueCount: number;
  counts: Record<TokenAssessmentOrigin, number>;
  labels: string[];
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
  | 'RUN_STORAGE_SCAN'      // popup asks the active tab content script to rescan storage
  // Passive transport observations (content → background, popup → background)
  | 'TRANSPORT_SCAN_RESULT'
  | 'GET_TRANSPORT_OBSERVATIONS'
  | 'RUN_TRANSPORT_SCAN'
  // Tab info
  | 'GET_ACTIVE_TAB_INFO'
  // Live response header cache
  | 'GET_TAB_HEADERS'        // popup requests cached headers for a tabId
  // Rule ordering
  | 'REORDER_HEADER_RULES'; // popup sends new ordered id array

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
  HEADER_RULES: 'headerRules',
  SETTINGS:     'settings',
  // Keyed by tab ID string at runtime; not a fixed key like the others
  // but declared here so the shape is documented alongside the rest.
  // e.g. chrome.storage.session.set({ [`storageScan:${tabId}`]: result })
} as const;

export type StorageKey = (typeof STORAGE_KEYS)[keyof typeof STORAGE_KEYS];

// ─────────────────────────────────────────────────────────────────────────────
// Settings types
// ─────────────────────────────────────────────────────────────────────────────

export interface ExtensionSettings {
  /** Automatically attempt JWT decode when a cookie value looks like a token. */
  autoDecodeTokens: boolean;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  autoDecodeTokens: true,
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
