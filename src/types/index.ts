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
// Storage inspection types  (content script → background → popup)
// ─────────────────────────────────────────────────────────────────────────────

/** The web storage area the entry was found in. */
export type WebStorageArea = 'localStorage' | 'sessionStorage' | 'indexedDB';

/** Reason an entry was flagged as a potential authentication token. */
export type TokenHint =
  | 'jwt-value'       // value matches the 3-segment Base64Url JWT pattern
  | 'key-name'        // key name contains an auth-related keyword
  | 'ey-prefix';      // value starts with 'ey' (Base64Url-encoded '{')

/** Category of a secret/PII pattern surfaced by the detection engine. */
export type DetectionCategory =
  | 'private-key'
  | 'api-key'
  | 'high-entropy-secret'
  | 'credential'
  | 'connection-string'
  | 'pii-email'
  | 'pii-card'
  | 'pii-phone'
  | 'pii-iban'
  | 'pii-codice-fiscale'
  | 'eu-vat';

/** A single secret/PII match found inside a storage value. */
export interface DetectionHit {
  /** Stable detector identifier (e.g. `aws-access-key-id`). */
  detectorId: string;
  category: DetectionCategory;
  severity: AssessmentSeverity;
  /** A redacted, display/export-safe sample of the first match. */
  sample: string;
  /** How many matches of this detector were found in the value. */
  matchCount: number;
  /** True when a code-side checksum (Luhn / mod-97 / CF) validated the match. */
  validated?: boolean;
}

/** A single web storage entry that may contain an authentication token or secret. */
export interface StorageEntry {
  /** The storage area where the entry was found. */
  area: WebStorageArea;
  /** The storage key. */
  key: string;
  /**
   * The string value stored under the key. Truncated to a bounded length, and
   * redacted at the source when high-sensitivity secrets/PII are detected —
   * except whole-value JWTs, which the Tokens tab needs intact to decode.
   */
  value: string;
  /** One or more reasons this entry was flagged. */
  hints: TokenHint[];
  /** True when the value passes the full JWT structural validation. */
  isJwt: boolean;
  /** Secret/PII matches found in the value (absent when none). */
  detections?: DetectionHit[];
  /** True when `value` was rewritten to mask detected secrets/PII. */
  valueRedacted?: boolean;
  /** Length of the original (pre-truncation, pre-redaction) value. */
  valueLength?: number;
  /** FNV-1a 32-bit hex of the raw value — stable change detection under redaction. */
  valueFingerprint?: string;
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
// Page resource inspection types  (SRI / mixed content — content → background)
// ─────────────────────────────────────────────────────────────────────────────

/** A single subresource (`<script src>` / `<link rel=stylesheet>`) seen in the DOM. */
export interface ObservedPageResource {
  /** Absolute URL of the subresource. */
  url: string;
  kind: 'script' | 'stylesheet';
  /** True when the resource origin differs from the page origin. */
  crossOrigin: boolean;
  /** The element's `crossorigin` attribute value, if any. */
  crossOriginAttr?: string;
  /** True when a non-empty `integrity` attribute is present. */
  hasIntegrity: boolean;
  /**
   * Format-only validity of the integrity attribute (one or more
   * `sha(256|384|512)-<base64>` hashes). This is NOT a cryptographic check —
   * the browser itself enforces the actual hash match.
   */
  integrityValid?: boolean;
}

/** Result of scanning the current document for subresources. */
export interface PageResourceObservation {
  pageUrl: string;
  scannedAt: string;
  scripts: ObservedPageResource[];
  stylesheets: ObservedPageResource[];
  /** True when the observed counts were capped, so the view can note it. */
  truncated: boolean;
}

/** A WebSocket handshake observed by the background webRequest listener. */
export interface ObservedWebSocket {
  url: string;
  /** True for `wss://`, false for `ws://`. */
  secure: boolean;
  /** Date.now() at the moment of capture. */
  timestamp: number;
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

export type TokenAssessmentOrigin = 'cookie' | 'localStorage' | 'sessionStorage' | 'indexedDB' | 'manual';

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
  // Cookie reading (passive — the panel needs a URL context the background supplies)
  | 'GET_COOKIES'
  // Storage token inspection (content → background, popup → background)
  | 'STORAGE_SCAN_RESULT'   // content script pushes scan results
  | 'GET_STORAGE_TOKENS'    // popup requests cached results for active tab
  | 'RUN_STORAGE_SCAN'      // popup asks the active tab content script to rescan storage
  // Passive transport observations (content → background, popup → background)
  | 'TRANSPORT_SCAN_RESULT'
  | 'GET_TRANSPORT_OBSERVATIONS'
  | 'RUN_TRANSPORT_SCAN'
  // Page subresource observations for SRI / mixed content
  | 'PAGE_RESOURCE_SCAN_RESULT'
  | 'GET_PAGE_RESOURCES'
  | 'RUN_PAGE_RESOURCE_SCAN'
  // Observed WebSocket connections for the active tab
  | 'GET_TAB_WEBSOCKETS'
  // Tab info
  | 'GET_ACTIVE_TAB_INFO'
  // Live response header cache
  | 'GET_TAB_HEADERS';       // popup requests cached headers for a tabId

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
  SETTINGS:     'settings',
  // Keyed by tab ID string at runtime; not a fixed key like the others
  // but declared here so the shape is documented alongside the rest.
  // e.g. chrome.storage.session.set({ [`storageScan:${tabId}`]: result })
} as const;

export type StorageKey = (typeof STORAGE_KEYS)[keyof typeof STORAGE_KEYS];

/**
 * Keys written by past versions that the current build no longer uses. Kept
 * only so the update migration in the background worker can remove them from
 * `chrome.storage.local` for upgrading users.
 */
export const LEGACY_STORAGE_KEYS = {
  HEADER_RULES: 'headerRules',
} as const;

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

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot Diff  (forward-compat types — the diff feature itself lands later)
// ─────────────────────────────────────────────────────────────────────────────
//
// A snapshot captures the full browser-observable context at a point in time
// (e.g. pre-login vs post-login) so a future release can diff two of them. The
// types are declared now so the storage-detection work stays compatible; no
// message types or handlers exist yet. Every field is already JSON-serializable.

export const SNAPSHOT_SCHEMA_VERSION = '1.0' as const;

/** Lightweight snapshot descriptor kept in the per-origin snapshot index. */
export interface SnapshotMeta {
  /** Stable unique id (e.g. crypto.randomUUID()). */
  id: string;
  /** User-facing label, e.g. "pre-login". */
  name: string;
  /** ISO 8601 capture time. */
  createdAt: string;
  /** Origin the snapshot was captured on. */
  origin: string;
}

/** A full capture of the observable context at a point in time. */
export interface ContextSnapshot extends SnapshotMeta {
  schemaVersion: typeof SNAPSHOT_SCHEMA_VERSION;
  activeUrl: string;
  cookies: chrome.cookies.Cookie[];
  storage: StorageScanResult | null;
  requests: CachedRequest[];
  pageResources: PageResourceObservation | null;
  domObservation: TransportDomObservation | null;
  webSockets: ObservedWebSocket[];
  /** Findings frozen at capture time. */
  findings: AssessmentFinding[];
}
