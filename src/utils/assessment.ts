import type {
  AssessmentFinding,
  CachedRequest,
  CookieAssessmentCategory,
  CookieAssessmentSummary,
  SetCookieAssessmentSummary,
  StorageEntry,
  TokenAssessmentOrigin,
  TokenAssessmentSummary,
} from '../types';
import { decodeJwt, isJwt } from './jwtUtils';

const EXACT_SENSITIVE_COOKIE_NAMES = new Set([
  'phpsessid',
  'jsessionid',
  'asp.net_sessionid',
  'aspnetsessionid',
  'connect.sid',
  'session',
  'sessionid',
  'session_id',
  'sid',
  'auth',
  'auth_token',
  'authtoken',
  'token',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'id_token',
  'bearer',
]);
const SENSITIVE_COOKIE_SEGMENT_RE = /(^|[-_.])(session|sess|auth|token|jwt|bearer|access|refresh)([-_.]|$)/i;
const SENSITIVE_CLAIM_RE = /(^email$|mail|phone|roles?$|scope|permission|tenant|customer|account|user(name|id)?$)/i;
const CSRF_COOKIE_RE = /(^|[-_.])(csrf|xsrf|antiforgery|requestverificationtoken)([-_.]|$)/i;
const PREFERENCE_COOKIE_RE = /(^|[-_.])(pref|theme|lang|locale|consent|currency|timezone|tz)([-_.]|$)/i;
const ANALYTICS_COOKIE_RE = /(^|[-_.])(_ga|_gid|_gat|ga|amplitude|mixpanel|analytics|segment)([-_.]|$)/i;
const TOKEN_NAMING_RE = /(^|[-_.])(access|refresh|id|jwt|token|bearer|auth)([-_.]|$)/i;
const BEARER_VALUE_RE = /^bearer\s+[a-z0-9\-._~+/]+=*$/i;
const OPAQUE_TOKEN_VALUE_RE = /^[A-Za-z0-9\-._~+/]+=*$/;

interface ParsedSetCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: string;
}

interface HeaderCheckResult {
  missing: string[];
  warning: string[];
}

interface RequestSetCookieObservation {
  request: CachedRequest;
  cookies: ParsedSetCookie[];
}

interface TokenCandidate {
  origin: TokenAssessmentOrigin;
  label: string;
  raw: string;
  isJwt: boolean;
}

function finding(
  id: string,
  category: AssessmentFinding['category'],
  severity: AssessmentFinding['severity'],
  title: string,
  summary: string,
  evidence: string,
  remediation: string,
): AssessmentFinding {
  return { id, category, severity, title, summary, evidence, remediation };
}

function headerFinding(
  id: string,
  severity: AssessmentFinding['severity'],
  title: string,
  summary: string,
  whyItMatters: string,
  evidence: string,
  remediation: string,
): AssessmentFinding {
  return {
    id,
    category: 'headers',
    severity,
    title,
    summary,
    whyItMatters,
    evidence,
    remediation,
  };
}

function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function firstHeaderValue(req: CachedRequest, name: string): string | undefined {
  return req.responseHeaders.find(header => header.name.toLowerCase() === name)?.value;
}

function allHeaderValues(req: CachedRequest, name: string): string[] {
  return req.responseHeaders
    .filter(header => header.name.toLowerCase() === name)
    .map(header => header.value);
}

function isSensitiveCookieName(name: string): boolean {
  const normalized = name.trim().toLowerCase();
  return EXACT_SENSITIVE_COOKIE_NAMES.has(normalized)
    || normalized.startsWith('__secure-')
    || normalized.startsWith('__host-')
    || SENSITIVE_COOKIE_SEGMENT_RE.test(normalized);
}

function isSensitiveStorageKey(entry: StorageEntry): boolean {
  const normalized = entry.key.trim().toLowerCase();
  return entry.isJwt
    || EXACT_SENSITIVE_COOKIE_NAMES.has(normalized)
    || normalized.includes('access_token')
    || normalized.includes('refresh_token')
    || normalized.includes('id_token')
    || normalized.includes('authorization')
    || normalized.includes('bearer')
    || normalized.includes('jwt')
    || normalized.includes('token')
    || normalized.includes('auth');
}

function isOpaqueTokenValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 24) return false;
  if (trimmed.includes(' ')) {
    return BEARER_VALUE_RE.test(trimmed);
  }

  return OPAQUE_TOKEN_VALUE_RE.test(trimmed);
}

function shouldTreatCookieAsToken(cookie: chrome.cookies.Cookie): boolean {
  return isJwt(cookie.value)
    || (TOKEN_NAMING_RE.test(cookie.name.toLowerCase()) && isOpaqueTokenValue(cookie.value));
}

function collectTokenCandidates(
  cookies: chrome.cookies.Cookie[],
  entries: StorageEntry[],
  manualValue?: string,
): TokenCandidate[] {
  const candidates: TokenCandidate[] = [];

  cookies.forEach(cookie => {
    if (!shouldTreatCookieAsToken(cookie)) return;
    candidates.push({
      origin: 'cookie',
      label: `cookie:${cookie.name}`,
      raw: cookie.value,
      isJwt: isJwt(cookie.value),
    });
  });

  entries.forEach(entry => {
    const opaqueToken = !entry.isJwt && (isSensitiveStorageKey(entry) || isOpaqueTokenValue(entry.value));
    if (!entry.isJwt && !opaqueToken) return;

    candidates.push({
      origin: entry.area,
      label: `${entry.area}:${entry.key}`,
      raw: entry.value,
      isJwt: entry.isJwt,
    });
  });

  const trimmedManual = manualValue?.trim();
  if (trimmedManual && isJwt(trimmedManual)) {
    candidates.push({
      origin: 'manual',
      label: 'manual:input',
      raw: trimmedManual,
      isJwt: true,
    });
  }

  return candidates;
}

function classifyCookie(name: string): CookieAssessmentCategory {
  const normalized = name.trim().toLowerCase();
  if (isSensitiveCookieName(normalized)) return 'session/auth';
  if (CSRF_COOKIE_RE.test(normalized)) return 'csrf';
  if (PREFERENCE_COOKIE_RE.test(normalized)) return 'preference';
  return ANALYTICS_COOKIE_RE.test(normalized) ? 'analytics/other' : 'analytics/other';
}

function pathnameFromUrl(url: string): string {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return '/';
  }
}

function isHostPrefixCandidate(cookie: chrome.cookies.Cookie): boolean {
  return cookie.secure && cookie.hostOnly && cookie.path === '/' && !cookie.name.startsWith('__Host-');
}

function isSecurePrefixCandidate(cookie: chrome.cookies.Cookie): boolean {
  return cookie.secure && !cookie.name.startsWith('__Host-') && !cookie.name.startsWith('__Secure-');
}

function hasLongLifetime(expirationDate: number | undefined, thresholdSeconds: number): boolean {
  if (expirationDate === undefined) return false;
  return expirationDate - Math.floor(Date.now() / 1000) > thresholdSeconds;
}

function looksLikeAuthEndpoint(url: string): boolean {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return /(^|\/)(login|signin|sign-in|auth|oauth|sso|callback|session|token|refresh)(\/|$)/.test(pathname);
  } catch {
    return false;
  }
}

function looksLikeLogoutEndpoint(url: string): boolean {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return /(^|\/)(logout|signout|sign-out|logoff|revoke|endsession|end-session)(\/|$)/.test(pathname);
  } catch {
    return false;
  }
}

function hasOriginVary(value: string | undefined): boolean {
  if (!value) return false;
  return value
    .split(',')
    .map(part => part.trim().toLowerCase())
    .includes('origin');
}

function parseClearSiteData(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map(part => part.trim().replace(/^"|"$/g, '').toLowerCase())
    .filter(Boolean);
}

function isRelevantSetCookieRequest(request: CachedRequest, activeUrl: string): boolean {
  const activeHostname = hostnameFromUrl(activeUrl);
  const requestHostname = hostnameFromUrl(request.url);
  const sameHost = requestHostname !== '' && requestHostname === activeHostname;
  if (!sameHost) return false;

  if (request.resourceType === 'main_frame' || request.resourceType === 'sub_frame') return true;
  if (request.resourceType === 'xmlhttprequest' && looksLikeAuthEndpoint(request.url)) return true;
  return false;
}

function collectSetCookieObservations(requests: CachedRequest[], activeUrl: string): RequestSetCookieObservation[] {
  return requests
    .filter(request => isRelevantSetCookieRequest(request, activeUrl))
    .map(request => ({
      request,
      cookies: allHeaderValues(request, 'set-cookie')
        .map(parseSetCookie)
        .filter((cookie): cookie is ParsedSetCookie => cookie !== null),
    }))
    .filter(entry => entry.cookies.length > 0);
}

function getPrimaryRequest(requests: CachedRequest[], activeUrl: string): CachedRequest | null {
  const activeHostname = hostnameFromUrl(activeUrl);
  return requests.find(req => req.resourceType === 'main_frame')
    ?? requests.find(req => req.resourceType === 'sub_frame' && hostnameFromUrl(req.url) === activeHostname)
    ?? requests.find(req => hostnameFromUrl(req.url) === activeHostname)
    ?? requests[0]
    ?? null;
}

function evaluatePrimaryHeaders(req: CachedRequest): HeaderCheckResult {
  const missing: string[] = [];
  const warning: string[] = [];
  const csp = firstHeaderValue(req, 'content-security-policy');
  const hsts = firstHeaderValue(req, 'strict-transport-security');
  const xfo = firstHeaderValue(req, 'x-frame-options');
  const xcto = firstHeaderValue(req, 'x-content-type-options');
  const referrerPolicy = firstHeaderValue(req, 'referrer-policy');
  const permissionsPolicy = firstHeaderValue(req, 'permissions-policy');
  const coop = firstHeaderValue(req, 'cross-origin-opener-policy');
  const coep = firstHeaderValue(req, 'cross-origin-embedder-policy');
  const corp = firstHeaderValue(req, 'cross-origin-resource-policy');

  if (!csp) {
    missing.push('Content-Security-Policy');
  } else {
    const normalized = csp.toLowerCase();
    if (normalized.includes("'unsafe-inline'") || normalized.includes("'unsafe-eval'")) {
      warning.push('Content-Security-Policy allows unsafe-inline or unsafe-eval.');
    }
  }

  if (req.url.startsWith('https://')) {
    if (!hsts) {
      missing.push('Strict-Transport-Security');
    } else {
      const normalized = hsts.toLowerCase();
      const directives = normalized.split(';').map(part => part.trim()).filter(Boolean);
      const maxAgeDirective = directives.find(part => part.startsWith('max-age='));
      const maxAge = maxAgeDirective ? Number.parseInt(maxAgeDirective.slice(8), 10) : NaN;
      if (!Number.isFinite(maxAge) || maxAge < 63072000) {
        warning.push('Strict-Transport-Security max-age is below the common OWASP reference value.');
      }
      if (!directives.includes('includesubdomains')) {
        warning.push('Strict-Transport-Security does not include includeSubDomains.');
      }
      if (!directives.includes('preload')) {
        warning.push('Strict-Transport-Security does not include preload.');
      }
    }
  }

  if (!xfo) missing.push('X-Frame-Options');
  else if (xfo.trim().toUpperCase() === 'SAMEORIGIN') {
    warning.push('X-Frame-Options uses SAMEORIGIN instead of the stricter DENY value.');
  } else if (xfo.trim().toUpperCase() !== 'DENY') {
    warning.push('X-Frame-Options uses an unexpected value.');
  }

  if (!xcto) missing.push('X-Content-Type-Options');
  else if (xcto.trim().toLowerCase() !== 'nosniff') warning.push('X-Content-Type-Options is not set to nosniff.');

  if (!referrerPolicy) missing.push('Referrer-Policy');
  else if (referrerPolicy.trim().toLowerCase() !== 'strict-origin-when-cross-origin') {
    warning.push('Referrer-Policy differs from strict-origin-when-cross-origin.');
  }

  if (!permissionsPolicy) missing.push('Permissions-Policy');
  else if (permissionsPolicy.includes('*')) warning.push('Permissions-Policy contains wildcard allowances.');

  if (!coop) missing.push('Cross-Origin-Opener-Policy');
  else if (coop.trim().toLowerCase() !== 'same-origin') warning.push('Cross-Origin-Opener-Policy is not same-origin.');

  if (!coep) missing.push('Cross-Origin-Embedder-Policy');
  else if (coep.trim().toLowerCase() !== 'require-corp') warning.push('Cross-Origin-Embedder-Policy is not require-corp.');

  if (!corp) missing.push('Cross-Origin-Resource-Policy');
  else if (corp.trim().toLowerCase() !== 'same-site') warning.push('Cross-Origin-Resource-Policy is not same-site.');

  return { missing, warning };
}

function parseSetCookie(headerValue: string): ParsedSetCookie | null {
  const [nameValue, ...attributeParts] = headerValue.split(';');
  const separatorIndex = nameValue.indexOf('=');
  if (separatorIndex <= 0) return null;

  const parsed: ParsedSetCookie = {
    name: nameValue.slice(0, separatorIndex).trim(),
    value: nameValue.slice(separatorIndex + 1).trim(),
    secure: false,
    httpOnly: false,
  };

  for (const rawAttribute of attributeParts) {
    const attribute = rawAttribute.trim();
    const [rawKey, ...rawRest] = attribute.split('=');
    const key = rawKey.toLowerCase();
    const value = rawRest.join('=').trim();

    if (key === 'secure') parsed.secure = true;
    else if (key === 'httponly') parsed.httpOnly = true;
    else if (key === 'samesite') parsed.sameSite = value.toLowerCase();
    else if (key === 'domain') parsed.domain = value;
    else if (key === 'path') parsed.path = value;
    else if (key === 'expires') parsed.expires = value;
    else if (key === 'max-age') parsed.maxAge = value;
  }

  return parsed;
}

export function assessCookies(cookies: chrome.cookies.Cookie[]): AssessmentFinding[] {
  return assessCookiesForUrl(cookies, '/');
}

export function assessCookiesForUrl(cookies: chrome.cookies.Cookie[], activeUrl: string): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  const cookieNames = new Map<string, chrome.cookies.Cookie[]>();
  const activePath = pathnameFromUrl(activeUrl);

  for (const cookie of cookies) {
    const existing = cookieNames.get(cookie.name) ?? [];
    existing.push(cookie);
    cookieNames.set(cookie.name, existing);

    const cookieCategory = classifyCookie(cookie.name);

    if (cookieCategory === 'csrf') {
      if (!cookie.sameSite || cookie.sameSite === 'unspecified') {
        findings.push(finding(
          `cookie-csrf-samesite-${cookie.name}-${cookie.domain}-${cookie.path}`,
          'cookies',
          'medium',
          'CSRF-related cookie without explicit SameSite',
          'CSRF-related state is easier to reason about when cross-site behavior is constrained explicitly.',
          `${cookie.name} is classified as a CSRF-related cookie and has no explicit SameSite value.`,
          'Set an explicit SameSite value and verify the application CSRF flow still behaves as intended.',
        ));
      }
      continue;
    }

    if (!isSensitiveCookieName(cookie.name)) continue;

    if (!cookie.secure) {
      findings.push(finding(
        `cookie-secure-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'high',
        'Sensitive cookie without Secure',
        'A cookie that looks related to authentication or session state can travel over non-TLS requests.',
        `${cookie.name} on ${cookie.domain}${cookie.path} is not marked Secure.`,
        'Mark authentication and session cookies as Secure and serve them only over HTTPS.',
      ));
    }

    if (!cookie.httpOnly) {
      findings.push(finding(
        `cookie-httponly-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'high',
        'Sensitive cookie without HttpOnly',
        'A script-accessible session or auth cookie increases token theft risk under XSS.',
        `${cookie.name} on ${cookie.domain}${cookie.path} is readable by JavaScript.`,
        'Mark session and authentication cookies as HttpOnly unless the application has a strict reason not to.',
      ));
    }

    if (cookie.sameSite === 'unspecified') {
      findings.push(finding(
        `cookie-samesite-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'medium',
        'Sensitive cookie without explicit SameSite',
        'Session-related cookies should usually have an explicit SameSite policy to reduce CSRF exposure.',
        `${cookie.name} has no explicit SameSite value.`,
        'Set SameSite=Lax or SameSite=Strict when possible. Use SameSite=None only when cross-site use is required and keep Secure enabled.',
      ));
    }

    if (cookie.sameSite === 'no_restriction') {
      findings.push(finding(
        `cookie-samesite-none-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'medium',
        'Sensitive cookie uses SameSite=None',
        'Cross-site cookie delivery can be legitimate, but it should be deliberate because it increases CSRF and session exposure.',
        `${cookie.name} is set with SameSite=None for ${cookie.domain}${cookie.path}.`,
        'Review whether cross-site delivery is actually required. If it is not, prefer SameSite=Lax or SameSite=Strict.',
      ));
    }

    if (!cookie.hostOnly) {
      findings.push(finding(
        `cookie-domain-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'medium',
        'Sensitive cookie uses a broad domain scope',
        'A non-host-only session cookie can be exposed across subdomains and widen fixation or theft risk.',
        `${cookie.name} is scoped to domain ${cookie.domain} instead of staying host-only.`,
        'Prefer host-only cookies for session state unless subdomain sharing is a deliberate requirement.',
      ));
    }

    if (cookie.path === '/' && activePath !== '/') {
      findings.push(finding(
        `cookie-path-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'low',
        'Sensitive cookie uses a broad path scope',
        'A root path cookie is available to the entire origin, which can be broader than necessary for the current application area.',
        `${cookie.name} is scoped to path / while the active page path is ${activePath}.`,
        'Review whether the cookie can be restricted to a narrower application path without breaking the session flow.',
      ));
    }

    if (!cookie.session && hasLongLifetime(cookie.expirationDate, 60 * 60 * 8)) {
      findings.push(finding(
        `cookie-lifetime-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'medium',
        'Long-lived sensitive cookie',
        'Persistent authentication cookies extend the replay window if stolen from the browser.',
        `${cookie.name} persists beyond a short browser session window.`,
        'Keep authentication cookies session-bound or reduce their lifetime and complement them with rotation or re-authentication controls.',
      ));
    }

    if (isHostPrefixCandidate(cookie)) {
      findings.push(finding(
        `cookie-host-prefix-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'low',
        'Sensitive cookie could use the __Host- prefix',
        'The __Host- prefix hardens secure host-only cookies by preventing Domain usage and forcing path=/.',
        `${cookie.name} is Secure, host-only, and scoped to /.`,
        'Consider renaming the cookie with the __Host- prefix if the backend can support the change.',
      ));
    } else if (isSecurePrefixCandidate(cookie)) {
      findings.push(finding(
        `cookie-secure-prefix-${cookie.name}-${cookie.domain}-${cookie.path}`,
        'cookies',
        'low',
        'Sensitive cookie could use the __Secure- prefix',
        'The __Secure- prefix helps signal that the cookie should only be set over secure transport.',
        `${cookie.name} is Secure but does not use a __Secure- or __Host- prefix.`,
        'Consider renaming the cookie with the __Secure- prefix if backend compatibility allows it.',
      ));
    }
  }

  for (const [name, scopedCookies] of cookieNames) {
    if (scopedCookies.length > 1) {
      findings.push(finding(
        `cookie-duplicate-${name}`,
        'cookies',
        'low',
        'Same cookie name reused across scopes',
        'Reusing the same cookie name on different paths or domains complicates session reasoning and can hide scoping issues.',
        `${name} appears ${scopedCookies.length} times with different scopes.`,
        'Avoid reusing the same session cookie name across multiple paths or domain scopes when possible.',
      ));
    }
  }

  return findings;
}

export function getCookieAssessmentSummary(cookies: chrome.cookies.Cookie[], activeUrl: string): CookieAssessmentSummary {
  const counts: Record<CookieAssessmentCategory, number> = {
    'session/auth': 0,
    csrf: 0,
    preference: 0,
    'analytics/other': 0,
  };

  const criticalCookies = new Set<string>();
  const findings = assessCookiesForUrl(cookies, activeUrl);
  for (const cookie of cookies) {
    counts[classifyCookie(cookie.name)] += 1;
  }

  findings.forEach(finding => {
    const match = finding.evidence.match(/^([^\s]+)\s/);
    if (match && (finding.severity === 'high' || finding.severity === 'medium')) {
      criticalCookies.add(match[1]);
    }
  });

  return {
    counts,
    criticalCookies: [...criticalCookies].slice(0, 8),
  };
}

export function getSetCookieAssessmentSummary(
  activeUrl: string,
  requests: CachedRequest[],
  cookies: chrome.cookies.Cookie[],
): SetCookieAssessmentSummary {
  const observations = collectSetCookieObservations(requests, activeUrl);
  const observedNames = new Set<string>();
  let observedCount = 0;
  let sensitiveObservedCount = 0;

  observations.forEach(observation => {
    observation.cookies.forEach(cookie => {
      observedCount += 1;
      observedNames.add(cookie.name);
      if (isSensitiveCookieName(cookie.name)) {
        sensitiveObservedCount += 1;
      }
    });
  });

  const persistedSensitiveNames = [...new Set(
    cookies
      .filter(cookie => isSensitiveCookieName(cookie.name))
      .map(cookie => cookie.name),
  )].slice(0, 8);

  return {
    observedCount,
    sensitiveObservedCount,
    relevantRequestCount: observations.length,
    observedNames: [...observedNames].slice(0, 8),
    persistedSensitiveNames,
  };
}

export function assessStorageTokens(entries: StorageEntry[]): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];

  for (const entry of entries) {
    const looksSensitive = isSensitiveStorageKey(entry);
    if (!looksSensitive) continue;

    if (entry.area === 'localStorage') {
      findings.push(finding(
        `storage-local-${entry.area}-${entry.key}`,
        'storage',
        'high',
        'Sensitive token stored in localStorage',
        'Tokens in localStorage survive browser restarts and remain reachable from JavaScript in the page context.',
        `${entry.key} was found in localStorage on ${entry.area}.`,
        'Prefer HttpOnly cookies for session identifiers or, when browser-side token storage is required, prefer shorter-lived sessionStorage with strong XSS defenses.',
      ));
    } else {
      findings.push(finding(
        `storage-session-${entry.area}-${entry.key}`,
        'storage',
        'medium',
        'Sensitive token stored in sessionStorage',
        'sessionStorage reduces persistence but the token is still exposed to JavaScript and XSS in the page context.',
        `${entry.key} was found in sessionStorage.`,
        'If browser-side token storage is required, keep token lifetime short and harden the application with strong CSP and XSS defenses.',
      ));
    }

    if (!entry.isJwt) continue;
    const decoded = decodeJwt(entry.value);
    if (!decoded.ok) continue;

    const { token } = decoded;
    if (token.header.alg.toLowerCase() === 'none') {
      findings.push(finding(
        `token-none-${entry.area}-${entry.key}`,
        'tokens',
        'high',
        'JWT uses alg=none',
        'Unsigned JWTs should not be trusted for authentication or authorization decisions.',
        `${entry.key} decodes with header alg=none.`,
        'Reject unsigned tokens in the application and require a specific expected signing algorithm during validation.',
      ));
    }

    if (token.expiresAt === undefined) {
      findings.push(finding(
        `token-no-exp-${entry.area}-${entry.key}`,
        'tokens',
        'high',
        'JWT without expiry claim',
        'A token without exp has no built-in browser-visible expiration boundary.',
        `${entry.key} has no exp claim.`,
        'Issue JWTs with explicit expiration and keep access token lifetime short.',
      ));
    } else {
      const lifetimeSeconds = token.payload.iat !== undefined ? token.payload.exp! - token.payload.iat : undefined;
      if (lifetimeSeconds !== undefined && lifetimeSeconds > 60 * 60 * 8) {
        findings.push(finding(
          `token-lifetime-${entry.area}-${entry.key}`,
          'tokens',
          'medium',
          'JWT has a long validity window',
          'Long-lived access tokens increase replay impact if the token is stolen from the browser.',
          `${entry.key} has a visible lifetime longer than 8 hours.`,
          'Use shorter-lived access tokens and rely on rotation or refresh mechanisms with stricter controls.',
        ));
      }

      if (token.isExpired) {
        findings.push(finding(
          `token-expired-${entry.area}-${entry.key}`,
          'tokens',
          'info',
          'Expired JWT still present in browser storage',
          'Expired tokens left in storage are not necessarily exploitable, but they often signal stale client-side auth state.',
          `${entry.key} is expired but still present in ${entry.area}.`,
          'Clear expired tokens during logout and token refresh flows to reduce confusion and stale session artifacts.',
        ));
      }
    }

    const sensitiveClaims = Object.keys(token.payload).filter(key => SENSITIVE_CLAIM_RE.test(key));
    if (sensitiveClaims.length > 0) {
      findings.push(finding(
        `token-claims-${entry.area}-${entry.key}`,
        'tokens',
        'low',
        'JWT payload exposes potentially sensitive claims',
        'JWT payloads are only encoded, not encrypted, unless the application adds extra protection beyond signing.',
        `${entry.key} contains claims such as ${sensitiveClaims.slice(0, 4).join(', ')}.`,
        'Keep JWT payloads minimal and avoid embedding sensitive personal or authorization details unless there is a clear need.',
      ));
    }
  }

  return findings;
}

function assessTokenCandidate(candidate: TokenCandidate): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  const originLabel = candidate.origin === 'manual' ? 'manual input' : candidate.origin;

  if (!candidate.isJwt) {
    if (candidate.origin === 'localStorage') {
      findings.push(finding(
        `opaque-token-local-${candidate.label}`,
        'storage',
        'high',
        'Opaque token-like value stored in localStorage',
        'A non-JWT token-like value was found in localStorage, where it stays reachable from page JavaScript and survives browser restarts.',
        `${candidate.label} contains a long opaque token-like value in localStorage.`,
        'Prefer HttpOnly cookies for browser session state, or reduce token lifetime and harden the application against XSS if browser-side storage is required.',
      ));
    } else if (candidate.origin === 'sessionStorage') {
      findings.push(finding(
        `opaque-token-session-${candidate.label}`,
        'storage',
        'medium',
        'Opaque token-like value stored in sessionStorage',
        'A non-JWT token-like value was found in sessionStorage, which reduces persistence but still exposes the token to page JavaScript.',
        `${candidate.label} contains a long opaque token-like value in sessionStorage.`,
        'Keep browser-stored opaque tokens short-lived and rely on strong XSS defenses if client-side storage cannot be avoided.',
      ));
    } else if (candidate.origin === 'cookie') {
      findings.push(finding(
        `opaque-token-cookie-${candidate.label}`,
        'tokens',
        'info',
        'Opaque token-like value observed in a cookie',
        'The cookie value looks token-like rather than a simple identifier, so it is worth reviewing how the backend treats it.',
        `${candidate.label} contains a long opaque token-like cookie value.`,
        'Review whether the cookie carries a bearer-like token and ensure cookie protections and backend validation rules are appropriate.',
      ));
    }

    return findings;
  }

  const decoded = decodeJwt(candidate.raw);
  if (!decoded.ok) return findings;

  const { token } = decoded;

  if (candidate.origin === 'localStorage') {
    findings.push(finding(
      `jwt-local-${candidate.label}`,
      'storage',
      'high',
      'JWT stored in localStorage',
      'A JWT found in localStorage is accessible to page scripts and survives browser restarts, which increases replay impact if the application is exposed to XSS.',
      `${candidate.label} stores a JWT in localStorage.`,
      'Prefer HttpOnly cookies for browser session tokens, or combine short JWT lifetime with strong XSS defenses when client-side storage is unavoidable.',
    ));
  } else if (candidate.origin === 'sessionStorage') {
    findings.push(finding(
      `jwt-session-${candidate.label}`,
      'storage',
      'medium',
      'JWT stored in sessionStorage',
      'sessionStorage reduces persistence but the JWT is still exposed to page JavaScript in the browser context.',
      `${candidate.label} stores a JWT in sessionStorage.`,
      'Keep session-stored JWTs short-lived and combine them with strong CSP and XSS defenses.',
    ));
  } else if (candidate.origin === 'cookie') {
    findings.push(finding(
      `jwt-cookie-${candidate.label}`,
      'tokens',
      'info',
      'JWT observed in a cookie value',
      'The browser is carrying a structured JWT inside a cookie rather than an opaque session identifier.',
      `${candidate.label} contains a JWT-shaped cookie value.`,
      'Review whether the backend intentionally uses self-contained tokens in cookies and keep cookie protections aligned with the token sensitivity.',
    ));
  } else if (candidate.origin === 'manual') {
    findings.push(finding(
      `jwt-manual-${candidate.label}`,
      'tokens',
      'info',
      'Manual JWT review is based on structure, not trust',
      'The manual token preview can assess payload and expiry signals, but it still does not verify the signature or backend revocation state.',
      'Manual token input is being evaluated without access to the signing key or revocation system.',
      'Treat manual JWT review as a structural inspection aid rather than proof that the token is trusted by the backend.',
    ));
  }

  if (token.header.alg.toLowerCase() === 'none') {
    findings.push(finding(
      `token-none-${candidate.label}`,
      'tokens',
      'high',
      'JWT uses alg=none',
      'Unsigned JWTs should not be trusted for authentication or authorization decisions.',
      `${candidate.label} from ${originLabel} decodes with header alg=none.`,
      'Reject unsigned tokens in the application and require a specific expected signing algorithm during validation.',
    ));
  }

  if (token.expiresAt === undefined) {
    findings.push(finding(
      `token-no-exp-${candidate.label}`,
      'tokens',
      'high',
      'JWT without expiry claim',
      'A token without exp has no built-in browser-visible expiration boundary.',
      `${candidate.label} from ${originLabel} has no exp claim.`,
      'Issue JWTs with explicit expiration and keep access token lifetime short.',
    ));
  } else {
    const lifetimeSeconds = token.payload.iat !== undefined ? token.payload.exp! - token.payload.iat : undefined;
    if (lifetimeSeconds !== undefined && lifetimeSeconds > 60 * 60 * 8) {
      findings.push(finding(
        `token-lifetime-${candidate.label}`,
        'tokens',
        'medium',
        'JWT has a long validity window',
        'Long-lived access tokens increase replay impact if the token is stolen from the browser.',
        `${candidate.label} from ${originLabel} has a visible lifetime longer than 8 hours.`,
        'Use shorter-lived access tokens and rely on rotation or refresh mechanisms with stricter controls.',
      ));
    }

    if (token.isExpired) {
      findings.push(finding(
        `token-expired-${candidate.label}`,
        'tokens',
        candidate.origin === 'manual' ? 'low' : 'info',
        'Expired JWT still present in review context',
        'Expired tokens are not necessarily exploitable, but they often signal stale client-side auth state or confusing operational handling.',
        `${candidate.label} from ${originLabel} is expired but still present in the current review context.`,
        'Clear expired tokens during logout and refresh flows, and review whether expired examples are still being distributed or persisted.',
      ));
    }
  }

  const payloadKeys = Object.keys(token.payload);
  const sensitiveClaims = payloadKeys.filter(key => SENSITIVE_CLAIM_RE.test(key));
  if (sensitiveClaims.length > 0) {
    findings.push(finding(
      `token-claims-${candidate.label}`,
      'tokens',
      'low',
      'JWT payload exposes potentially sensitive claims',
      'JWT payloads are only encoded, not encrypted, unless the application adds extra protection beyond signing.',
      `${candidate.label} from ${originLabel} contains claims such as ${sensitiveClaims.slice(0, 4).join(', ')}.`,
      'Keep JWT payloads minimal and avoid embedding sensitive personal or authorization details unless there is a clear need.',
    ));
  }

  if (payloadKeys.length > 12 || candidate.raw.length > 1500) {
    findings.push(finding(
      `token-excessive-${candidate.label}`,
      'tokens',
      'low',
      'JWT payload is claim-heavy or oversized',
      'Large or claim-heavy JWTs often carry more information than the browser needs and increase exposure if the token is leaked.',
      `${candidate.label} from ${originLabel} has ${payloadKeys.length} payload claims and raw length ${candidate.raw.length}.`,
      'Review whether the JWT can be reduced to the minimum claims required by the browser and backend flow.',
    ));
  }

  return findings;
}

export function assessBrowserTokens(cookies: chrome.cookies.Cookie[], entries: StorageEntry[]): AssessmentFinding[] {
  return collectTokenCandidates(cookies, entries).flatMap(candidate => assessTokenCandidate(candidate));
}

export function assessManualToken(raw: string): AssessmentFinding[] {
  return collectTokenCandidates([], [], raw).flatMap(candidate => assessTokenCandidate(candidate));
}

export function getTokenAssessmentSummary(
  cookies: chrome.cookies.Cookie[],
  entries: StorageEntry[],
  manualValue?: string,
): TokenAssessmentSummary {
  const candidates = collectTokenCandidates(cookies, entries, manualValue);
  const counts: Record<TokenAssessmentOrigin, number> = {
    cookie: 0,
    localStorage: 0,
    sessionStorage: 0,
    manual: 0,
  };
  let jwtCount = 0;
  let opaqueCount = 0;
  const labels = new Set<string>();

  candidates.forEach(candidate => {
    counts[candidate.origin] += 1;
    if (candidate.isJwt) jwtCount += 1;
    else opaqueCount += 1;
    labels.add(candidate.label);
  });

  return {
    observedCount: candidates.length,
    jwtCount,
    opaqueCount,
    counts,
    labels: [...labels].slice(0, 8),
  };
}

export function assessHeaders(activeUrl: string, requests: CachedRequest[]): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  const primaryRequest = getPrimaryRequest(requests, activeUrl);
  if (!primaryRequest) {
    return [finding(
      'headers-missing-capture',
      'headers',
      'info',
      'No captured response headers yet',
      'The assessment can evaluate browser-visible hardening only after requests have been captured for the current tab.',
      'No response headers are available in the session cache for this tab.',
      'Reload or navigate the page so the extension can capture the document response and recent network requests.',
    )];
  }

  const { missing, warning } = evaluatePrimaryHeaders(primaryRequest);
  if (missing.length > 0) {
    findings.push(headerFinding(
      `headers-missing-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Missing key browser security headers',
      'The latest document response is missing one or more headers commonly used to harden the browser execution context.',
      'Missing hardening headers leave the browser with fewer built-in protections against injection, framing abuse, MIME confusion, and unsafe cross-origin behavior.',
      `Missing: ${missing.join(', ')}.`,
      'Add the missing security headers to the main HTML document response and verify them across authenticated and unauthenticated flows.',
    ));
  }

  warning.forEach((message, index) => {
    findings.push(headerFinding(
      `headers-warning-${index}-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Security header value differs from common OWASP guidance',
      'The response includes the header, but its value weakens or complicates the intended browser protection.',
      'A weak header value can create a false sense of protection because the control exists but still allows risky browser behavior.',
      message,
      'Tighten the response header value for the main document and validate the change on real browser traffic.',
    ));
  });

  const server = firstHeaderValue(primaryRequest, 'server');
  if (server) {
    findings.push(headerFinding(
      `headers-server-${hostnameFromUrl(primaryRequest.url)}`,
      'low',
      'Server header discloses backend details',
      'Backend technology disclosure can help attackers refine fingerprinting and exploit selection.',
      'Reducing platform disclosure raises the cost of reconnaissance and makes opportunistic targeting less precise.',
      `Server: ${server}`,
      'Remove or generalize the Server header where the platform allows it.',
    ));
  }

  const poweredBy = firstHeaderValue(primaryRequest, 'x-powered-by');
  if (poweredBy) {
    findings.push(headerFinding(
      `headers-powered-by-${hostnameFromUrl(primaryRequest.url)}`,
      'low',
      'X-Powered-By header discloses framework details',
      'Technology disclosure lowers the cost of reconnaissance against the application stack.',
      'Framework disclosure makes it easier to align exploit attempts with known middleware and framework behavior.',
      `X-Powered-By: ${poweredBy}`,
      'Remove X-Powered-By headers at the application server, framework, or reverse proxy layer.',
    ));
  }

  const cacheControl = firstHeaderValue(primaryRequest, 'cache-control')?.toLowerCase();
  const varyHeader = firstHeaderValue(primaryRequest, 'vary');
  const setCookieObservations = collectSetCookieObservations(requests, activeUrl);
  const setCookieEntries = setCookieObservations.flatMap(observation =>
    observation.cookies.map(cookie => ({ request: observation.request, cookie })),
  );
  const primarySetCookieCount = allHeaderValues(primaryRequest, 'set-cookie').length;
  if (primarySetCookieCount > 0 && !cacheControl) {
    findings.push(headerFinding(
      `headers-cache-missing-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Sensitive response is missing Cache-Control guidance',
      'The primary response sets cookies but does not declare browser caching behavior.',
      'Without explicit cache directives, browsers and intermediaries may keep sensitive responses longer than intended.',
      'The primary response sets cookies and does not include Cache-Control.',
      'Add Cache-Control guidance for login and authenticated document responses, typically including no-store when sensitive state or content is involved.',
    ));
  } else if (primarySetCookieCount > 0 && cacheControl !== undefined && !cacheControl.includes('no-store')) {
    findings.push(headerFinding(
      `headers-cache-weak-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Sensitive response uses weak Cache-Control',
      'The response includes cache directives, but it still lacks a strong no-store instruction for a cookie-establishing response.',
      'Login and authenticated responses can leak sensitive content through browser history, cache, or shared machine artifacts when caching is too permissive.',
      `Cache-Control is ${cacheControl} while the primary response sets cookies.`,
      'Review caching headers on authenticated and login-related responses and add no-store where sensitive state or content is returned.',
    ));
  }

  const logoutRequests = requests.filter(request => hostnameFromUrl(request.url) === hostnameFromUrl(activeUrl) && looksLikeLogoutEndpoint(request.url));
  if (logoutRequests.length > 0) {
    logoutRequests.forEach((request, index) => {
      const directives = parseClearSiteData(firstHeaderValue(request, 'clear-site-data'));
      if (directives.length === 0) {
        findings.push(headerFinding(
          `headers-clear-site-data-missing-${index}-${hostnameFromUrl(request.url)}`,
          'medium',
          'Logout-like response is missing Clear-Site-Data',
          'A captured logout or session-termination response did not request browser-side cleanup of cached state.',
          'Logout flows can leave cookies, cached documents, or web storage artifacts behind unless the browser is asked to clear them explicitly.',
          `${request.method} ${request.url} looks logout-related and does not include Clear-Site-Data.`,
          'Consider adding Clear-Site-Data on logout or end-session responses when the application expects browser-side state to be cleared.',
        ));
      } else if (!['cache', 'cookies', 'storage'].every(value => directives.includes(value) || directives.includes('*'))) {
        findings.push(headerFinding(
          `headers-clear-site-data-weak-${index}-${hostnameFromUrl(request.url)}`,
          'low',
          'Logout-like response uses partial Clear-Site-Data cleanup',
          'The response tries to clear browser state, but the directive set is narrower than a full session cleanup pattern.',
          'Partial cleanup can leave residual cookies, cached data, or storage artifacts after logout.',
          `${request.method} ${request.url} returns Clear-Site-Data=${directives.join(', ')}.`,
          'Review whether logout should clear cookies, storage, and cache together for this application flow.',
        ));
      }
    });
  } else {
    findings.push(headerFinding(
      `headers-clear-site-data-not-applicable-${hostnameFromUrl(primaryRequest.url)}`,
      'info',
      'Clear-Site-Data was not applicable in the captured flow',
      'No logout or end-session response was captured in the current browser-visible session.',
      'Clear-Site-Data is most meaningful on logout or explicit session cleanup responses, not on every page load.',
      'No same-host logout-like response was observed among the captured requests.',
      'Capture a logout flow if you want the assessment to evaluate browser-side cleanup headers.',
    ));
  }

  const acao = firstHeaderValue(primaryRequest, 'access-control-allow-origin');
  const acac = firstHeaderValue(primaryRequest, 'access-control-allow-credentials');
  if (acao === '*' && acac?.toLowerCase() === 'true') {
    findings.push(headerFinding(
      `headers-cors-credentials-${hostnameFromUrl(primaryRequest.url)}`,
      'high',
      'CORS policy mixes wildcard origin and credentials',
      'Credentialed cross-origin access should not be combined with a wildcard allow-origin policy.',
      'This combination can let any origin attempt authenticated cross-site access, which defeats the point of restricting credentialed CORS.',
      'Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.',
      'Use explicit trusted origins for credentialed CORS responses and review whether cross-origin credentials are required at all.',
    ));
  } else if (acao === '*') {
    findings.push(headerFinding(
      `headers-cors-wildcard-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Wildcard CORS policy present',
      'A wildcard allow-origin policy can be correct for public resources, but it should be deliberate and reviewed for sensitive endpoints.',
      'Broad CORS policies increase the chance that sensitive responses become reachable from untrusted web origins.',
      'Access-Control-Allow-Origin is * on the primary response.',
      'Limit CORS to explicit origins unless the resource is intentionally public and unauthenticated.',
    ));
  } else if (acao && acac?.toLowerCase() === 'true' && !hasOriginVary(varyHeader)) {
    findings.push(headerFinding(
      `headers-cors-vary-origin-${hostnameFromUrl(primaryRequest.url)}`,
      'medium',
      'Credentialed CORS response is missing Vary: Origin',
      'The response appears to allow credentials for a specific origin but does not vary caches by Origin.',
      'Without Vary: Origin, shared caches can reuse a response across origins even when the server reflects or selects origins dynamically.',
      `Access-Control-Allow-Origin is ${acao}, Access-Control-Allow-Credentials is true, and Vary does not include Origin.`,
      'Add Vary: Origin when the server serves origin-dependent CORS responses, especially for credentialed flows.',
    ));
  } else {
    findings.push(headerFinding(
      `headers-cors-vary-origin-not-applicable-${hostnameFromUrl(primaryRequest.url)}`,
      'info',
      'Vary: Origin was not applicable in the current primary response',
      'The current primary response does not expose a credentialed origin-specific CORS pattern that would require Vary: Origin review.',
      'Vary: Origin is mainly relevant when responses change per caller origin, especially with credentialed CORS.',
      'The captured primary response does not show an explicit credentialed origin-specific CORS configuration.',
      'Capture a credentialed cross-origin flow if you want the assessment to review Vary: Origin behavior.',
    ));
  }

  if (setCookieEntries.length > 0) {
    findings.push(finding(
      `set-cookie-observed-${hostnameFromUrl(primaryRequest.url)}`,
      'cookies',
      'info',
      'Observed Set-Cookie delivery on relevant responses',
      'The assessment captured cookies directly from server responses in addition to the browser cookie jar.',
      `${setCookieEntries.length} Set-Cookie headers were observed across ${setCookieObservations.length} relevant responses.`,
      'Compare response-delivered cookies with the browser cookie jar to spot scope, persistence, and delivery mismatches.',
    ));
  }

  setCookieEntries.forEach(({ request, cookie: parsed }, index) => {
    if (!isSensitiveCookieName(parsed.name)) return;

    const requestDescriptor = `${request.resourceType} ${request.method} ${request.url}`;

    if (!parsed.secure) {
      findings.push(finding(
        `set-cookie-secure-${index}-${parsed.name}`,
        'cookies',
        'high',
        'Set-Cookie for a sensitive cookie is missing Secure',
        'A session or auth cookie delivered without Secure can be exposed over non-TLS traffic if the browser is induced to use HTTP.',
        `${requestDescriptor} sets ${parsed.name} without Secure.`,
        'Add the Secure attribute to session and authentication cookies and ensure the application stays on HTTPS.',
      ));
    }

    if (!parsed.httpOnly) {
      findings.push(finding(
        `set-cookie-httponly-${index}-${parsed.name}`,
        'cookies',
        'high',
        'Set-Cookie for a sensitive cookie is missing HttpOnly',
        'A script-accessible auth cookie raises XSS-driven theft risk before the cookie is ever persisted.',
        `${requestDescriptor} sets ${parsed.name} without HttpOnly.`,
        'Add HttpOnly to authentication and session cookies unless browser-side script access is strictly necessary.',
      ));
    }

    if (parsed.sameSite === undefined) {
      findings.push(finding(
        `set-cookie-samesite-${index}-${parsed.name}`,
        'cookies',
        'medium',
        'Set-Cookie for a sensitive cookie has no explicit SameSite',
        'Setting SameSite explicitly makes CSRF posture easier to reason about and review.',
        `${requestDescriptor} sets ${parsed.name} without SameSite.`,
        'Set SameSite=Lax or SameSite=Strict when possible. Use SameSite=None only when cross-site behavior is required and keep Secure enabled.',
      ));
    }

    if (parsed.sameSite === 'none' && !parsed.secure) {
      findings.push(finding(
        `set-cookie-samesite-none-insecure-${index}-${parsed.name}`,
        'cookies',
        'high',
        'Set-Cookie uses SameSite=None without Secure',
        'Cross-site cookies with SameSite=None should also be marked Secure to avoid unsafe delivery patterns.',
        `${requestDescriptor} sets ${parsed.name} with SameSite=None and no Secure flag.`,
        'Pair SameSite=None with Secure and review whether the cookie truly needs cross-site delivery.',
      ));
    }

    if (parsed.path === '/' && request.resourceType === 'xmlhttprequest' && looksLikeAuthEndpoint(request.url)) {
      findings.push(finding(
        `set-cookie-path-${index}-${parsed.name}`,
        'cookies',
        'low',
        'Set-Cookie delivered from an auth endpoint uses path=/',
        'Cookies issued by authentication callbacks or token refresh APIs are often broader than necessary when scoped to the root path.',
        `${requestDescriptor} sets ${parsed.name} with Path=/.`,
        'Review whether the cookie can be scoped to a narrower path without breaking the authentication flow.',
      ));
    }
  });

  return findings;
}

export function buildAssessmentFindings(params: {
  activeUrl: string;
  cookies: chrome.cookies.Cookie[];
  storageEntries: StorageEntry[];
  requests: CachedRequest[];
}): AssessmentFinding[] {
  const findings = [
    ...assessCookiesForUrl(params.cookies, params.activeUrl),
    ...assessBrowserTokens(params.cookies, params.storageEntries),
    ...assessHeaders(params.activeUrl, params.requests),
  ];

  const unique = new Map<string, AssessmentFinding>();
  for (const item of findings) {
    if (!unique.has(item.id)) unique.set(item.id, item);
  }

  const severityWeight: Record<AssessmentFinding['severity'], number> = {
    high: 0,
    medium: 1,
    low: 2,
    info: 3,
  };

  return [...unique.values()].sort((left, right) => {
    const severityDelta = severityWeight[left.severity] - severityWeight[right.severity];
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

export function getFindingCounts(findings: AssessmentFinding[]): Record<AssessmentFinding['severity'], number> {
  return findings.reduce<Record<AssessmentFinding['severity'], number>>((acc, finding) => {
    acc[finding.severity] += 1;
    return acc;
  }, {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  });
}