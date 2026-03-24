import type {
  AssessmentFinding,
  CachedRequest,
  CookieAssessmentCategory,
  CookieAssessmentSummary,
  StorageEntry,
} from '../types';
import { decodeJwt } from './jwtUtils';

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
      const maxAgeDirective = normalized.split(';').map(part => part.trim()).find(part => part.startsWith('max-age='));
      const maxAge = maxAgeDirective ? Number.parseInt(maxAgeDirective.slice(8), 10) : NaN;
      if (!Number.isFinite(maxAge) || maxAge < 63072000) {
        warning.push('Strict-Transport-Security max-age is below the common OWASP reference value.');
      }
    }
  }

  if (!xfo) missing.push('X-Frame-Options');
  else if (xfo.trim().toUpperCase() !== 'DENY' && xfo.trim().toUpperCase() !== 'SAMEORIGIN') {
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
    findings.push(finding(
      `headers-missing-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'medium',
      'Missing key browser security headers',
      'The latest document response is missing one or more headers commonly used to harden the browser execution context.',
      `Missing: ${missing.join(', ')}.`,
      'Add the missing security headers to the main HTML document response and verify them across authenticated and unauthenticated flows.',
    ));
  }

  warning.forEach((message, index) => {
    findings.push(finding(
      `headers-warning-${index}-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'medium',
      'Security header value differs from common OWASP guidance',
      'The response includes the header, but its value weakens or complicates the intended browser protection.',
      message,
      'Tighten the response header value for the main document and validate the change on real browser traffic.',
    ));
  });

  const server = firstHeaderValue(primaryRequest, 'server');
  if (server) {
    findings.push(finding(
      `headers-server-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'low',
      'Server header discloses backend details',
      'Backend technology disclosure can help attackers refine fingerprinting and exploit selection.',
      `Server: ${server}`,
      'Remove or generalize the Server header where the platform allows it.',
    ));
  }

  const poweredBy = firstHeaderValue(primaryRequest, 'x-powered-by');
  if (poweredBy) {
    findings.push(finding(
      `headers-powered-by-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'low',
      'X-Powered-By header discloses framework details',
      'Technology disclosure lowers the cost of reconnaissance against the application stack.',
      `X-Powered-By: ${poweredBy}`,
      'Remove X-Powered-By headers at the application server, framework, or reverse proxy layer.',
    ));
  }

  const cacheControl = firstHeaderValue(primaryRequest, 'cache-control')?.toLowerCase();
  const setCookies = allHeaderValues(primaryRequest, 'set-cookie');
  if (setCookies.length > 0 && (!cacheControl || !cacheControl.includes('no-store'))) {
    findings.push(finding(
      `headers-cache-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'medium',
      'Sensitive response may be cacheable',
      'Responses that establish session state should usually avoid being stored in browser caches.',
      'The primary response sets cookies but does not visibly include Cache-Control: no-store.',
      'Review caching headers on authenticated and login-related responses and add no-store where sensitive state or content is returned.',
    ));
  }

  const acao = firstHeaderValue(primaryRequest, 'access-control-allow-origin');
  const acac = firstHeaderValue(primaryRequest, 'access-control-allow-credentials');
  if (acao === '*' && acac?.toLowerCase() === 'true') {
    findings.push(finding(
      `headers-cors-credentials-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'high',
      'CORS policy mixes wildcard origin and credentials',
      'Credentialed cross-origin access should not be combined with a wildcard allow-origin policy.',
      'Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.',
      'Use explicit trusted origins for credentialed CORS responses and review whether cross-origin credentials are required at all.',
    ));
  } else if (acao === '*') {
    findings.push(finding(
      `headers-cors-wildcard-${hostnameFromUrl(primaryRequest.url)}`,
      'headers',
      'medium',
      'Wildcard CORS policy present',
      'A wildcard allow-origin policy can be correct for public resources, but it should be deliberate and reviewed for sensitive endpoints.',
      'Access-Control-Allow-Origin is * on the primary response.',
      'Limit CORS to explicit origins unless the resource is intentionally public and unauthenticated.',
    ));
  }

  setCookies.forEach((headerValue, index) => {
    const parsed = parseSetCookie(headerValue);
    if (!parsed || !isSensitiveCookieName(parsed.name)) return;

    if (!parsed.secure) {
      findings.push(finding(
        `set-cookie-secure-${index}-${parsed.name}`,
        'cookies',
        'high',
        'Set-Cookie for a sensitive cookie is missing Secure',
        'A session or auth cookie delivered without Secure can be exposed over non-TLS traffic if the browser is induced to use HTTP.',
        `Set-Cookie ${parsed.name} does not include Secure.`,
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
        `Set-Cookie ${parsed.name} does not include HttpOnly.`,
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
        `Set-Cookie ${parsed.name} has no SameSite attribute.`,
        'Set SameSite=Lax or SameSite=Strict when possible. Use SameSite=None only when cross-site behavior is required and keep Secure enabled.',
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
    ...assessStorageTokens(params.storageEntries),
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