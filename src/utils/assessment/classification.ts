import type { CookieAssessmentCategory, StorageEntry } from '../../types';
import { isJwt } from '../jwtUtils';

export const EXACT_SENSITIVE_COOKIE_NAMES = new Set([
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
export const SENSITIVE_COOKIE_SEGMENT_RE = /(^|[-_.])(session|sess|auth|token|jwt|bearer|access|refresh)([-_.]|$)/i;
export const SENSITIVE_CLAIM_RE = /(^email$|mail|phone|roles?$|scope|permission|tenant|customer|account|user(name|id)?$)/i;
export const CSRF_COOKIE_RE = /(^|[-_.])(csrf|xsrf|antiforgery|requestverificationtoken)([-_.]|$)/i;
export const PREFERENCE_COOKIE_RE = /(^|[-_.])(pref|theme|lang|locale|consent|currency|timezone|tz)([-_.]|$)/i;
export const ANALYTICS_COOKIE_RE = /(^|[-_.])(_ga|_gid|_gat|ga|amplitude|mixpanel|analytics|segment)([-_.]|$)/i;
export const TOKEN_NAMING_RE = /(^|[-_.])(access|refresh|id|jwt|token|bearer|auth)([-_.]|$)/i;
export const BEARER_VALUE_RE = /^bearer\s+[a-z0-9\-._~+/]+=*$/i;
export const OPAQUE_TOKEN_VALUE_RE = /^[A-Za-z0-9\-._~+/]+=*$/;

export function isSensitiveCookieName(name: string): boolean {
  const normalized = name.trim().toLowerCase();
  return EXACT_SENSITIVE_COOKIE_NAMES.has(normalized)
    || normalized.startsWith('__secure-')
    || normalized.startsWith('__host-')
    || SENSITIVE_COOKIE_SEGMENT_RE.test(normalized);
}

export function isSensitiveStorageKey(entry: StorageEntry): boolean {
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

export function isOpaqueTokenValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 24) return false;
  if (trimmed.includes(' ')) {
    return BEARER_VALUE_RE.test(trimmed);
  }

  return OPAQUE_TOKEN_VALUE_RE.test(trimmed);
}

export function classifyCookie(name: string): CookieAssessmentCategory {
  const normalized = name.trim().toLowerCase();
  if (isSensitiveCookieName(normalized)) return 'session/auth';
  if (CSRF_COOKIE_RE.test(normalized)) return 'csrf';
  if (PREFERENCE_COOKIE_RE.test(normalized)) return 'preference';
  return ANALYTICS_COOKIE_RE.test(normalized) ? 'analytics/other' : 'analytics/other';
}

export function shouldTreatCookieAsToken(cookie: chrome.cookies.Cookie): boolean {
  return isJwt(cookie.value)
    || (TOKEN_NAMING_RE.test(cookie.name.toLowerCase()) && isOpaqueTokenValue(cookie.value));
}

export function hasLongLifetime(expirationDate: number | undefined, thresholdSeconds: number): boolean {
  if (expirationDate === undefined) return false;
  return expirationDate - Math.floor(Date.now() / 1000) > thresholdSeconds;
}

export function isHostPrefixCandidate(cookie: chrome.cookies.Cookie): boolean {
  return cookie.secure && cookie.hostOnly && cookie.path === '/' && !cookie.name.startsWith('__Host-');
}

export function isSecurePrefixCandidate(cookie: chrome.cookies.Cookie): boolean {
  return cookie.secure && !cookie.name.startsWith('__Host-') && !cookie.name.startsWith('__Secure-');
}
