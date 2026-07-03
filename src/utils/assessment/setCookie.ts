import type { CachedRequest, SetCookieAssessmentSummary } from '../../types';
import { allHeaderValues, hostnameFromUrl, looksLikeAuthEndpoint } from './shared';
import { isSensitiveCookieName } from './classification';

export interface ParsedSetCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  partitioned: boolean;
  sameSite?: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: string;
}

export interface RequestSetCookieObservation {
  request: CachedRequest;
  cookies: ParsedSetCookie[];
}

export function parseSetCookie(headerValue: string): ParsedSetCookie | null {
  const [nameValue, ...attributeParts] = headerValue.split(';');
  const separatorIndex = nameValue.indexOf('=');
  if (separatorIndex <= 0) return null;

  const parsed: ParsedSetCookie = {
    name: nameValue.slice(0, separatorIndex).trim(),
    value: nameValue.slice(separatorIndex + 1).trim(),
    secure: false,
    httpOnly: false,
    partitioned: false,
  };

  for (const rawAttribute of attributeParts) {
    const attribute = rawAttribute.trim();
    const [rawKey, ...rawRest] = attribute.split('=');
    const key = rawKey.toLowerCase();
    const value = rawRest.join('=').trim();

    if (key === 'secure') parsed.secure = true;
    else if (key === 'httponly') parsed.httpOnly = true;
    else if (key === 'partitioned') parsed.partitioned = true;
    else if (key === 'samesite') parsed.sameSite = value.toLowerCase();
    else if (key === 'domain') parsed.domain = value;
    else if (key === 'path') parsed.path = value;
    else if (key === 'expires') parsed.expires = value;
    else if (key === 'max-age') parsed.maxAge = value;
  }

  return parsed;
}

export function isRelevantSetCookieRequest(request: CachedRequest, activeUrl: string): boolean {
  const activeHostname = hostnameFromUrl(activeUrl);
  const requestHostname = hostnameFromUrl(request.url);
  const sameHost = requestHostname !== '' && requestHostname === activeHostname;
  if (!sameHost) return false;

  if (request.resourceType === 'main_frame' || request.resourceType === 'sub_frame') return true;
  if (request.resourceType === 'xmlhttprequest' && looksLikeAuthEndpoint(request.url)) return true;
  return false;
}

export function collectSetCookieObservations(requests: CachedRequest[], activeUrl: string): RequestSetCookieObservation[] {
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
