import type { AssessmentFinding, CachedRequest } from '../../types';

export function finding(
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

export function headerFinding(
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

export function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

export function firstHeaderValue(req: CachedRequest, name: string): string | undefined {
  return req.responseHeaders.find(header => header.name.toLowerCase() === name)?.value;
}

export function allHeaderValues(req: CachedRequest, name: string): string[] {
  return req.responseHeaders
    .filter(header => header.name.toLowerCase() === name)
    .map(header => header.value);
}

export function isHttpsUrl(url: string): boolean {
  return url.startsWith('https://');
}

export function normalizeHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

export function normalizeCaseInsensitive(value: string): string {
  return normalizeHeaderValue(value).toLowerCase();
}

export function normalizeCommaSeparatedValue(value: string): string {
  return value
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .join(', ')
    .toLowerCase();
}

export function normalizeSemicolonSeparatedValue(value: string): string {
  return value
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .join('; ')
    .toLowerCase();
}

export function sameNormalizedValue(value: string, expected: string): boolean {
  return normalizeCaseInsensitive(value) === normalizeCaseInsensitive(expected);
}

export function sameCommaSeparatedValue(value: string, expected: string): boolean {
  return normalizeCommaSeparatedValue(value) === normalizeCommaSeparatedValue(expected);
}

export function sameSemicolonSeparatedValue(value: string, expected: string): boolean {
  return normalizeSemicolonSeparatedValue(value) === normalizeSemicolonSeparatedValue(expected);
}

export function formatObservedValues(values: string[]): string {
  return values.length > 0 ? values.map(value => normalizeHeaderValue(value)).join(' | ') : 'Not observed.';
}

export function pathnameFromUrl(url: string): string {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return '/';
  }
}

export function looksLikeAuthEndpoint(url: string): boolean {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return /(^|\/)(login|signin|sign-in|auth|oauth|sso|callback|session|token|refresh)(\/|$)/.test(pathname);
  } catch {
    return false;
  }
}

export function looksLikeLogoutEndpoint(url: string): boolean {
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return /(^|\/)(logout|signout|sign-out|logoff|revoke|endsession|end-session)(\/|$)/.test(pathname);
  } catch {
    return false;
  }
}

export function hasOriginVary(value: string | undefined): boolean {
  if (!value) return false;
  return value
    .split(',')
    .map(part => part.trim().toLowerCase())
    .includes('origin');
}

export function parseClearSiteData(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map(part => part.trim().replace(/^"|"$/g, '').toLowerCase())
    .filter(Boolean);
}

export function getPrimaryRequest(requests: CachedRequest[], activeUrl: string): CachedRequest | null {
  const activeHostname = hostnameFromUrl(activeUrl);
  return requests.find(req => req.resourceType === 'main_frame')
    ?? requests.find(req => req.resourceType === 'sub_frame' && hostnameFromUrl(req.url) === activeHostname)
    ?? requests.find(req => hostnameFromUrl(req.url) === activeHostname)
    ?? requests[0]
    ?? null;
}
