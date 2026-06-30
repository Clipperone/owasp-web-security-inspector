import type { AssessmentFinding, CookieAssessmentCategory, CookieAssessmentSummary } from '../../types';
import { finding, pathnameFromUrl } from './shared';
import {
  classifyCookie,
  hasLongLifetime,
  isHostPrefixCandidate,
  isSecurePrefixCandidate,
  isSensitiveCookieName,
} from './classification';

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
