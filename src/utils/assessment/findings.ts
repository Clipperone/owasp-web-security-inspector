import type {
  AssessmentFinding,
  CachedRequest,
  ObservedWebSocket,
  PageResourceObservation,
  StorageEntry,
  TransportDomObservation,
} from '../../types';
import {
  allHeaderValues,
  finding,
  firstHeaderValue,
  getPrimaryRequest,
  hasOriginVary,
  headerFinding,
  hostnameFromUrl,
  looksLikeAuthEndpoint,
  looksLikeLogoutEndpoint,
  parseClearSiteData,
} from './shared';
import { isSensitiveCookieName } from './classification';
import { collectSetCookieObservations } from './setCookie';
import { assessCsp } from './csp';
import { evaluatePrimaryHeaders } from './headers';
import { assessCookiesForUrl } from './cookies';
import { assessBrowserTokens } from './tokens';
import {
  assessMixedContent,
  assessSubresourceIntegrity,
  assessThirdParties,
  assessWebSockets,
} from './pageResources';

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

  findings.push(...assessCsp(primaryRequest));

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
  // Optional M5 inputs — absent inputs simply yield no additional findings.
  pageResources?: PageResourceObservation | null;
  domObservation?: TransportDomObservation | null;
  webSockets?: ObservedWebSocket[];
}): AssessmentFinding[] {
  const findings = [
    ...assessCookiesForUrl(params.cookies, params.activeUrl),
    ...assessBrowserTokens(params.cookies, params.storageEntries),
    ...assessHeaders(params.activeUrl, params.requests),
    ...assessSubresourceIntegrity(params.pageResources ?? null),
    ...assessMixedContent(params.activeUrl, params.requests, params.pageResources ?? null, params.domObservation ?? null),
    ...assessWebSockets(params.activeUrl, params.webSockets ?? []),
    ...assessThirdParties(params.activeUrl, params.requests, params.cookies),
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
