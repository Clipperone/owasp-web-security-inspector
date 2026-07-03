/**
 * @file pageResources.ts
 * @description Additional browser-observable controls (milestone M5):
 * Subresource Integrity, mixed content / insecure forms, insecure WebSockets,
 * and a best-effort third-party inventory. All findings use the `transport`
 * category and surface under the Transport tab alongside the TLS panel.
 *
 * Limitations (browser-side only):
 *   - SRI is checked against the same-document DOM captured at scan time;
 *     dynamically injected or late-loaded resources may be missed until re-scan,
 *     and `integrityValid` is a format check, not a hash verification.
 *   - Mixed-content / downgrade signals reuse `computeDowngradeSignals` so they
 *     never contradict the Transport panel's narrative.
 *   - WebSocket handshakes opened before the background listener registered are
 *     missed; only the handshake URL is visible.
 *   - Third-party grouping uses an eTLD+1 heuristic (see site.ts), so all
 *     third-party findings are INFO-level.
 */

import type {
  AssessmentFinding,
  CachedRequest,
  ObservedWebSocket,
  PageResourceObservation,
  TransportDomObservation,
} from '../../types';
import { computeDowngradeSignals } from '../transportTls/helpers';
import { finding, hostnameFromUrl } from './shared';
import { isSameSite } from './site';

// ── Subresource Integrity ──────────────────────────────────────────────────

export function assessSubresourceIntegrity(resources: PageResourceObservation | null): AssessmentFinding[] {
  if (!resources) return [];

  const findings: AssessmentFinding[] = [];
  const all = [...resources.scripts, ...resources.stylesheets];

  for (const resource of all) {
    const host = hostnameFromUrl(resource.url);

    if (resource.crossOrigin && !resource.hasIntegrity) {
      if (resource.kind === 'script') {
        findings.push(finding(
          `resource-sri-script-missing-${host}`,
          'transport',
          'medium',
          'Cross-origin script without Subresource Integrity',
          'A cross-origin <script> loads without an integrity attribute, so a swapped or compromised file would execute unmodified.',
          `${resource.url} is cross-origin and has no integrity attribute.`,
          'Add integrity="sha384-…" and crossorigin="anonymous" to the script, or self-host it.',
        ));
      } else {
        findings.push(finding(
          `resource-sri-style-missing-${host}`,
          'transport',
          'low',
          'Cross-origin stylesheet without Subresource Integrity',
          'A cross-origin stylesheet loads without an integrity attribute.',
          `${resource.url} is cross-origin and has no integrity attribute.`,
          'Add integrity + crossorigin to the <link>, or self-host the stylesheet.',
        ));
      }
    } else if (resource.hasIntegrity && resource.integrityValid === false) {
      findings.push(finding(
        `resource-sri-malformed-${resource.kind}-${host}`,
        'transport',
        'low',
        'Subresource integrity attribute is malformed',
        'An integrity attribute is present but is not a valid sha256/384/512 digest, so the browser ignores it and provides no protection.',
        `${resource.url} has an integrity value that is not a valid sha256/384/512 hash.`,
        'Fix the integrity value to a valid sha384-<base64> digest.',
      ));
    }
  }

  return findings;
}

// ── Mixed content / insecure forms ──────────────────────────────────────────

export function assessMixedContent(
  activeUrl: string,
  requests: CachedRequest[],
  resources: PageResourceObservation | null,
  domObservation: TransportDomObservation | null,
): AssessmentFinding[] {
  const signals = computeDowngradeSignals({ activeUrl, requests, domObservation });
  if (!signals.pageIsHttps) return [];

  const host = hostnameFromUrl(activeUrl);
  const findings: AssessmentFinding[] = [];

  const httpResources = resources
    ? [...resources.scripts, ...resources.stylesheets].filter(resource => resource.url.startsWith('http://'))
    : [];
  const activeCount = signals.httpFetches.length + httpResources.length + signals.redirectsToHttp.length;
  if (activeCount > 0) {
    findings.push(finding(
      `transport-mixed-content-active-${host}`,
      'transport',
      'high',
      'Active mixed content on an HTTPS page',
      'The HTTPS page references executable resources over HTTP or issues XHR/fetch or redirects to HTTP.',
      `Observed ${httpResources.length} HTTP subresource(s), ${signals.httpFetches.length} HTTP fetch/XHR request(s), and ${signals.redirectsToHttp.length} redirect(s) to HTTP.`,
      'Load all scripts, stylesheets, and API calls over HTTPS. Browsers block active mixed content, so these references indicate a misconfiguration.',
    ));
  }

  const passiveCount = signals.httpLinks.length + signals.httpForms.length;
  if (passiveCount > 0) {
    findings.push(finding(
      `transport-mixed-content-passive-${host}`,
      'transport',
      'medium',
      'HTTP references from an HTTPS page',
      'The HTTPS page contains absolute HTTP links or HTTP form actions.',
      `Observed ${signals.httpLinks.length} absolute HTTP link(s) and ${signals.httpForms.length} HTTP form action(s).`,
      'Replace absolute http:// references with https://.',
    ));
  }

  const insecureForms = (domObservation?.forms ?? []).filter(form =>
    (form.hasPasswordField || form.sensitiveFieldNames.length > 0) && form.action.startsWith('http://'),
  );
  if (insecureForms.length > 0) {
    findings.push(finding(
      `transport-insecure-form-${host}`,
      'transport',
      'high',
      'Sensitive form submits over HTTP',
      'A form with password or sensitive fields targets an HTTP action, exposing the submitted data in cleartext.',
      `Observed ${insecureForms.length} sensitive form(s) whose action is HTTP.`,
      'Serve the page over HTTPS and point the form action at an HTTPS endpoint.',
    ));
  }

  return findings;
}

// ── WebSockets ──────────────────────────────────────────────────────────────

export function assessWebSockets(activeUrl: string, sockets: ObservedWebSocket[]): AssessmentFinding[] {
  if (sockets.length === 0) return [];

  const host = hostnameFromUrl(activeUrl);
  const pageIsHttps = activeUrl.startsWith('https://');
  const insecure = sockets.filter(socket => !socket.secure);
  const findings: AssessmentFinding[] = [];

  if (pageIsHttps && insecure.length > 0) {
    findings.push(finding(
      `transport-insecure-websocket-${host}`,
      'transport',
      'high',
      'Insecure WebSocket (ws://) from an HTTPS page',
      'The HTTPS page opened a ws:// WebSocket, which travels in cleartext and is treated as mixed content by modern browsers.',
      `Observed ${insecure.length} insecure ws:// connection(s): ${insecure.slice(0, 3).map(socket => socket.url).join(', ')}.`,
      'Use wss:// for all WebSocket connections opened from secure pages.',
    ));
  }

  findings.push(finding(
    `transport-websocket-observed-${host}`,
    'transport',
    'info',
    'WebSocket connections observed',
    'The page established one or more WebSocket connections in the current session.',
    `Observed ${sockets.length} WebSocket connection(s): ${insecure.length} ws:// and ${sockets.length - insecure.length} wss://.`,
    'Review whether the WebSocket endpoints are expected and encrypted (wss://).',
  ));

  return findings;
}

// ── Third-party inventory ───────────────────────────────────────────────────

export function assessThirdParties(
  activeUrl: string,
  requests: CachedRequest[],
  cookies: chrome.cookies.Cookie[],
): AssessmentFinding[] {
  const pageHost = hostnameFromUrl(activeUrl);
  if (pageHost === '') return [];

  const findings: AssessmentFinding[] = [];

  const thirdPartyOrigins = new Set<string>();
  for (const request of requests) {
    let originHost = '';
    try {
      originHost = new URL(request.url).hostname;
    } catch {
      continue;
    }
    if (originHost !== '' && !isSameSite(originHost, pageHost)) {
      thirdPartyOrigins.add(originHost);
    }
  }
  for (const originHost of thirdPartyOrigins) {
    findings.push(finding(
      `resource-third-party-origin-${originHost}`,
      'transport',
      'info',
      'Third-party origin contacted',
      'The page made requests to an origin whose site differs from the page (best-effort eTLD+1 heuristic).',
      `Requests to ${originHost} were observed; its site differs from ${pageHost}.`,
      'Review third-party dependencies and the data they can access. Site comparison uses a heuristic without a full public-suffix list.',
    ));
  }

  for (const cookie of cookies) {
    const cookieHost = cookie.domain.replace(/^\./, '');
    if (cookieHost !== '' && !isSameSite(cookieHost, pageHost)) {
      findings.push(finding(
        `resource-third-party-cookie-${cookieHost}-${cookie.name}`,
        'transport',
        'info',
        'Third-party cookie present',
        'A cookie is scoped to a site different from the page.',
        `Cookie ${cookie.name} on ${cookie.domain} differs from the page site ${pageHost}.`,
        'Review necessity; third-party cookies are increasingly restricted by browsers.',
      ));
    }
  }

  return findings;
}
