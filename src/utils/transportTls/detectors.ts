import type {
  CachedRequest,
  TransportTlsCheck,
} from '../../types';
import {
  buildEvidence,
  buildTransportCheck,
  formatUrlForEvidence,
  getFirstHeaderValue,
  getHeaderValues,
  hostnameFromUrl,
  isHttpUrl,
  isHttpsUrl,
  looksSensitiveQueryParam,
  sameHostname,
  type TransportTlsInputs,
} from './helpers';

interface ParsedHsts {
  maxAge?: number;
  includeSubDomains: boolean;
  preload: boolean;
}

function parseHsts(value: string): ParsedHsts {
  const segments = value.split(';').map(segment => segment.trim()).filter(Boolean);
  let maxAge: number | undefined;
  let includeSubDomains = false;
  let preload = false;

  segments.forEach(segment => {
    const lower = segment.toLowerCase();
    if (lower.startsWith('max-age=')) {
      const parsed = Number.parseInt(lower.slice('max-age='.length), 10);
      if (Number.isFinite(parsed)) {
        maxAge = parsed;
      }
      return;
    }
    if (lower === 'includesubdomains') {
      includeSubDomains = true;
      return;
    }
    if (lower === 'preload') {
      preload = true;
    }
  });

  return { maxAge, includeSubDomains, preload };
}

function getSameHostRequests(requests: CachedRequest[], activeUrl: string): CachedRequest[] {
  const host = hostnameFromUrl(activeUrl);
  return requests.filter(request => sameHostname(request.url, host));
}

function getSensitiveQueryEvidence(requests: CachedRequest[]): Array<{ request: CachedRequest; key: string }> {
  const evidence: Array<{ request: CachedRequest; key: string }> = [];

  requests.forEach(request => {
    try {
      const parsed = new URL(request.url);
      for (const [key, value] of parsed.searchParams.entries()) {
        if (looksSensitiveQueryParam(key, value)) {
          evidence.push({ request, key });
        }
      }
    } catch {
      // Ignore malformed URLs.
    }
  });

  return evidence;
}

export function detectHttpsAdoption(inputs: TransportTlsInputs): TransportTlsCheck {
  const sameHostRequests = getSameHostRequests(inputs.requests, inputs.activeUrl);
  const httpRequests = sameHostRequests.filter(request => isHttpUrl(request.url));
  const httpsRequests = sameHostRequests.filter(request => isHttpsUrl(request.url));
  const redirectsToHttps = httpRequests.filter(request => {
    const location = getFirstHeaderValue(request, 'location');
    return typeof location === 'string' && isHttpsUrl(location);
  });

  if (sameHostRequests.length === 0) {
    return buildTransportCheck({
      id: 'https-adoption',
      theme: 'https-adoption',
      title: 'HTTPS adoption',
      status: 'inconclusive',
      confidence: 'low',
      coverage: 'limited',
      summary: 'Inconclusive due to limited evidence. No same-host requests were observed for the active page.',
      observedFacts: ['No captured request to the selected host was available in the current browser session.'],
      assessment: 'The extension cannot evaluate HTTPS adoption without at least one observed request to the selected host.',
      guidance: ['Reload or navigate the page to capture document and XHR responses before relying on this check.'],
      evidenceRefs: [],
    });
  }

  const status = httpRequests.length === 0
    ? 'pass'
    : (httpsRequests.length === 0 ? 'fail' : 'warn');
  const observedFacts = [
    `Observed ${httpsRequests.length} HTTPS request(s) and ${httpRequests.length} HTTP request(s) for the selected host.`,
  ];

  if (redirectsToHttps.length > 0) {
    observedFacts.push(`Observed ${redirectsToHttps.length} HTTP to HTTPS redirect(s).`);
  }

  return buildTransportCheck({
    id: 'https-adoption',
    theme: 'https-adoption',
    title: 'HTTPS adoption',
    status,
    confidence: sameHostRequests.length >= 3 ? 'high' : 'medium',
    coverage: sameHostRequests.length >= 3 ? 'broad' : 'partial',
    summary: status === 'pass'
      ? 'Observed good practice. All same-host traffic seen in the current session used HTTPS.'
      : (status === 'fail'
        ? 'Potential weakness. Only HTTP traffic was observed for the selected host in the current session.'
        : 'Potential weakness. Both HTTP and HTTPS traffic were observed for the selected host in the current session.'),
    observedFacts,
    assessment: status === 'pass'
      ? 'The observed session shows HTTPS-only traffic for the selected host, but this remains scoped to what the browser captured here.'
      : (status === 'fail'
        ? 'The browser observed unencrypted traffic to the selected host. This is a transport weakness for the current session.'
        : 'The browser observed mixed transport usage. HTTPS is present, but HTTP endpoints were still reachable in the current session.'),
    guidance: [
      'Keep transport findings scoped to the observed session; do not assume full-site coverage beyond the captured flows.',
      'Remove or redirect remaining HTTP endpoints so browser traffic consistently lands on HTTPS.',
    ],
    evidenceRefs: [
      ...httpRequests.slice(0, 5).map(request => buildEvidence('request', `${request.method} HTTP`, formatUrlForEvidence(request.url))),
      ...redirectsToHttps.slice(0, 3).map(request => buildEvidence('header', 'Redirect to HTTPS', formatUrlForEvidence(getFirstHeaderValue(request, 'location') || ''))),
    ],
  });
}

export function detectSensitiveDataOverEncryptedChannel(inputs: TransportTlsInputs): TransportTlsCheck {
  const sensitiveQueryEvidence = getSensitiveQueryEvidence(inputs.requests);
  const insecureSensitiveQueries = sensitiveQueryEvidence.filter(item => isHttpUrl(item.request.url));
  const sensitiveForms = (inputs.domObservation?.forms || []).filter(form => form.hasPasswordField || form.sensitiveFieldNames.length > 0);
  const insecureSensitiveForms = sensitiveForms.filter(form => isHttpUrl(form.action) || isHttpUrl(inputs.domObservation?.pageUrl || ''));
  const storageEntryCount = inputs.storageScan?.entries.length ?? 0;

  if (sensitiveQueryEvidence.length === 0 && sensitiveForms.length === 0) {
    return buildTransportCheck({
      id: 'sensitive-flows',
      theme: 'sensitive-flows',
      title: 'Sensitive flows',
      status: inputs.requests.length === 0 && !inputs.domObservation ? 'inconclusive' : 'pass',
      confidence: inputs.requests.length > 0 || inputs.domObservation ? 'medium' : 'low',
      coverage: inputs.requests.length > 0 || inputs.domObservation ? 'partial' : 'limited',
      summary: inputs.requests.length === 0 && !inputs.domObservation
        ? 'Inconclusive due to limited evidence. No browser-visible sensitive flow indicators were available.'
        : 'No sensitive unencrypted flow observed in current session.',
      observedFacts: [
        'No password form action over HTTP and no sensitive query parameter over HTTP was observed in the current session.',
        storageEntryCount > 0
          ? `Token-like entries were present in browser storage (${storageEntryCount}), but no transport exposure was observed from the passive evidence collected here.`
          : 'No browser storage hint changed this transport conclusion.',
      ],
      assessment: inputs.requests.length === 0 && !inputs.domObservation
        ? 'The extension cannot confirm transport handling of sensitive flows without observed request or DOM evidence.'
        : 'Observed good practice from the current passive evidence, with the caveat that request bodies and request headers are not visible to this extension.',
      guidance: [
        'Treat this result as session-scoped and partial because the extension does not inspect request bodies.',
        'Continue to avoid placing secrets, tokens, or credentials in URLs or insecure form targets.',
      ],
      evidenceRefs: [],
    });
  }

  const status = insecureSensitiveQueries.length > 0 || insecureSensitiveForms.length > 0 ? 'fail' : 'pass';
  const observedFacts = [
    sensitiveQueryEvidence.length > 0
      ? `Observed ${sensitiveQueryEvidence.length} URL-based sensitive flow indicator(s).`
      : 'No sensitive query parameter was observed in captured requests.',
    sensitiveForms.length > 0
      ? `Observed ${sensitiveForms.length} form(s) with password or sensitive-looking fields in the current document.`
      : 'No sensitive form was observed in the current document.',
  ];

  return buildTransportCheck({
    id: 'sensitive-flows',
    theme: 'sensitive-flows',
    title: 'Sensitive flows',
    status,
    confidence: 'medium',
    coverage: 'partial',
    summary: status === 'fail'
      ? 'Potential weakness. Sensitive flow indicators were observed on an unencrypted channel.'
      : 'Observed good practice. Sensitive flow indicators seen in this session were tied to HTTPS only.',
    observedFacts,
    assessment: status === 'fail'
      ? 'At least one password form or token-like URL parameter was observed over HTTP. This creates exposure risk in the current session.'
      : 'Sensitive flow indicators were observed only on HTTPS in the passive evidence collected here, but the extension still lacks request-body visibility.',
    guidance: [
      'Avoid sending credentials, reset tokens, bearer tokens, or API keys in URLs.',
      'Keep login and other sensitive forms on HTTPS pages and ensure their action targets also resolve to HTTPS.',
    ],
    evidenceRefs: [
      ...insecureSensitiveQueries.slice(0, 5).map(item => buildEvidence('request', `Sensitive query over HTTP (${item.key})`, formatUrlForEvidence(item.request.url))),
      ...insecureSensitiveForms.slice(0, 5).map(form => buildEvidence('dom', 'Sensitive form action over HTTP', formatUrlForEvidence(form.action))),
      ...(status === 'pass'
        ? sensitiveQueryEvidence.slice(0, 3).map(item => buildEvidence('request', `Sensitive query over HTTPS (${item.key})`, formatUrlForEvidence(item.request.url)))
        : []),
    ],
  });
}

export function detectHstsPosture(inputs: TransportTlsInputs): TransportTlsCheck {
  const sameHostHttpsRequests = getSameHostRequests(inputs.requests, inputs.activeUrl).filter(request => isHttpsUrl(request.url));
  const hstsEvidence = sameHostHttpsRequests.flatMap(request =>
    getHeaderValues(request, 'strict-transport-security').map(value => ({ request, value })),
  );

  if (sameHostHttpsRequests.length === 0) {
    return buildTransportCheck({
      id: 'hsts-posture',
      theme: 'hsts',
      title: 'HSTS posture',
      status: 'inconclusive',
      confidence: 'low',
      coverage: 'limited',
      summary: 'Inconclusive due to limited evidence. No HTTPS response was observed for the selected host.',
      observedFacts: ['No same-host HTTPS response was available to inspect for Strict-Transport-Security.'],
      assessment: 'Without an observed HTTPS response, the extension cannot determine whether HSTS is present or robust.',
      guidance: ['Capture an HTTPS document response before relying on this HSTS evaluation.'],
      evidenceRefs: [],
    });
  }

  if (hstsEvidence.length === 0) {
    return buildTransportCheck({
      id: 'hsts-posture',
      theme: 'hsts',
      title: 'HSTS posture',
      status: 'fail',
      confidence: 'high',
      coverage: sameHostHttpsRequests.length >= 2 ? 'broad' : 'partial',
      summary: 'Potential weakness. HTTPS responses were observed without Strict-Transport-Security.',
      observedFacts: [`Observed ${sameHostHttpsRequests.length} HTTPS response(s) for the selected host and none included Strict-Transport-Security.`],
      assessment: 'The observed HTTPS responses do not advertise HSTS, so the browser has no captured signal to enforce HTTPS-only future navigation for this host.',
      guidance: [
        'Serve Strict-Transport-Security on HTTPS responses for the main application host.',
        'Use a durable max-age and include subdomains only when the broader host set is ready for it.',
      ],
      evidenceRefs: sameHostHttpsRequests.slice(0, 4).map(request => buildEvidence('request', `${request.method} HTTPS response`, formatUrlForEvidence(request.url))),
    });
  }

  const strongest = hstsEvidence
    .map(item => ({ ...item, parsed: parseHsts(item.value) }))
    .sort((left, right) => (right.parsed.maxAge || 0) - (left.parsed.maxAge || 0))[0];
  const robust = (strongest.parsed.maxAge || 0) >= 31536000 && strongest.parsed.includeSubDomains;

  return buildTransportCheck({
    id: 'hsts-posture',
    theme: 'hsts',
    title: 'HSTS posture',
    status: robust ? 'pass' : 'warn',
    confidence: 'high',
    coverage: sameHostHttpsRequests.length >= 2 ? 'broad' : 'partial',
    summary: robust
      ? 'Observed good practice. The strongest HSTS value seen in this session was robust.'
      : 'Observed partial HSTS protection. The header was present but not robust in the captured session.',
    observedFacts: [
      `Observed Strict-Transport-Security value: ${strongest.value}`,
      `Parsed max-age=${strongest.parsed.maxAge ?? 'missing'}, includeSubDomains=${strongest.parsed.includeSubDomains ? 'yes' : 'no'}, preload=${strongest.parsed.preload ? 'yes' : 'no'}.`,
    ],
    assessment: robust
      ? 'The captured HSTS policy is consistent with a strong browser transport-hardening posture for the observed host.'
      : 'HSTS was present but incomplete or weak in the observed session, so browser hardening may be limited.',
    guidance: [
      'Keep HSTS decisions scoped to the observed host and captured responses.',
      'Use a long max-age and include subdomains only when the entire host scope is ready for strict HTTPS handling.',
    ],
    evidenceRefs: [buildEvidence('header', 'Strict-Transport-Security', strongest.value)],
  });
}

export function detectDowngradeSignals(inputs: TransportTlsInputs): TransportTlsCheck {
  const pageIsHttps = isHttpsUrl(inputs.activeUrl);
  const httpFetches = pageIsHttps
    ? inputs.requests.filter(request => request.resourceType === 'xmlhttprequest' && isHttpUrl(request.url))
    : [];
  const redirectsToHttp = inputs.requests.filter(request => {
    const location = getFirstHeaderValue(request, 'location');
    return typeof location === 'string' && isHttpUrl(location);
  });
  const httpLinks = pageIsHttps ? (inputs.domObservation?.absoluteHttpLinks || []) : [];
  const httpForms = pageIsHttps ? (inputs.domObservation?.forms || []).filter(form => isHttpUrl(form.action)) : [];

  if (inputs.requests.length === 0 && !inputs.domObservation) {
    return buildTransportCheck({
      id: 'downgrade-signals',
      theme: 'downgrade-signals',
      title: 'Downgrade signals',
      status: 'inconclusive',
      confidence: 'low',
      coverage: 'limited',
      summary: 'Inconclusive due to limited evidence. No request or document-level transport signal was available for downgrade analysis.',
      observedFacts: ['The current session did not expose request or DOM evidence that could confirm or exclude downgrade patterns.'],
      assessment: 'Without request history or document transport metadata, the extension cannot make a confident downgrade determination.',
      guidance: ['Reload the active page and re-open the Assessment tab to gather more browser-visible evidence.'],
      evidenceRefs: [],
    });
  }

  if (!pageIsHttps && httpFetches.length === 0 && redirectsToHttp.length === 0 && httpLinks.length === 0 && httpForms.length === 0) {
    return buildTransportCheck({
      id: 'downgrade-signals',
      theme: 'downgrade-signals',
      title: 'Downgrade signals',
      status: 'inconclusive',
      confidence: 'low',
      coverage: 'limited',
      summary: 'Inconclusive due to limited evidence. Downgrade analysis is most meaningful from an HTTPS page context.',
      observedFacts: ['The active page was not HTTPS, so downgrade-specific browser signals were limited in this session.'],
      assessment: 'This check focuses on HTTPS pages that still reference or redirect to HTTP. The current page context did not provide that baseline.',
      guidance: ['Re-run the check from an HTTPS page to evaluate mixed references and downgrade patterns more directly.'],
      evidenceRefs: [],
    });
  }

  const status = redirectsToHttp.length > 0 || httpFetches.length > 0
    ? 'fail'
    : ((httpLinks.length > 0 || httpForms.length > 0) ? 'warn' : 'pass');

  return buildTransportCheck({
    id: 'downgrade-signals',
    theme: 'downgrade-signals',
    title: 'Downgrade signals',
    status,
    confidence: pageIsHttps ? 'medium' : 'low',
    coverage: pageIsHttps ? 'partial' : 'limited',
    summary: status === 'pass'
      ? 'Observed good practice. No downgrade signal was observed from the current HTTPS context.'
      : (status === 'fail'
        ? 'Potential weakness. Active downgrade signals were observed in the current session.'
        : 'Potential weakness. HTTP references were observed from an HTTPS context.'),
    observedFacts: [
      `Observed ${httpFetches.length} HTTP fetch/XHR request(s), ${redirectsToHttp.length} redirect(s) to HTTP, ${httpForms.length} HTTP form action(s), and ${httpLinks.length} absolute HTTP link(s).`,
    ],
    assessment: status === 'pass'
      ? 'The passive evidence from the current HTTPS page did not show anomalous HTTP references or redirects.'
      : (status === 'fail'
        ? 'The browser observed an explicit move or call back to HTTP from the current session, which is a stronger downgrade signal.'
        : 'The browser observed HTTP references from an HTTPS page, which may indicate incomplete migration or mixed transport patterns.'),
    guidance: [
      'Replace absolute HTTP references with HTTPS where possible.',
      'Avoid redirect chains or XHR/fetch calls that move the browser back to HTTP.',
    ],
    evidenceRefs: [
      ...httpFetches.slice(0, 4).map(request => buildEvidence('request', 'HTTP fetch/XHR from HTTPS context', formatUrlForEvidence(request.url))),
      ...redirectsToHttp.slice(0, 4).map(request => buildEvidence('header', 'Redirect to HTTP', formatUrlForEvidence(getFirstHeaderValue(request, 'location') || ''))),
      ...httpForms.slice(0, 4).map(form => buildEvidence('dom', 'HTTP form action', formatUrlForEvidence(form.action))),
      ...httpLinks.slice(0, 4).map(link => buildEvidence('dom', 'Absolute HTTP link', formatUrlForEvidence(link))),
    ],
  });
}

export function detectCertificateTrust(inputs: TransportTlsInputs): TransportTlsCheck {
  return buildTransportCheck({
    id: 'certificate-trust',
    theme: 'certificate-trust',
    title: 'Certificate trust',
    status: 'inconclusive',
    confidence: 'low',
    coverage: 'limited',
    summary: 'Inconclusive due to limited evidence. Certificate trust details are not exposed by the browser APIs used by this extension.',
    observedFacts: [
      `The current extension context for ${inputs.activeUrl || 'the active page'} exposes response headers and DOM metadata, but not issuer, SAN match, trust chain, or validity dates.`,
    ],
    assessment: 'The module intentionally avoids synthetic certificate conclusions when the browser does not expose certificate trust details in the current passive context.',
    guidance: [
      'Treat certificate trust as inconclusive in this plugin unless a future browser API exposes reliable certificate metadata.',
    ],
    evidenceRefs: [],
  });
}

export function detectTlsPosture(inputs: TransportTlsInputs): TransportTlsCheck {
  return buildTransportCheck({
    id: 'tls-posture',
    theme: 'tls-posture',
    title: 'TLS posture',
    status: 'inconclusive',
    confidence: 'low',
    coverage: 'limited',
    summary: 'Inconclusive due to limited evidence. TLS version, cipher suite, and certificate strength are not exposed by the browser APIs used here.',
    observedFacts: [
      `The current passive dataset for ${inputs.activeUrl || 'the active page'} does not include protocol version, negotiated cipher, or certificate key details.`,
    ],
    assessment: 'The module keeps TLS posture inconclusive rather than inferring protocol strength from incomplete browser-visible data.',
    guidance: [
      'Use a source that can reliably expose negotiated TLS details if protocol-level posture must be verified outside this plugin.',
    ],
    evidenceRefs: [],
  });
}