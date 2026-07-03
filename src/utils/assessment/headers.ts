import type {
  CachedRequest,
  HeaderAssessmentCheck,
  HeaderAssessmentReport,
  HeaderAssessmentStatus,
} from '../../types';
import {
  allHeaderValues,
  firstHeaderValue,
  formatObservedValues,
  getPrimaryRequest,
  hostnameFromUrl,
  isHttpsUrl,
  looksLikeLogoutEndpoint,
  sameCommaSeparatedValue,
  sameNormalizedValue,
  sameSemicolonSeparatedValue,
} from './shared';

const OWASP_VALIDATOR_DEPRECATED_HEADERS = [
  'Feature-Policy',
  'Public-Key-Pins',
  'Expect-CT',
  'X-XSS-Protection',
] as const;
const OWASP_DISCLOSURE_HEADERS = ['Server', 'X-Powered-By'] as const;
const OWASP_PERMISSIONS_POLICY_DIRECTIVES = [
  'accelerometer=()',
  'autoplay=()',
  'camera=()',
  'clipboard-read=()',
  'clipboard-write=()',
  'cross-origin-isolated=()',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=()',
  'gamepad=()',
  'geolocation=()',
  'gyroscope=()',
  'hid=()',
  'idle-detection=()',
  'interest-cohort=()',
  'keyboard-map=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'serial=()',
  'unload=()',
  'usb=()',
  'web-share=()',
  'xr-spatial-tracking=()',
] as const;
const OWASP_PERMISSIONS_POLICY_SYNC_XHR = ['sync-xhr=(self)', 'sync-xhr=()'] as const;

export interface HeaderCheckResult {
  missing: string[];
  warning: string[];
}

function headerCheck(check: HeaderAssessmentCheck): HeaderAssessmentCheck {
  return check;
}

function buildHeaderAssessmentSummary(checks: HeaderAssessmentCheck[]): Record<HeaderAssessmentStatus, number> {
  return checks.reduce<Record<HeaderAssessmentStatus, number>>((acc, check) => {
    acc[check.status] += 1;
    return acc;
  }, {
    pass: 0,
    fail: 0,
    warn: 0,
    'not-applicable': 0,
  });
}

function requiredHeaderStatus(hasObservedValue: boolean, isValid: boolean): HeaderAssessmentStatus {
  if (!hasObservedValue) return 'fail';
  return isValid ? 'pass' : 'warn';
}

function evaluatePermissionsPolicy(value: string): { ok: boolean; missing: string[] } {
  const normalized = value.toLowerCase().replace(/\s+/g, '');
  const missing: string[] = OWASP_PERMISSIONS_POLICY_DIRECTIVES.filter(directive => !normalized.includes(directive));
  const hasSyncXhr = OWASP_PERMISSIONS_POLICY_SYNC_XHR.some(directive => normalized.includes(directive));
  if (!hasSyncXhr) {
    missing.push('sync-xhr=(self) or sync-xhr=()');
  }

  return {
    ok: missing.length === 0,
    missing,
  };
}

function buildRequiredHeaderChecks(primaryRequest: CachedRequest, logoutRequests: CachedRequest[]): HeaderAssessmentCheck[] {
  const checks: HeaderAssessmentCheck[] = [];

  const hstsValues = allHeaderValues(primaryRequest, 'strict-transport-security');
  if (!isHttpsUrl(primaryRequest.url)) {
    checks.push(headerCheck({
      id: 'owasp-required-hsts',
      headerName: 'Strict-Transport-Security',
      kind: 'required',
      status: 'not-applicable',
      summary: 'HSTS is only meaningful on HTTPS responses.',
      expected: 'max-age=63072000; includeSubDomains or max-age=63072000; includeSubDomains; preload',
      observedValues: hstsValues,
      evidence: `Primary response URL is ${primaryRequest.url}, so browsers ignore HSTS over plain HTTP.`,
      remediation: 'Assess HSTS on the HTTPS version of the application.',
      source: 'validator',
    }));
  } else if (hstsValues.length === 0) {
    checks.push(headerCheck({
      id: 'owasp-required-hsts',
      headerName: 'Strict-Transport-Security',
      kind: 'required',
      status: 'fail',
      summary: 'The primary response is missing HSTS.',
      expected: 'max-age=63072000; includeSubDomains or max-age=63072000; includeSubDomains; preload',
      observedValues: [],
      evidence: `No Strict-Transport-Security header was captured on ${primaryRequest.method} ${primaryRequest.url}.`,
      remediation: 'Serve the main HTML response over HTTPS and add an HSTS header aligned with the OWASP reference value.',
      source: 'validator',
    }));
  } else {
    const isValid = hstsValues.some(value =>
      sameSemicolonSeparatedValue(value, 'max-age=63072000; includeSubDomains')
      || sameSemicolonSeparatedValue(value, 'max-age=63072000; includeSubDomains; preload'),
    );
    checks.push(headerCheck({
      id: 'owasp-required-hsts',
      headerName: 'Strict-Transport-Security',
      kind: 'required',
      status: requiredHeaderStatus(hstsValues.length > 0, isValid),
      summary: isValid
        ? 'The primary response matches the HSTS values accepted by the OWASP validator.'
        : 'The HSTS value differs from the values accepted by the OWASP validator.',
      expected: 'max-age=63072000; includeSubDomains or max-age=63072000; includeSubDomains; preload',
      observedValues: hstsValues,
      evidence: `Observed Strict-Transport-Security value: ${formatObservedValues(hstsValues)}`,
      remediation: 'Use the OWASP reference HSTS value and keep any preload rollout deliberate.',
      source: 'validator',
    }));
  }

  const xfoValues = allHeaderValues(primaryRequest, 'x-frame-options');
  const xfoValid = xfoValues.some(value => sameNormalizedValue(value, 'deny'));
  checks.push(headerCheck({
    id: 'owasp-required-xfo',
    headerName: 'X-Frame-Options',
    kind: 'required',
    status: requiredHeaderStatus(xfoValues.length > 0, xfoValid),
    summary: xfoValues.length === 0
      ? 'The primary response is missing X-Frame-Options.'
      : (xfoValid
        ? 'The response uses the DENY framing policy accepted by the OWASP validator.'
        : 'The X-Frame-Options value is present but does not match the OWASP validator expectation.'),
    expected: 'deny',
    observedValues: xfoValues,
    evidence: `Observed X-Frame-Options value: ${formatObservedValues(xfoValues)}`,
    remediation: 'Set X-Frame-Options to DENY on the main browser document when framing is not intentionally required.',
    source: 'validator',
  }));

  const xctoValues = allHeaderValues(primaryRequest, 'x-content-type-options');
  const xctoValid = xctoValues.some(value => sameNormalizedValue(value, 'nosniff'));
  checks.push(headerCheck({
    id: 'owasp-required-xcto',
    headerName: 'X-Content-Type-Options',
    kind: 'required',
    status: requiredHeaderStatus(xctoValues.length > 0, xctoValid),
    summary: xctoValues.length === 0
      ? 'The primary response is missing X-Content-Type-Options.'
      : (xctoValid
        ? 'The response uses the nosniff value accepted by the OWASP validator.'
        : 'The X-Content-Type-Options value is present but does not match the OWASP validator expectation.'),
    expected: 'nosniff',
    observedValues: xctoValues,
    evidence: `Observed X-Content-Type-Options value: ${formatObservedValues(xctoValues)}`,
    remediation: 'Set X-Content-Type-Options to nosniff on the document response.',
    source: 'validator',
  }));

  const cspValues = allHeaderValues(primaryRequest, 'content-security-policy');
  const cspValid = cspValues.length > 0 && cspValues.every(value => !value.toLowerCase().includes('unsafe'));
  checks.push(headerCheck({
    id: 'owasp-required-csp',
    headerName: 'Content-Security-Policy',
    kind: 'required',
    status: requiredHeaderStatus(cspValues.length > 0, cspValid),
    summary: cspValues.length === 0
      ? 'The primary response is missing Content-Security-Policy.'
      : (cspValid
        ? 'The response exposes a CSP without the unsafe patterns rejected by the OWASP validator.'
        : 'The CSP contains unsafe expressions rejected by the OWASP validator.'),
    expected: 'Present and must not contain the substring unsafe',
    observedValues: cspValues,
    evidence: `Observed Content-Security-Policy value: ${formatObservedValues(cspValues)}`,
    remediation: 'Keep a CSP on the main document and remove unsafe-inline, unsafe-eval, and similar unsafe expressions.',
    source: 'validator',
  }));

  const xpcdpValues = allHeaderValues(primaryRequest, 'x-permitted-cross-domain-policies');
  const xpcdpValid = xpcdpValues.some(value => sameNormalizedValue(value, 'none'));
  checks.push(headerCheck({
    id: 'owasp-required-xpcdp',
    headerName: 'X-Permitted-Cross-Domain-Policies',
    kind: 'required',
    status: requiredHeaderStatus(xpcdpValues.length > 0, xpcdpValid),
    summary: xpcdpValues.length === 0
      ? 'The primary response is missing X-Permitted-Cross-Domain-Policies.'
      : (xpcdpValid
        ? 'The response matches the OWASP validator expectation for X-Permitted-Cross-Domain-Policies.'
        : 'The X-Permitted-Cross-Domain-Policies value differs from the OWASP validator expectation.'),
    expected: 'none',
    observedValues: xpcdpValues,
    evidence: `Observed X-Permitted-Cross-Domain-Policies value: ${formatObservedValues(xpcdpValues)}`,
    remediation: 'Use X-Permitted-Cross-Domain-Policies: none unless the application intentionally relies on cross-domain policy files.',
    source: 'validator',
  }));

  const referrerPolicyValues = allHeaderValues(primaryRequest, 'referrer-policy');
  const referrerPolicyValid = referrerPolicyValues.some(value => sameNormalizedValue(value, 'no-referrer'));
  checks.push(headerCheck({
    id: 'owasp-required-referrer-policy',
    headerName: 'Referrer-Policy',
    kind: 'required',
    status: requiredHeaderStatus(referrerPolicyValues.length > 0, referrerPolicyValid),
    summary: referrerPolicyValues.length === 0
      ? 'The primary response is missing Referrer-Policy.'
      : (referrerPolicyValid
        ? 'The response matches the Referrer-Policy value expected by the OWASP validator.'
        : 'The Referrer-Policy value differs from the OWASP validator expectation.'),
    expected: 'no-referrer',
    observedValues: referrerPolicyValues,
    evidence: `Observed Referrer-Policy value: ${formatObservedValues(referrerPolicyValues)}`,
    remediation: 'Use Referrer-Policy: no-referrer if you want to stay aligned with the current OWASP validator suite.',
    source: 'validator',
  }));

  const coepValues = allHeaderValues(primaryRequest, 'cross-origin-embedder-policy');
  const coepValid = coepValues.some(value => sameNormalizedValue(value, 'require-corp'));
  checks.push(headerCheck({
    id: 'owasp-required-coep',
    headerName: 'Cross-Origin-Embedder-Policy',
    kind: 'required',
    status: requiredHeaderStatus(coepValues.length > 0, coepValid),
    summary: coepValues.length === 0
      ? 'The primary response is missing Cross-Origin-Embedder-Policy.'
      : (coepValid
        ? 'The response matches the COEP value expected by the OWASP validator.'
        : 'The COEP value differs from the OWASP validator expectation.'),
    expected: 'require-corp',
    observedValues: coepValues,
    evidence: `Observed Cross-Origin-Embedder-Policy value: ${formatObservedValues(coepValues)}`,
    remediation: 'Use Cross-Origin-Embedder-Policy: require-corp when the application is prepared for a cross-origin isolated context.',
    source: 'validator',
  }));

  const coopValues = allHeaderValues(primaryRequest, 'cross-origin-opener-policy');
  const coopValid = coopValues.some(value => sameNormalizedValue(value, 'same-origin'));
  checks.push(headerCheck({
    id: 'owasp-required-coop',
    headerName: 'Cross-Origin-Opener-Policy',
    kind: 'required',
    status: requiredHeaderStatus(coopValues.length > 0, coopValid),
    summary: coopValues.length === 0
      ? 'The primary response is missing Cross-Origin-Opener-Policy.'
      : (coopValid
        ? 'The response matches the COOP value expected by the OWASP validator.'
        : 'The COOP value differs from the OWASP validator expectation.'),
    expected: 'same-origin',
    observedValues: coopValues,
    evidence: `Observed Cross-Origin-Opener-Policy value: ${formatObservedValues(coopValues)}`,
    remediation: 'Use Cross-Origin-Opener-Policy: same-origin when the document should stay isolated from cross-origin browsing contexts.',
    source: 'validator',
  }));

  const corpValues = allHeaderValues(primaryRequest, 'cross-origin-resource-policy');
  const corpValid = corpValues.some(value => sameNormalizedValue(value, 'same-origin'));
  checks.push(headerCheck({
    id: 'owasp-required-corp',
    headerName: 'Cross-Origin-Resource-Policy',
    kind: 'required',
    status: requiredHeaderStatus(corpValues.length > 0, corpValid),
    summary: corpValues.length === 0
      ? 'The primary response is missing Cross-Origin-Resource-Policy.'
      : (corpValid
        ? 'The response matches the CORP value expected by the OWASP validator.'
        : 'The CORP value differs from the OWASP validator expectation.'),
    expected: 'same-origin',
    observedValues: corpValues,
    evidence: `Observed Cross-Origin-Resource-Policy value: ${formatObservedValues(corpValues)}`,
    remediation: 'Use Cross-Origin-Resource-Policy: same-origin on document responses when cross-origin resource use is not intended.',
    source: 'validator',
  }));

  const permissionsPolicyValues = allHeaderValues(primaryRequest, 'permissions-policy');
  const permissionsPolicyEvaluation = permissionsPolicyValues.length > 0
    ? evaluatePermissionsPolicy(permissionsPolicyValues[0])
    : { ok: false, missing: [...OWASP_PERMISSIONS_POLICY_DIRECTIVES, 'sync-xhr=(self) or sync-xhr=()'] };
  checks.push(headerCheck({
    id: 'owasp-required-permissions-policy',
    headerName: 'Permissions-Policy',
    kind: 'required',
    status: requiredHeaderStatus(permissionsPolicyValues.length > 0, permissionsPolicyEvaluation.ok),
    summary: permissionsPolicyValues.length === 0
      ? 'The primary response is missing Permissions-Policy.'
      : (permissionsPolicyEvaluation.ok
        ? 'The response contains the Permissions-Policy directives expected by the OWASP validator.'
        : 'The Permissions-Policy header is present but misses one or more directives expected by the OWASP validator.'),
    expected: 'Present and must contain the directive set expected by the OWASP validator.',
    observedValues: permissionsPolicyValues,
    evidence: permissionsPolicyEvaluation.ok
      ? `Observed Permissions-Policy value: ${formatObservedValues(permissionsPolicyValues)}`
      : `Observed Permissions-Policy value: ${formatObservedValues(permissionsPolicyValues)} Missing directives: ${permissionsPolicyEvaluation.missing.join(', ')}.`,
    remediation: 'Start from the OWASP Secure Headers reference Permissions-Policy and adjust only when a browser feature is intentionally needed.',
    source: 'validator',
  }));

  const cacheControlValues = allHeaderValues(primaryRequest, 'cache-control');
  const cacheControlValid = cacheControlValues.some(value => sameCommaSeparatedValue(value, 'no-store, max-age=0'));
  checks.push(headerCheck({
    id: 'owasp-required-cache-control',
    headerName: 'Cache-Control',
    kind: 'required',
    status: requiredHeaderStatus(cacheControlValues.length > 0, cacheControlValid),
    summary: cacheControlValues.length === 0
      ? 'The primary response is missing Cache-Control.'
      : (cacheControlValid
        ? 'The response matches the cache policy expected by the OWASP validator.'
        : 'The Cache-Control value differs from the OWASP validator expectation.'),
    expected: 'no-store, max-age=0',
    observedValues: cacheControlValues,
    evidence: `Observed Cache-Control value: ${formatObservedValues(cacheControlValues)}`,
    remediation: 'Use Cache-Control: no-store, max-age=0 on sensitive browser documents if you want to stay aligned with the OWASP validator rule set.',
    source: 'validator',
  }));

  const dnsPrefetchValues = allHeaderValues(primaryRequest, 'x-dns-prefetch-control');
  const dnsPrefetchValid = dnsPrefetchValues.some(value => sameNormalizedValue(value, 'off'));
  checks.push(headerCheck({
    id: 'owasp-required-xdns-prefetch-control',
    headerName: 'X-DNS-Prefetch-Control',
    kind: 'required',
    status: requiredHeaderStatus(dnsPrefetchValues.length > 0, dnsPrefetchValid),
    summary: dnsPrefetchValues.length === 0
      ? 'The primary response is missing X-DNS-Prefetch-Control.'
      : (dnsPrefetchValid
        ? 'The response matches the DNS prefetch control expected by the OWASP validator.'
        : 'The X-DNS-Prefetch-Control value differs from the OWASP validator expectation.'),
    expected: 'off',
    observedValues: dnsPrefetchValues,
    evidence: `Observed X-DNS-Prefetch-Control value: ${formatObservedValues(dnsPrefetchValues)}`,
    remediation: 'Use X-DNS-Prefetch-Control: off if you want to stay aligned with the OWASP validator reference.',
    source: 'validator',
  }));

  if (logoutRequests.length === 0) {
    checks.push(headerCheck({
      id: 'owasp-required-clear-site-data',
      headerName: 'Clear-Site-Data',
      kind: 'required',
      status: 'not-applicable',
      summary: 'No logout-like response was captured in the current session.',
      expected: 'On logout responses: "cache","cookies","storage"',
      observedValues: [],
      evidence: 'The OWASP validator checks Clear-Site-Data on a logout endpoint, and no same-host logout-like request was captured here.',
      remediation: 'Capture a logout or end-session flow if you want to validate Clear-Site-Data from the Assessment tab.',
      source: 'validator',
    }));
  } else {
    const invalidLogoutRequests = logoutRequests.filter(request => {
      const values = allHeaderValues(request, 'clear-site-data');
      return values.length === 0 || !values.some(value => sameCommaSeparatedValue(value, '"cache","cookies","storage"'));
    });
    const missingClearSiteDataRequests = invalidLogoutRequests.filter(request => allHeaderValues(request, 'clear-site-data').length === 0);
    const logoutObservedValues = logoutRequests.flatMap(request => allHeaderValues(request, 'clear-site-data'));
    checks.push(headerCheck({
      id: 'owasp-required-clear-site-data',
      headerName: 'Clear-Site-Data',
      kind: 'required',
      status: invalidLogoutRequests.length === 0
        ? 'pass'
        : (missingClearSiteDataRequests.length > 0 ? 'fail' : 'warn'),
      summary: invalidLogoutRequests.length === 0
        ? 'All captured logout-like responses match the Clear-Site-Data value expected by the OWASP validator.'
        : 'At least one captured logout-like response is missing Clear-Site-Data or uses a different value than the OWASP validator expects.',
      expected: '"cache","cookies","storage"',
      observedValues: logoutObservedValues,
      evidence: invalidLogoutRequests.length === 0
        ? `Observed Clear-Site-Data value on ${logoutRequests.length} logout-like response(s): ${formatObservedValues(logoutObservedValues)}`
        : `Failing logout-like responses: ${invalidLogoutRequests.map(request => `${request.method} ${request.url}`).join(' | ')}. Observed Clear-Site-Data values: ${formatObservedValues(logoutObservedValues)}`,
      remediation: 'Set Clear-Site-Data: "cache","cookies","storage" on logout or end-session responses if that cleanup model matches the application.',
      source: 'validator',
    }));
  }

  return checks;
}

function buildDeprecatedHeaderChecks(primaryRequest: CachedRequest): HeaderAssessmentCheck[] {
  return OWASP_VALIDATOR_DEPRECATED_HEADERS.map(headerName => {
    const observedValues = allHeaderValues(primaryRequest, headerName.toLowerCase());
    const present = observedValues.length > 0;

    return headerCheck({
      id: `owasp-deprecated-${headerName.toLowerCase()}`,
      headerName,
      kind: 'deprecated',
      status: present ? 'fail' : 'pass',
      summary: present
        ? `${headerName} is present even though the OWASP validator expects it to be absent.`
        : `${headerName} is absent, which matches the OWASP validator expectation.`,
      expected: 'Header should not exist',
      observedValues,
      evidence: `Observed ${headerName} value: ${formatObservedValues(observedValues)}`,
      remediation: `Remove ${headerName} from browser responses unless you have a deliberate compatibility reason to keep it.`,
      source: 'validator',
    });
  });
}

function buildDisclosureHeaderChecks(primaryRequest: CachedRequest): HeaderAssessmentCheck[] {
  return OWASP_DISCLOSURE_HEADERS.map(headerName => {
    const observedValues = allHeaderValues(primaryRequest, headerName.toLowerCase());
    const present = observedValues.length > 0;
    const exposesVersion = observedValues.some(value => /\d/.test(value));

    return headerCheck({
      id: `owasp-advisory-${headerName.toLowerCase()}`,
      headerName,
      kind: 'advisory',
      status: !present ? 'pass' : (exposesVersion ? 'fail' : 'warn'),
      summary: present
        ? (exposesVersion
          ? `${headerName} discloses implementation details and an explicit version string.`
          : `${headerName} discloses implementation details that the OWASP project recommends removing.`)
        : `${headerName} is not exposed on the primary response.`,
      expected: 'Header should be absent when possible',
      observedValues,
      evidence: `Observed ${headerName} value: ${formatObservedValues(observedValues)}`,
      remediation: exposesVersion
        ? `Remove ${headerName} entirely or strip version tokens at the application server, framework, or reverse proxy layer.`
        : `Remove or generalize ${headerName} at the application server, framework, or reverse proxy layer.`,
      source: 'project',
    });
  });
}

export function getOwaspHeaderAssessment(activeUrl: string, requests: CachedRequest[]): HeaderAssessmentReport {
  const primaryRequest = getPrimaryRequest(requests, activeUrl);
  if (!primaryRequest) {
    return {
      activeUrl,
      primaryRequest: null,
      capturedRequestCount: requests.length,
      logoutRequestCount: 0,
      observedHeaderNames: [],
      checks: [],
      summary: {
        pass: 0,
        fail: 0,
        warn: 0,
        'not-applicable': 0,
      },
    };
  }

  const logoutRequests = requests.filter(request =>
    hostnameFromUrl(request.url) === hostnameFromUrl(activeUrl) && looksLikeLogoutEndpoint(request.url),
  );

  const checks = [
    ...buildRequiredHeaderChecks(primaryRequest, logoutRequests),
    ...buildDeprecatedHeaderChecks(primaryRequest),
    ...buildDisclosureHeaderChecks(primaryRequest),
  ];

  return {
    activeUrl,
    primaryRequest,
    capturedRequestCount: requests.length,
    logoutRequestCount: logoutRequests.length,
    observedHeaderNames: [...new Set(primaryRequest.responseHeaders.map(header => header.name))].sort((left, right) => left.localeCompare(right)),
    checks,
    summary: buildHeaderAssessmentSummary(checks),
  };
}

export function evaluatePrimaryHeaders(req: CachedRequest): HeaderCheckResult {
  const missing: string[] = [];
  const warning: string[] = [];
  const hsts = firstHeaderValue(req, 'strict-transport-security');
  const xfo = firstHeaderValue(req, 'x-frame-options');
  const xcto = firstHeaderValue(req, 'x-content-type-options');
  const referrerPolicy = firstHeaderValue(req, 'referrer-policy');
  const permissionsPolicy = firstHeaderValue(req, 'permissions-policy');
  const coop = firstHeaderValue(req, 'cross-origin-opener-policy');
  const coep = firstHeaderValue(req, 'cross-origin-embedder-policy');
  const corp = firstHeaderValue(req, 'cross-origin-resource-policy');

  // Content-Security-Policy is evaluated in depth by the dedicated per-directive
  // analyzer in csp.ts, so it is intentionally not re-checked here to avoid
  // emitting generic findings that would duplicate or contradict it.

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
