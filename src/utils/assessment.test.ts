import { afterEach, describe, expect, test, vi } from 'vitest';
import type { CachedRequest, StorageEntry } from '../types';
import {
  assessBrowserTokens,
  assessCookiesForUrl,
  assessCsp,
  assessHeaders,
  buildAssessmentFindings,
  getFindingCounts,
  getOwaspHeaderAssessment,
  getTokenAssessmentSummary,
} from './assessment';

function base64UrlEncode(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = '';
  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createJwt(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  return `${base64UrlEncode(header)}.${base64UrlEncode(payload)}.signature`;
}

function createCookie(overrides: Partial<chrome.cookies.Cookie> = {}): chrome.cookies.Cookie {
  return {
    domain: 'app.example.com',
    expirationDate: undefined,
    hostOnly: true,
    httpOnly: false,
    name: 'session',
    path: '/',
    sameSite: 'unspecified',
    secure: false,
    session: true,
    storeId: '0',
    value: 'opaque-session-id',
    ...overrides,
  };
}

function createRequest(overrides: Partial<CachedRequest> = {}): CachedRequest {
  return {
    method: 'GET',
    resourceType: 'main_frame',
    responseHeaders: [],
    statusCode: 200,
    timestamp: Date.now(),
    url: 'https://app.example.com/account',
    ...overrides,
  };
}

describe('assessment utilities', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('classifies sensitive and csrf cookies through findings', () => {
    const cookies = [
      createCookie({ name: 'session', secure: false, httpOnly: false, sameSite: 'unspecified' }),
      createCookie({ name: 'xsrf', secure: true, httpOnly: false, sameSite: 'unspecified', value: 'csrf-value' }),
    ];

    const findings = assessCookiesForUrl(cookies, 'https://app.example.com/account/profile');
    const titles = findings.map(finding => finding.title);

    expect(titles).toContain('Sensitive cookie without Secure');
    expect(titles).toContain('Sensitive cookie without HttpOnly');
    expect(titles).toContain('Sensitive cookie without explicit SameSite');
    expect(titles).toContain('CSRF-related cookie without explicit SameSite');
  });

  test('parses Set-Cookie headers with equals signs and evaluates response-side security attributes', () => {
    const requests = [
      createRequest({
        method: 'POST',
        resourceType: 'xmlhttprequest',
        url: 'https://app.example.com/auth/callback',
        responseHeaders: [
          { name: 'Set-Cookie', value: 'auth_token=abc=def; Path=/; SameSite=None' },
          { name: 'Cache-Control', value: 'no-store' },
        ],
      }),
    ];

    const findings = assessHeaders('https://app.example.com/account', requests);
    const titles = findings.map(finding => finding.title);
    const evidence = findings.map(finding => finding.evidence).join('\n');

    expect(titles).toContain('Set-Cookie for a sensitive cookie is missing Secure');
    expect(titles).toContain('Set-Cookie for a sensitive cookie is missing HttpOnly');
    expect(titles).toContain('Set-Cookie uses SameSite=None without Secure');
    expect(evidence).toContain('auth_token');
    expect(evidence).toContain('/auth/callback');
  });

  test('sorts aggregate findings by severity before title and reports counts', () => {
    const cookies = [
      createCookie({ name: 'session', secure: false, httpOnly: false, sameSite: 'unspecified' }),
      createCookie({ name: 'auth', secure: true, httpOnly: true, sameSite: 'lax', path: '/account' }),
    ];

    const findings = buildAssessmentFindings({
      activeUrl: 'https://app.example.com/account',
      cookies,
      storageEntries: [],
      requests: [createRequest()],
    });

    const counts = getFindingCounts(findings);
    const lastFinding = findings[findings.length - 1];

    expect(findings[0]?.severity).toBe('high');
    expect(lastFinding?.severity === 'low' || lastFinding?.severity === 'info').toBe(true);
    expect(counts.high).toBeGreaterThan(0);
    expect(counts.medium).toBeGreaterThanOrEqual(0);
  });

  test('detects JWT risk and sensitive claims across token origins', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-24T12:00:00Z'));

    const jwt = createJwt({
      sub: 'user-123',
      email: 'user@example.com',
      role: 'admin',
      iat: 1_774_814_400,
      exp: 1_774_900_800,
      scope: 'read:all',
    });

    const entries: StorageEntry[] = [
      {
        area: 'localStorage',
        key: 'access_token',
        value: jwt,
        hints: ['jwt-value'],
        isJwt: true,
      },
      {
        area: 'sessionStorage',
        key: 'refresh_token',
        value: 'Bearer abcdefghijklmnopqrstuvwxyz0123456789',
        hints: ['key-name'],
        isJwt: false,
      },
    ];

    const findings = assessBrowserTokens([], entries);
    const titles = findings.map(finding => finding.title);
    const tokenSummary = getTokenAssessmentSummary([], entries, jwt);

    expect(titles).toContain('JWT stored in localStorage');
    expect(titles).toContain('JWT payload exposes potentially sensitive claims');
    expect(titles).toContain('JWT has a long validity window');
    expect(titles).toContain('Opaque token-like value stored in sessionStorage');
    expect(tokenSummary.counts.localStorage).toBe(1);
    expect(tokenSummary.counts.sessionStorage).toBe(1);
    expect(tokenSummary.counts.manual).toBe(1);
    expect(tokenSummary.jwtCount).toBe(2);
  });

  test('builds a passing OWASP Secure Headers report for validator-aligned responses', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        { name: 'X-Frame-Options', value: 'DENY' },
        { name: 'X-Content-Type-Options', value: 'nosniff' },
        { name: 'Content-Security-Policy', value: "default-src 'self'; object-src 'none'; frame-ancestors 'none'" },
        { name: 'X-Permitted-Cross-Domain-Policies', value: 'none' },
        { name: 'Referrer-Policy', value: 'no-referrer' },
        { name: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },
        { name: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
        { name: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
        {
          name: 'Permissions-Policy',
          value: 'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(self), unload=(), usb=(), web-share=(), xr-spatial-tracking=()',
        },
        { name: 'Cache-Control', value: 'no-store, max-age=0' },
        { name: 'X-DNS-Prefetch-Control', value: 'off' },
      ],
    });
    const logoutRequest = createRequest({
      method: 'POST',
      resourceType: 'xmlhttprequest',
      url: 'https://app.example.com/logout',
      responseHeaders: [
        { name: 'Clear-Site-Data', value: '"cache","cookies","storage"' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest, logoutRequest]);
    const hstsCheck = report.checks.find(check => check.headerName === 'Strict-Transport-Security');
    const clearSiteDataCheck = report.checks.find(check => check.headerName === 'Clear-Site-Data');
    const deprecatedChecks = report.checks.filter(check => check.kind === 'deprecated');

    expect(report.summary.fail).toBe(0);
    expect(report.summary.warn).toBe(0);
    expect(hstsCheck?.status).toBe('pass');
    expect(clearSiteDataCheck?.status).toBe('pass');
    expect(deprecatedChecks.every(check => check.status === 'pass')).toBe(true);
  });

  test('flags warning OWASP Secure Headers checks for mismatched values and escalates version disclosures', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
        { name: 'X-Frame-Options', value: 'SAMEORIGIN' },
        { name: 'X-Content-Type-Options', value: 'sniff' },
        { name: 'Content-Security-Policy', value: "default-src 'self' 'unsafe-inline'" },
        { name: 'X-Permitted-Cross-Domain-Policies', value: 'master-only' },
        { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { name: 'Cross-Origin-Embedder-Policy', value: 'unsafe-none' },
        { name: 'Cross-Origin-Opener-Policy', value: 'same-origin-allow-popups' },
        { name: 'Cross-Origin-Resource-Policy', value: 'same-site' },
        { name: 'Permissions-Policy', value: 'geolocation=()' },
        { name: 'Cache-Control', value: 'private, max-age=60' },
        { name: 'X-DNS-Prefetch-Control', value: 'on' },
        { name: 'Expect-CT', value: 'max-age=86400' },
        { name: 'Server', value: 'nginx/1.27.0' },
        { name: 'X-Powered-By', value: 'Express' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest]);
    const cspCheck = report.checks.find(check => check.headerName === 'Content-Security-Policy');
    const clearSiteDataCheck = report.checks.find(check => check.headerName === 'Clear-Site-Data');
    const expectCtCheck = report.checks.find(check => check.headerName === 'Expect-CT');
    const serverCheck = report.checks.find(check => check.headerName === 'Server');

    expect(report.summary.fail).toBeGreaterThan(0);
    expect(report.summary.warn).toBeGreaterThan(0);
    expect(cspCheck?.status).toBe('warn');
    expect(clearSiteDataCheck?.status).toBe('not-applicable');
    expect(expectCtCheck?.status).toBe('fail');
    expect(serverCheck?.status).toBe('fail');
  });

  test('keeps advisory disclosures without version numbers as warn', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Server', value: 'nginx' },
        { name: 'X-Powered-By', value: 'PHP' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest]);
    const serverCheck = report.checks.find(check => check.headerName === 'Server');
    const poweredByCheck = report.checks.find(check => check.headerName === 'X-Powered-By');

    expect(serverCheck?.status).toBe('warn');
    expect(poweredByCheck?.status).toBe('warn');
  });

  test('keeps missing required headers as fail while mismatched values become warn', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'X-Frame-Options', value: 'SAMEORIGIN' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest]);
    const xfoCheck = report.checks.find(check => check.headerName === 'X-Frame-Options');
    const xctoCheck = report.checks.find(check => check.headerName === 'X-Content-Type-Options');

    expect(xfoCheck?.status).toBe('warn');
    expect(xctoCheck?.status).toBe('fail');
  });

  test('marks Clear-Site-Data as warn when logout responses have a different value but the header is present', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
      ],
    });
    const logoutRequest = createRequest({
      method: 'POST',
      resourceType: 'xmlhttprequest',
      url: 'https://app.example.com/logout',
      responseHeaders: [
        { name: 'Clear-Site-Data', value: '"cache","cookies"' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest, logoutRequest]);
    const clearSiteDataCheck = report.checks.find(check => check.headerName === 'Clear-Site-Data');

    expect(clearSiteDataCheck?.status).toBe('warn');
  });
});

describe('CSP per-directive analysis', () => {
  function cspRequest(value: string, headerName = 'Content-Security-Policy'): CachedRequest {
    return createRequest({ responseHeaders: [{ name: headerName, value }] });
  }

  const SAFE_TAIL = "object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

  test("flags script-src 'unsafe-inline' without a nonce as high", () => {
    const findings = assessCsp(cspRequest(`default-src 'self'; script-src 'self' 'unsafe-inline'; ${SAFE_TAIL}`));
    const inline = findings.find(f => f.id.startsWith('csp-script-unsafe-inline-') && !f.id.includes('mitigated'));
    const mitigated = findings.find(f => f.id.includes('unsafe-inline-mitigated'));

    expect(inline?.severity).toBe('high');
    expect(mitigated).toBeUndefined();
  });

  test("downgrades 'unsafe-inline' to a mitigated low when a nonce is present", () => {
    const findings = assessCsp(cspRequest(`default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'; ${SAFE_TAIL}`));
    const mitigated = findings.find(f => f.id.includes('unsafe-inline-mitigated'));
    const plainInline = findings.find(f => f.id.startsWith('csp-script-unsafe-inline-') && !f.id.includes('mitigated'));

    expect(mitigated?.severity).toBe('low');
    expect(plainInline).toBeUndefined();
  });

  test("flags 'unsafe-eval' as high", () => {
    const titles = assessCsp(cspRequest(`default-src 'self'; script-src 'self' 'unsafe-eval'; ${SAFE_TAIL}`)).map(f => f.title);
    expect(titles).toContain("CSP script-src allows 'unsafe-eval'");
  });

  test('flags a wildcard script source as high', () => {
    const wildcard = assessCsp(cspRequest(`default-src 'self'; script-src *; ${SAFE_TAIL}`))
      .find(f => f.id.startsWith('csp-script-wildcard-'));
    expect(wildcard?.severity).toBe('high');
  });

  test('flags insecure/broad schemes in script-src as high', () => {
    const scheme = assessCsp(cspRequest(`default-src 'self'; script-src 'self' http: data:; ${SAFE_TAIL}`))
      .find(f => f.id.startsWith('csp-script-insecure-scheme-'));
    expect(scheme?.severity).toBe('high');
  });

  test('reports missing defensive directives when only default-src is present', () => {
    const titles = assessCsp(cspRequest("default-src 'self'")).map(f => f.title);
    expect(titles).toContain("CSP object-src is not 'none'");
    expect(titles).toContain('CSP base-uri directive is missing');
    expect(titles).toContain('CSP frame-ancestors directive is missing');
    expect(titles).not.toContain('CSP does not define default-src');
  });

  test('raises no medium or high findings for a hardened policy', () => {
    const findings = assessCsp(cspRequest(`default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self'`));
    expect(findings.filter(f => f.severity === 'high' || f.severity === 'medium')).toHaveLength(0);
  });

  test('recognizes Trusted Types and reporting as positive info findings', () => {
    const titles = assessCsp(cspRequest(
      `default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self'; require-trusted-types-for 'script'; report-uri /csp-report`,
    )).map(f => f.title);
    expect(titles).toContain('CSP enforces Trusted Types for scripts');
    expect(titles).toContain('CSP configures violation reporting');
  });

  test('downgrades report-only findings and never raises csp-missing for them', () => {
    const findings = assessCsp(cspRequest(`script-src 'self' 'unsafe-inline'`, 'Content-Security-Policy-Report-Only'));
    const reportOnly = findings.find(f => f.id.startsWith('csp-report-only-'));
    const inline = findings.find(f => f.id.startsWith('csp-script-unsafe-inline-') && f.id.endsWith('-ro'));

    expect(reportOnly?.severity).toBe('info');
    expect(inline?.severity).toBe('medium'); // high downgraded one level
    expect(findings.some(f => f.id.startsWith('csp-missing-'))).toBe(false);
  });

  test('emits a single csp-missing finding when no CSP header is present', () => {
    const findings = assessCsp(createRequest());
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id.startsWith('csp-missing-')).toBe(true);
    expect(findings[0]?.severity).toBe('medium');
  });

  test('no longer lists Content-Security-Policy in the generic missing-headers finding', () => {
    const missingFinding = assessHeaders('https://app.example.com/account', [createRequest()])
      .find(f => f.title === 'Missing key browser security headers');
    expect(missingFinding?.evidence).not.toContain('Content-Security-Policy');
  });

  test('parses directives case-insensitively', () => {
    const inline = assessCsp(cspRequest(`SCRIPT-SRC   'UNSAFE-INLINE'`))
      .find(f => f.id.startsWith('csp-script-unsafe-inline-') && !f.id.includes('mitigated'));
    expect(inline?.severity).toBe('high');
  });

  test('analyzes multiple Content-Security-Policy headers independently', () => {
    const request = createRequest({
      responseHeaders: [
        { name: 'Content-Security-Policy', value: `script-src 'unsafe-eval'` },
        { name: 'Content-Security-Policy', value: `script-src 'unsafe-inline'` },
      ],
    });
    const titles = assessCsp(request).map(f => f.title);
    expect(titles).toContain("CSP script-src allows 'unsafe-eval'");
    expect(titles).toContain("CSP script-src allows 'unsafe-inline'");
  });
});

describe('coverage & correctness additions (M2)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('flags a JWT stored in IndexedDB as high', () => {
    const jwt = createJwt({ sub: 'user' });
    const entries: StorageEntry[] = [
      { area: 'indexedDB', key: 'firebaseLocalStorageDb/firebaseLocalStorage/fbase_key', value: jwt, hints: ['jwt-value'], isJwt: true },
    ];

    const finding = assessBrowserTokens([], entries).find(f => f.title === 'JWT stored in IndexedDB');
    expect(finding?.severity).toBe('high');
  });

  test('flags a JWT whose nbf is in the future', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-24T12:00:00Z'));
    const nbf = Math.floor(new Date('2026-03-24T18:00:00Z').getTime() / 1_000);
    const jwt = createJwt({ sub: 'user', nbf });
    const entries: StorageEntry[] = [
      { area: 'localStorage', key: 'access_token', value: jwt, hints: ['jwt-value'], isJwt: true },
    ];

    const titles = assessBrowserTokens([], entries).map(f => f.title);
    expect(titles).toContain('JWT is not yet valid (nbf in the future)');
  });

  test('flags a cross-site cookie that is not Partitioned', () => {
    const cookies = [createCookie({ name: 'session', secure: true, httpOnly: true, sameSite: 'no_restriction' })];
    const finding = assessCookiesForUrl(cookies, 'https://app.example.com/')
      .find(f => f.title === 'Cross-site cookie is not Partitioned');
    expect(finding?.severity).toBe('low');
  });

  test('does not flag a partitioned cross-site cookie', () => {
    const cookies = [createCookie({
      name: 'session',
      secure: true,
      httpOnly: true,
      sameSite: 'no_restriction',
      partitionKey: { topLevelSite: 'https://app.example.com' },
    })];
    const titles = assessCookiesForUrl(cookies, 'https://app.example.com/').map(f => f.title);
    expect(titles).not.toContain('Cross-site cookie is not Partitioned');
  });
});